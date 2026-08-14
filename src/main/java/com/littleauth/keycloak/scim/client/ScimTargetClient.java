package com.littleauth.keycloak.scim.client;

import com.fasterxml.jackson.databind.node.BooleanNode;
import com.littleauth.keycloak.scim.config.ScimTargetConfig.DeletePolicy;
import de.captaingoldfish.scim.sdk.client.ScimRequestBuilder;
import de.captaingoldfish.scim.sdk.client.response.ServerResponse;
import de.captaingoldfish.scim.sdk.common.constants.enums.PatchOp;
import de.captaingoldfish.scim.sdk.common.resources.ServiceProvider;
import de.captaingoldfish.scim.sdk.common.resources.User;
import java.util.Map;

/**
 * Thin orchestration layer over {@code scim-sdk-client}: create/replace/delete Users, plus
 * the {@code active}-flag PATCH-with-PUT-fallback path (mirrors exactly what a real
 * Keycloak enable/disable maps to). Request-building correctness is proven against real
 * traffic by the keycloak-it conformance harness, not exhaustive mocking here -- see the
 * implementation ticket's discovery log for why that split was made.
 *
 * <p>Every request explicitly passes its Authorization header via {@code sendRequest(Map)}
 * rather than relying on {@code ScimClientConfig}'s client-level header configuration --
 * confirmed via the conformance harness that the latter is unreliable in scim-sdk-client
 * 1.34.0 (a client configured with {@code .httpHeaders(...)}/{@code .httpMultiHeaders(...)}
 * still sent unauthenticated discovery requests). {@link
 * ScimRequestBuilder#loadServiceProviderConfiguration()} has no such per-call override, so
 * discovery is built manually instead of using it.
 */
public class ScimTargetClient implements AutoCloseable {

  private static final String USERS_ENDPOINT = "/Users";
  private static final String SERVICE_PROVIDER_CONFIG_ENDPOINT = "/ServiceProviderConfig";

  private final ScimRequestBuilder requestBuilder;
  private final PatchCapability patchCapability;
  private final Map<String, String> authHeaders;

  /** Connects and immediately runs discovery to seed the initial PATCH capability. */
  public ScimTargetClient(ScimRequestBuilder requestBuilder, Map<String, String> authHeaders) {
    this(requestBuilder, new PatchCapability(false), authHeaders);
    patchCapability.recordDiscovery(fetchPatchSupport());
  }

  ScimTargetClient(
      ScimRequestBuilder requestBuilder,
      PatchCapability patchCapability,
      Map<String, String> authHeaders) {
    this.requestBuilder = requestBuilder;
    this.patchCapability = patchCapability;
    this.authHeaders = authHeaders;
  }

  private boolean fetchPatchSupport() {
    ServerResponse<ServiceProvider> response =
        requestBuilder
            .get(ServiceProvider.class, SERVICE_PROVIDER_CONFIG_ENDPOINT)
            .sendRequest(authHeaders);
    return response.isSuccess() && response.getResource().getPatchConfig().isSupported();
  }

  /** Re-checks the target's advertised PATCH support, piggybacked on reconciliation cadence. */
  public void refreshCapabilities() {
    patchCapability.recordDiscovery(fetchPatchSupport());
  }

  /** AC-1: POSTs a new User resource. */
  public ServerResponse<User> createUser(User user) {
    return requestBuilder
        .create(User.class, USERS_ENDPOINT)
        .setResource(user.toString())
        .sendRequest(authHeaders);
  }

  /** Full PUT replace of an existing User resource. */
  public ServerResponse<User> replaceUser(String scimId, User user) {
    return requestBuilder
        .update(User.class, USERS_ENDPOINT, scimId)
        .setResource(user.toString())
        .sendRequest(authHeaders);
  }

  /** Hard DELETE of a User resource; only invoked when the realm is configured for it. */
  public ServerResponse<User> deleteUser(String scimId) {
    return requestBuilder.delete(User.class, USERS_ENDPOINT, scimId).sendRequest(authHeaders);
  }

  /**
   * Sets {@code active} via PATCH (native JSON boolean, never the mitodl-style
   * string-coerced value) when the target supports it, falling back to PUT otherwise --
   * including when a PATCH attempt itself fails with a client error, not just when
   * discovery never advertised support.
   *
   * <p>The PUT fallback fetches the resource's current state first and PUTs that back with
   * only {@code active} changed, rather than PUTting a minimal/placeholder representation
   * -- SCIM PUT is a full replace per RFC 7644 §3.5.1, so PUTting anything less than the
   * complete current resource would wipe every field this client doesn't know about
   * (email, name, username) instead of just toggling one flag.
   */
  public ServerResponse<User> setActive(String scimId, boolean active) {
    if (patchCapability.shouldAttemptPatch()) {
      ServerResponse<User> response =
          requestBuilder
              .patch(User.class, USERS_ENDPOINT, scimId)
              .addOperation()
              .path("active")
              .op(PatchOp.REPLACE)
              .valueNode(BooleanNode.valueOf(active))
              .build()
              .sendRequest(authHeaders);
      if (response.isSuccess()) {
        return response;
      }
      if (!isClientError(response)) {
        // Server error / network issue: surface it, don't mask it behind a PUT retry.
        return response;
      }
      patchCapability.recordPatchClientError();
    }
    return replaceActiveViaFetchAndPut(scimId, active);
  }

  private ServerResponse<User> replaceActiveViaFetchAndPut(String scimId, boolean active) {
    ServerResponse<User> current =
        requestBuilder.get(User.class, USERS_ENDPOINT, scimId).sendRequest(authHeaders);
    if (!current.isSuccess()) {
      // Can't safely PUT without the current state -- surface the GET failure rather
      // than risk wiping fields with an incomplete replace.
      return current;
    }
    User user = current.getResource();
    user.setActive(active);
    return replaceUser(scimId, user);
  }

  /** AC-3: never throws, and honors the realm's configured delete policy. */
  public ServerResponse<User> deprovision(String scimId, DeletePolicy policy) {
    return switch (policy) {
      case SOFT_DELETE -> setActive(scimId, false);
      case HARD_DELETE -> deleteUser(scimId);
    };
  }

  private static boolean isClientError(ServerResponse<?> response) {
    Integer status = response.getHttpStatus();
    return status != null && status >= 400 && status < 500;
  }

  @Override
  public void close() {
    requestBuilder.close();
  }
}
