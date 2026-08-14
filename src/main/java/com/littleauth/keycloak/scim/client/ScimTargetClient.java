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
   * string-coerced value) when the target supports it, falling back to a full PUT replace
   * otherwise -- including when a PATCH attempt itself fails with a client error, not just
   * when discovery never advertised support.
   *
   * @param fallbackRepresentation the full resource to PUT if PATCH isn't used; the caller
   *     owns building this from current Keycloak state, since this client holds no
   *     resource cache of its own.
   */
  public ServerResponse<User> setActive(
      String scimId, boolean active, User fallbackRepresentation) {
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
    fallbackRepresentation.setActive(active);
    return replaceUser(scimId, fallbackRepresentation);
  }

  /** AC-3: never throws, and honors the realm's configured delete policy. */
  public ServerResponse<User> deprovision(
      String scimId, DeletePolicy policy, User softDeleteRepresentation) {
    return switch (policy) {
      case SOFT_DELETE -> setActive(scimId, false, softDeleteRepresentation);
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
