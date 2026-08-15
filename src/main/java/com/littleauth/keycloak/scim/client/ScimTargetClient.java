package com.littleauth.keycloak.scim.client;

import com.fasterxml.jackson.databind.node.BooleanNode;
import com.littleauth.keycloak.scim.client.ReconciliationWriteResult.Outcome;
import com.littleauth.keycloak.scim.config.ScimTargetConfig.DeletePolicy;
import de.captaingoldfish.scim.sdk.client.ScimRequestBuilder;
import de.captaingoldfish.scim.sdk.client.builder.UpdateBuilder;
import de.captaingoldfish.scim.sdk.client.response.ServerResponse;
import de.captaingoldfish.scim.sdk.common.constants.enums.PatchOp;
import de.captaingoldfish.scim.sdk.common.resources.ServiceProvider;
import de.captaingoldfish.scim.sdk.common.resources.User;
import de.captaingoldfish.scim.sdk.common.resources.complex.Meta;
import de.captaingoldfish.scim.sdk.common.response.ListResponse;
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

  /** Plain GET of a User resource by its SCIM id. */
  public ServerResponse<User> getUser(String scimId) {
    return requestBuilder.get(User.class, USERS_ENDPOINT, scimId).sendRequest(authHeaders);
  }

  /**
   * Reconciliation's duplicate-create guard (issue #6): before self-healing a missing
   * mapping by creating a new resource, check whether one already exists on the target for
   * this Keycloak user -- closes the window where an event-driven create (N6) and a
   * reconciliation create for the same user race across two separate transactions, each
   * observing no mapping yet and each calling create.
   */
  public ServerResponse<ListResponse<User>> findByExternalId(String keycloakUserId) {
    return requestBuilder
        .list(User.class, USERS_ENDPOINT)
        .filter(externalIdEqualsFilter(keycloakUserId))
        .get()
        .sendRequest(authHeaders);
  }

  private static String externalIdEqualsFilter(String keycloakUserId) {
    String escaped = keycloakUserId.replace("\\", "\\\\").replace("\"", "\\\"");
    return "externalId eq \"" + escaped + "\"";
  }

  /**
   * Applies a reconciliation diff-derived full PUT replace, but only after checking the
   * target's {@code meta.version} hasn't moved since {@code expectedMeta} was read (issue
   * #6: the N6/N7 race -- an event-driven write landing between reconciliation's read and
   * its write must not be silently overwritten). Passes {@code If-Match} when the target
   * advertises a version, so a target that honors conditional requests gets true atomicity;
   * either way, a 412/409 response is reported as {@link Outcome#VERSION_CONFLICT} rather
   * than treated as a generic failure, so the caller skips instead of retrying blindly.
   *
   * <p>{@code desired} must already be the full desired resource (built by fetching the
   * current resource and merging Keycloak-sourced fields onto it -- see {@code
   * KeycloakUserMapper#mergeOnto} -- never a bare, partially-populated {@code User}, which
   * would wipe target-only fields via SCIM's full-replace PUT semantics).
   */
  public ReconciliationWriteResult replaceIfVersionUnchanged(
      String scimId, User desired, Meta expectedMeta) {
    UpdateBuilder<User> updateBuilder =
        requestBuilder.update(User.class, USERS_ENDPOINT, scimId).setResource(desired.toString());
    if (expectedMeta != null) {
      expectedMeta.getVersion().ifPresent(updateBuilder::setETagForIfMatch);
    }
    ServerResponse<User> response = updateBuilder.sendRequest(authHeaders);
    if (response.isSuccess()) {
      return new ReconciliationWriteResult(Outcome.APPLIED, response);
    }
    Integer status = response.getHttpStatus();
    if (status != null && (status == 412 || status == 409)) {
      return new ReconciliationWriteResult(Outcome.VERSION_CONFLICT, response);
    }
    return new ReconciliationWriteResult(Outcome.FAILED, response);
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
    ServerResponse<User> current = getUser(scimId);
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
