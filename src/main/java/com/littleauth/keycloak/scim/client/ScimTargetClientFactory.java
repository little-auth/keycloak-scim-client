package com.littleauth.keycloak.scim.client;

import com.littleauth.keycloak.scim.config.ScimTargetConfig;
import com.littleauth.keycloak.scim.config.TargetUrlValidator;
import de.captaingoldfish.scim.sdk.client.ScimClientConfig;
import de.captaingoldfish.scim.sdk.client.ScimRequestBuilder;
import java.util.Map;
import org.keycloak.models.KeycloakSession;

/**
 * Builds a {@link ScimTargetClient} for a realm's configured target -- shared by the
 * event-driven push path ({@code ScimEventListenerProvider}) and reconciliation ({@code
 * ReconciliationJob}, issue #6) so both go through exactly the same validation and
 * credential-resolution logic rather than two copies drifting apart.
 */
public final class ScimTargetClientFactory {

  private ScimTargetClientFactory() {}

  /**
   * Re-validates the target URL on every call, not just at config-save time: a save-time-only
   * check is a DNS-rebinding TOCTOU gap -- an admin-configured hostname that resolved to a
   * public address at save time can be repointed at an internal address before the next sync
   * or reconciliation pass fires. Not cached, so a rebind is caught before the next outbound
   * call.
   */
  public static ScimTargetClient build(KeycloakSession session, ScimTargetConfig config) {
    new TargetUrlValidator(config.getAllowlistHosts()).validate(config.getTargetUrl());
    String credential = config.resolveCredential(session);
    ScimClientConfig clientConfig =
        ScimClientConfig.builder().connectTimeout(5).requestTimeout(10).socketTimeout(10).build();
    var requestBuilder = new ScimRequestBuilder(config.getTargetUrl(), clientConfig);
    // Passed per-request via ScimTargetClient, not through ScimClientConfig -- see that
    // class's doc for why client-level header config proved unreliable in this SDK version.
    Map<String, String> authHeaders = Map.of("Authorization", "Bearer " + credential);
    return new ScimTargetClient(requestBuilder, authHeaders);
  }
}
