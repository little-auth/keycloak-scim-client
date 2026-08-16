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
 * ReconciliationJob}, issue #6) so both go through exactly the same validation,
 * credential-resolution, and auth-mode wiring (Basic vs Bearer, issue #1) rather than two
 * copies drifting apart.
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
    ScimClientConfig clientConfig = buildScimClientConfig(config, credential);
    var requestBuilder = new ScimRequestBuilder(config.getTargetUrl(), clientConfig);
    Map<String, String> authHeaders = buildAuthHeaders(config, credential);
    return new ScimTargetClient(requestBuilder, authHeaders);
  }

  /**
   * Builds the SDK client config, wiring in HTTP Basic auth when {@link
   * ScimTargetConfig#getAuthMode()} is {@link ScimTargetConfig.AuthMode#BASIC} -- verified
   * directly against {@code scim-sdk-client} 1.34.0's bytecode that {@code
   * ScimHttpClient.sendRequest} applies this to every request (all HTTP methods funnel
   * through that one method) whenever the request doesn't already carry an explicit {@code
   * Authorization} header, which is exactly what {@link #buildAuthHeaders} leaves true for
   * Basic mode.
   *
   * <p>Rejects a blank or colon-containing username here rather than trusting
   * config-save-time validation ({@code ScimTargetStorageProviderFactory
   * .validateConfiguration}) alone: {@code BasicAuth.getAuthorizationHeaderValue()} treats a
   * {@code null} username as an empty string, not an error, and happily builds a header from
   * a colon-containing one, so an unvalidated config would otherwise silently build a
   * working-looking but wrong header instead of failing loudly -- the same class of silent
   * 401 this auth mode existed to fix in the first place. RFC 7617 SS2 forbids a colon in the
   * userid precisely because it makes the encoded credential ambiguous: a server splitting
   * {@code username:password} on the first colon would read {@code "alice:bob"} + password
   * {@code "s3cret"} as user {@code alice}, password {@code "bob:s3cret"}.
   */
  public static ScimClientConfig buildScimClientConfig(
      ScimTargetConfig config, String credential) {
    var builder =
        ScimClientConfig.builder().connectTimeout(5).requestTimeout(10).socketTimeout(10);
    if (config.getAuthMode() == ScimTargetConfig.AuthMode.BASIC) {
      String username = config.getUsername();
      if (username == null || username.isBlank()) {
        throw new IllegalStateException(
            "Auth mode is Basic but no username is configured for this SCIM target");
      }
      if (username.indexOf(':') >= 0) {
        throw new IllegalStateException(
            "Basic auth username must not contain a colon (RFC 7617)");
      }
      builder.basic(username, credential);
    }
    return builder.build();
  }

  /**
   * Bearer still passes its header per-request: this SDK has no client-level convenience for
   * a bearer token the way {@code ScimClientConfig.builder().basic(...)} exists for Basic
   * auth (see {@link ScimTargetClient}'s doc). Basic auth leaves this map empty on purpose:
   * an explicit {@code Authorization} header here would collide with the client-level {@code
   * BasicAuth} set in {@link #buildScimClientConfig}, which only applies when the outgoing
   * request doesn't already carry one.
   */
  public static Map<String, String> buildAuthHeaders(ScimTargetConfig config, String credential) {
    return config.getAuthMode() == ScimTargetConfig.AuthMode.BASIC
        ? Map.of()
        : Map.of("Authorization", "Bearer " + credential);
  }
}
