package com.littleauth.keycloak.scim.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.InetAddress;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * AC-5: outbound SCIM target URLs pointing at private/link-local/metadata-service ranges
 * are rejected by default at config-save time. Pre-mortem mitigation: an explicit,
 * audited allowlist override exists so legitimate internal-network SCIM targets (e.g.
 * keycloak-it running in CI) aren't permanently blocked.
 *
 * <p>Uses an injected resolver instead of real DNS so these tests are deterministic and
 * offline -- and so the SSRF-relevant case (a hostname that *resolves* to a private
 * address, regardless of how public it looks) is actually exercisable.
 */
class TargetUrlValidatorTest {

  /**
   * A hostname map for the cases this test suite cares about; anything not in the map falls
   * back to real (network-free) literal-IP parsing, matching what the production resolver
   * ({@code InetAddress::getAllByName}) does for an IP literal without touching the network.
   */
  private static TargetUrlValidator.HostResolver fakeResolver(Map<String, String> hostToIp) {
    return host -> {
      String ip = hostToIp.get(host);
      return new InetAddress[] {InetAddress.getByName(ip != null ? ip : host)};
    };
  }

  @Test
  void rejectsPrivateIpv4Literal() {
    var validator = new TargetUrlValidator(List.of(), fakeResolver(Map.of()));
    assertThrows(
        InvalidTargetUrlException.class, () -> validator.validate("https://10.0.0.5/scim/v2"));
  }

  @Test
  void rejectsLoopback() {
    var validator = new TargetUrlValidator(List.of(), fakeResolver(Map.of()));
    assertThrows(
        InvalidTargetUrlException.class, () -> validator.validate("https://127.0.0.1/scim/v2"));
  }

  @Test
  void rejectsLinkLocalAndCloudMetadataAddress() {
    var validator = new TargetUrlValidator(List.of(), fakeResolver(Map.of()));
    assertThrows(
        InvalidTargetUrlException.class,
        () -> validator.validate("https://169.254.169.254/latest/meta-data"));
  }

  @Test
  void rejectsSiteLocalIpv6() {
    var validator = new TargetUrlValidator(List.of(), fakeResolver(Map.of()));
    assertThrows(
        InvalidTargetUrlException.class, () -> validator.validate("https://[fc00::1]/scim/v2"));
  }

  @Test
  void rejectsCarrierGradeNatRange() {
    // 100.64.0.0/10 -- not flagged by InetAddress#isSiteLocalAddress, needs an explicit check.
    var validator = new TargetUrlValidator(List.of(), fakeResolver(Map.of()));
    assertThrows(
        InvalidTargetUrlException.class, () -> validator.validate("https://100.64.0.1/scim/v2"));
  }

  @Test
  void acceptsPublicAddress() {
    var validator = new TargetUrlValidator(List.of(), fakeResolver(Map.of()));
    assertDoesNotThrow(() -> validator.validate("https://93.184.216.34/scim/v2"));
  }

  @Test
  void rejectsHostnameThatResolvesToPrivateAddress() {
    // The actual SSRF case: an attacker (or a misconfigured admin) points a normal-looking
    // hostname at an internal address via DNS.
    var validator =
        new TargetUrlValidator(
            List.of(), fakeResolver(Map.of("scim.attacker.example", "10.1.2.3")));
    assertThrows(
        InvalidTargetUrlException.class,
        () -> validator.validate("https://scim.attacker.example/scim/v2"));
  }

  @Test
  void allowlistOverridePermitsAnExplicitlyApprovedPrivateHost() {
    var validator =
        new TargetUrlValidator(
            List.of("keycloak-it.internal"),
            fakeResolver(Map.of("keycloak-it.internal", "10.1.2.3")));
    assertDoesNotThrow(() -> validator.validate("https://keycloak-it.internal/scim/v2"));
  }

  @Test
  void rejectsPlainHttpToPublicHost() {
    var validator = new TargetUrlValidator(List.of(), fakeResolver(Map.of()));
    assertThrows(
        InvalidTargetUrlException.class, () -> validator.validate("http://93.184.216.34/scim/v2"));
  }

  @Test
  void allowlistOverridePermitsPlainHttpForLocalConformanceTarget() {
    // keycloak-it (little-auth-scim's disposable conformance server) serves plain HTTP --
    // the allowlist is what makes local/CI conformance testing possible at all.
    var validator =
        new TargetUrlValidator(
            List.of("keycloak-it.internal"),
            fakeResolver(Map.of("keycloak-it.internal", "10.1.2.3")));
    assertDoesNotThrow(() -> validator.validate("http://keycloak-it.internal:8087/scim/v2"));
  }
}
