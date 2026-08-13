package com.littleauth.keycloak.scim.config;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Rejects SCIM target URLs that resolve to a private, loopback, link-local, or
 * cloud-metadata address, so a realm-admin (malicious or merely careless) can't turn this
 * plugin's outbound push into an SSRF vector against internal infrastructure.
 *
 * <p>An explicit host allowlist bypasses both the address-range check and the
 * default HTTPS-only requirement, for legitimate internal-network SCIM targets (a
 * production internal deployment, or a local/CI conformance target like keycloak-it).
 */
public class TargetUrlValidator {

  private final Set<String> allowlistHosts;
  private final HostResolver resolver;

  /** Validates against real DNS/address resolution, with the given host allowlist. */
  public TargetUrlValidator(Collection<String> allowlistHosts) {
    this(allowlistHosts, InetAddress::getAllByName);
  }

  /** Validates using the given resolver instead of real DNS (for deterministic tests). */
  TargetUrlValidator(Collection<String> allowlistHosts, HostResolver resolver) {
    this.allowlistHosts = new HashSet<>(allowlistHosts);
    this.resolver = resolver;
  }

  /**
   * Rejects the URL unless it is either host-allowlisted, or both HTTPS and resolves only
   * to public addresses.
   *
   * @throws InvalidTargetUrlException if the URL is malformed, uses a non-HTTPS scheme
   *     without being allowlisted, or resolves to a blocked address range.
   */
  public void validate(String url) {
    URI uri = parse(url);
    String host = uri.getHost();
    if (host == null) {
      throw new InvalidTargetUrlException("SCIM target URL has no host: " + url);
    }
    // getHost() strips the brackets from an IPv6 literal; re-derive resolvable form.
    if (uri.getAuthority() != null && uri.getAuthority().startsWith("[")) {
      host = "[" + host + "]";
    }
    String bareHost = stripBrackets(host);

    if (allowlistHosts.contains(bareHost)) {
      return;
    }

    if (!"https".equalsIgnoreCase(uri.getScheme())) {
      throw new InvalidTargetUrlException(
          "SCIM target URL must use https unless the host is explicitly allowlisted: " + url);
    }

    InetAddress[] addresses;
    try {
      addresses = resolver.resolve(bareHost);
    } catch (UnknownHostException e) {
      throw new InvalidTargetUrlException("Could not resolve SCIM target host: " + bareHost, e);
    }
    for (InetAddress address : addresses) {
      if (isBlocked(address)) {
        throw new InvalidTargetUrlException(
            "SCIM target host '"
                + bareHost
                + "' resolves to a blocked address range ("
                + address.getHostAddress()
                + "). Add it to the target host allowlist if this is intentional.");
      }
    }
  }

  private static URI parse(String url) {
    try {
      return new URI(url);
    } catch (URISyntaxException e) {
      throw new InvalidTargetUrlException("Malformed SCIM target URL: " + url, e);
    }
  }

  private static String stripBrackets(String host) {
    return host.startsWith("[") && host.endsWith("]")
        ? host.substring(1, host.length() - 1)
        : host;
  }

  private static boolean isBlocked(InetAddress address) {
    if (address.isLoopbackAddress()
        || address.isLinkLocalAddress()
        || address.isSiteLocalAddress()
        || address.isAnyLocalAddress()
        || address.isMulticastAddress()) {
      return true;
    }
    // 100.64.0.0/10 (carrier-grade NAT, RFC 6598) -- not covered by isSiteLocalAddress.
    if (address instanceof Inet4Address) {
      byte[] octets = address.getAddress();
      int first = octets[0] & 0xFF;
      int second = octets[1] & 0xFF;
      return first == 100 && second >= 64 && second <= 127;
    }
    // fc00::/7 (unique local, RFC 4193) -- isSiteLocalAddress only recognizes the older,
    // deprecated fec0::/10 site-local prefix, not this one.
    byte[] octets = address.getAddress();
    return (octets[0] & 0xFE) == 0xFC;
  }

  @FunctionalInterface
  interface HostResolver {
    InetAddress[] resolve(String host) throws UnknownHostException;
  }
}
