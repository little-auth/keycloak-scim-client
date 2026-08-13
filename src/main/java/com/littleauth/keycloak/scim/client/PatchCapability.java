package com.littleauth.keycloak.scim.client;

/**
 * Tracks whether PATCH should currently be attempted against a SCIM target, versus
 * falling back to full PUT replace. Encodes two pre-mortem mitigations: a stale cached
 * discovery result must not be trusted forever (a fresh discovery re-check can restore or
 * revoke PATCH use), and a target that advertises PATCH support but whose PATCH requests
 * actually fail with a client error must fall back too, not just a target that never
 * advertised support. Not thread-safe by design: callers own one instance per target
 * connection and serialize access to it (matches how the rest of this plugin already
 * serializes writes to a given target through the event dispatch queue).
 */
public final class PatchCapability {

  private boolean supported;
  private boolean patchFailedSinceLastDiscovery;

  /** Seeds the initial capability from a target's {@code ServiceProviderConfig} discovery. */
  public PatchCapability(boolean supportedPerDiscovery) {
    this.supported = supportedPerDiscovery;
  }

  /** True unless the target never advertised PATCH, or a PATCH attempt has since failed. */
  public boolean shouldAttemptPatch() {
    return supported && !patchFailedSinceLastDiscovery;
  }

  /** Call after a PATCH request fails with a client error despite being advertised as supported. */
  public void recordPatchClientError() {
    patchFailedSinceLastDiscovery = true;
  }

  /** Call after a fresh {@code ServiceProviderConfig} fetch, giving PATCH another chance. */
  public void recordDiscovery(boolean supportedPerDiscovery) {
    this.supported = supportedPerDiscovery;
    this.patchFailedSinceLastDiscovery = false;
  }
}
