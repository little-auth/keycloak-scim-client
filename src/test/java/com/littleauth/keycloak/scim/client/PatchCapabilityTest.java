package com.littleauth.keycloak.scim.client;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Decides PATCH-vs-PUT for a SCIM target. Two pre-mortem mitigations live here:
 *
 * <ul>
 *   <li>a stale cached {@code ServiceProviderConfig} capability must not be trusted
 *       forever -- a fresh discovery re-check can restore or revoke PATCH use;
 *   <li>a target that *advertises* PATCH support but whose PATCH requests actually fail
 *       with a client error (the SCIM-SDK#968 class of bug: PATCH supported per
 *       discovery, but the specific request the SDK builds is malformed) must fall back
 *       to PUT too, not just a target that never advertised support in the first place.
 * </ul>
 */
class PatchCapabilityTest {

  @Test
  void doesNotAttemptPatchWhenDiscoveryReportsUnsupported() {
    var capability = new PatchCapability(false);
    assertFalse(capability.shouldAttemptPatch());
  }

  @Test
  void attemptsPatchWhenDiscoveryReportsSupported() {
    var capability = new PatchCapability(true);
    assertTrue(capability.shouldAttemptPatch());
  }

  @Test
  void stopsAttemptingPatchAfterClientErrorEvenThoughDiscoverySaidItWasSupported() {
    var capability = new PatchCapability(true);
    capability.recordPatchClientError();
    assertFalse(capability.shouldAttemptPatch());
  }

  @Test
  void freshSupportedDiscoveryClearsPriorClientErrorAndGivesPatchAnotherChance() {
    var capability = new PatchCapability(true);
    capability.recordPatchClientError();
    capability.recordDiscovery(true);
    assertTrue(capability.shouldAttemptPatch());
  }

  @Test
  void freshUnsupportedDiscoveryStopsPatchEvenWithoutPriorClientError() {
    var capability = new PatchCapability(true);
    capability.recordDiscovery(false);
    assertFalse(capability.shouldAttemptPatch());
  }
}
