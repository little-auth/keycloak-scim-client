package com.littleauth.keycloak.scim.event;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Translates a Keycloak {@code UserRepresentation} (what {@code AdminEvent.getRepresentation()}
 * actually carries) into a SCIM {@code User}.
 *
 * <p>Sets {@code externalId} to the Keycloak user ID, never {@code id} -- RFC 7643 draws a
 * hard line between a client-supplied, opaque identifier and a server-assigned one;
 * conflating them is exactly the root cause behind CVE-2025-41115 (a SCIM client
 * provisions a numeric externalId, the server maps it onto its own internal ID, and the
 * attacker's new account becomes an existing admin account).
 */
class KeycloakUserMapperTest {

  private static final String REPRESENTATION =
      "{\"username\":\"bjensen\",\"email\":\"bjensen@example.com\","
          + "\"firstName\":\"Barbara\",\"lastName\":\"Jensen\",\"enabled\":true}";

  @Test
  void mapsUsernameAndActiveFlag() {
    var user = KeycloakUserMapper.toScimUser(REPRESENTATION, "kc-user-1");
    assertEquals("bjensen", user.getUserName().orElseThrow());
    assertTrue(user.isActive().orElseThrow());
  }

  @Test
  void mapsNameFields() {
    var user = KeycloakUserMapper.toScimUser(REPRESENTATION, "kc-user-1");
    var name = user.getName().orElseThrow();
    assertEquals("Barbara", name.getGivenName().orElseThrow());
    assertEquals("Jensen", name.getFamilyName().orElseThrow());
  }

  @Test
  void mapsPrimaryEmailWhenPresent() {
    var user = KeycloakUserMapper.toScimUser(REPRESENTATION, "kc-user-1");
    assertEquals(1, user.getEmails().size());
    assertEquals("bjensen@example.com", user.getEmails().get(0).getValue().orElseThrow());
    assertTrue(user.getEmails().get(0).isPrimary());
  }

  @Test
  void omitsEmailWhenKeycloakUserHasNone() {
    String noEmail = "{\"username\":\"bjensen\",\"enabled\":true}";
    var user = KeycloakUserMapper.toScimUser(noEmail, "kc-user-1");
    assertTrue(user.getEmails().isEmpty());
  }

  @Test
  void setsExternalIdToKeycloakIdNeverTheScimId() {
    var user = KeycloakUserMapper.toScimUser(REPRESENTATION, "kc-user-1");
    assertEquals("kc-user-1", user.getExternalId().orElseThrow());
    assertFalse(user.getId().isPresent(), "id is server-assigned -- must never be set here");
  }

  @Test
  void treatsDisabledKeycloakUserAsInactive() {
    String disabled = "{\"username\":\"bjensen\",\"enabled\":false}";
    var user = KeycloakUserMapper.toScimUser(disabled, "kc-user-1");
    assertFalse(user.isActive().orElseThrow());
  }

  @Test
  void treatsMissingEnabledFlagAsInactiveNotActive() {
    // Keycloak's own default for a brand new user representation with no explicit
    // "enabled" is null, not true -- don't silently default to active.
    String noEnabledFlag = "{\"username\":\"bjensen\"}";
    var user = KeycloakUserMapper.toScimUser(noEnabledFlag, "kc-user-1");
    assertFalse(user.isActive().orElseThrow());
  }
}
