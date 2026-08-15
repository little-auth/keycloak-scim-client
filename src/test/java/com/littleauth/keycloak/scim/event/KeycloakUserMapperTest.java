package com.littleauth.keycloak.scim.event;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.captaingoldfish.scim.sdk.common.resources.User;
import de.captaingoldfish.scim.sdk.common.resources.complex.Name;
import de.captaingoldfish.scim.sdk.common.resources.multicomplex.Email;
import java.util.List;
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

  private static org.keycloak.representations.idm.UserRepresentation representation(
      String username, String firstName, String lastName, String email, Boolean enabled) {
    var rep = new org.keycloak.representations.idm.UserRepresentation();
    rep.setUsername(username);
    rep.setFirstName(firstName);
    rep.setLastName(lastName);
    rep.setEmail(email);
    rep.setEnabled(enabled);
    return rep;
  }

  @Test
  void mergeOntoOverwritesManagedFieldsButPreservesFieldsItDoesNotModel() {
    // ReconciliationJob's fetch-then-merge mitigation (issue #6): the target may have
    // fields this plugin never sets (e.g. a phone number added by another SCIM client) --
    // mergeOnto must never touch anything except externalId/userName/active/name/emails.
    User target = new User();
    target.setId("scim-existing");
    target.setPhoneNumbers(
        List.of(
            de.captaingoldfish.scim.sdk.common.resources.multicomplex.PhoneNumber.builder()
                .value("+1-555-0100")
                .build()));
    target.setUserName("stale-username");

    var kcUser = representation("bjensen", "Barbara", "Jensen", "bjensen@example.com", true);
    User merged = KeycloakUserMapper.mergeOnto(target, kcUser, "kc-user-1");

    assertEquals(target, merged, "mergeOnto mutates and returns the same instance");
    assertEquals("bjensen", merged.getUserName().orElseThrow());
    assertEquals("kc-user-1", merged.getExternalId().orElseThrow());
    assertTrue(merged.isActive().orElseThrow());
    assertEquals("scim-existing", merged.getId().orElseThrow(), "id must never be touched");
    assertEquals(1, merged.getPhoneNumbers().size(), "unmanaged fields must survive the merge");
  }

  @Test
  void mergeOntoClearsManagedNameAndEmailWhenKeycloakNoLongerHasThem() {
    User target = new User();
    target.setName(Name.builder().givenName("Old").familyName("Name").build());
    target.setEmails(List.of(Email.builder().value("old@example.com").primary(true).build()));

    var kcUser = representation("bjensen", null, null, null, true);
    User merged = KeycloakUserMapper.mergeOnto(target, kcUser, "kc-user-1");

    assertFalse(merged.getName().isPresent());
    assertTrue(merged.getEmails().isEmpty());
  }

  @Test
  void toScimUserFromRepresentationMatchesTheJsonOverload() {
    var kcUser = representation("bjensen", "Barbara", "Jensen", "bjensen@example.com", true);
    User fromRepresentation = KeycloakUserMapper.toScimUser(kcUser, "kc-user-1");
    User fromJson = KeycloakUserMapper.toScimUser(REPRESENTATION, "kc-user-1");

    assertEquals(fromJson.getUserName(), fromRepresentation.getUserName());
    assertEquals(fromJson.isActive(), fromRepresentation.isActive());
  }

  @Test
  void differsIsFalseWhenManagedFieldsAllMatch() {
    var kcUser = representation("bjensen", "Barbara", "Jensen", "bjensen@example.com", true);
    User current = KeycloakUserMapper.toScimUser(kcUser, "kc-user-1");
    User desired = KeycloakUserMapper.toScimUser(kcUser, "kc-user-1");

    assertFalse(KeycloakUserMapper.differs(current, desired));
  }

  @Test
  void differsIsTrueWhenActiveFlagDiverges() {
    User current = KeycloakUserMapper.toScimUser(representation("bjensen", null, null, null, true), "kc-1");
    User desired = KeycloakUserMapper.toScimUser(representation("bjensen", null, null, null, false), "kc-1");

    assertTrue(KeycloakUserMapper.differs(current, desired));
  }

  @Test
  void differsIsTrueWhenPrimaryEmailDiverges() {
    User current =
        KeycloakUserMapper.toScimUser(
            representation("bjensen", null, null, "old@example.com", true), "kc-1");
    User desired =
        KeycloakUserMapper.toScimUser(
            representation("bjensen", null, null, "new@example.com", true), "kc-1");

    assertTrue(KeycloakUserMapper.differs(current, desired));
  }

  @Test
  void differsIgnoresFieldsItDoesNotManage() {
    User current = KeycloakUserMapper.toScimUser(representation("bjensen", null, null, null, true), "kc-1");
    current.setPhoneNumbers(
        List.of(
            de.captaingoldfish.scim.sdk.common.resources.multicomplex.PhoneNumber.builder()
                .value("+1-555-0100")
                .build()));
    User desired = KeycloakUserMapper.toScimUser(representation("bjensen", null, null, null, true), "kc-1");

    assertFalse(KeycloakUserMapper.differs(current, desired));
  }
}
