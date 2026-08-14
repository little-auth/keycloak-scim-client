package com.littleauth.keycloak.scim.event;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.captaingoldfish.scim.sdk.common.resources.User;
import de.captaingoldfish.scim.sdk.common.resources.complex.Name;
import de.captaingoldfish.scim.sdk.common.resources.multicomplex.Email;
import java.io.UncheckedIOException;
import java.util.List;
import org.keycloak.representations.idm.UserRepresentation;

/**
 * Translates a Keycloak {@code UserRepresentation} (what {@code AdminEvent.getRepresentation()}
 * carries) into a SCIM {@code User}.
 *
 * <p>Sets {@code externalId} to the Keycloak user ID, never {@code id} -- RFC 7643 draws a
 * hard line between a client-supplied, opaque identifier and a server-assigned one.
 * Conflating them is the root cause behind CVE-2025-41115 (a SCIM client provisions a
 * numeric {@code externalId}, the server maps it onto its own internal user ID, and the
 * attacker's new account becomes an existing admin account).
 */
public final class KeycloakUserMapper {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private KeycloakUserMapper() {}

  /**
   * Maps a Keycloak user representation to a SCIM {@code User}.
   *
   * @param keycloakUserId becomes the SCIM {@code externalId}, never {@code id}.
   */
  public static User toScimUser(String representationJson, String keycloakUserId) {
    UserRepresentation kcUser;
    try {
      kcUser = MAPPER.readValue(representationJson, UserRepresentation.class);
    } catch (java.io.IOException e) {
      throw new UncheckedIOException("Malformed Keycloak user representation", e);
    }

    User user = new User();
    user.setExternalId(keycloakUserId);
    user.setUserName(kcUser.getUsername());
    // Keycloak's own default for "enabled" is null, not true -- an absent flag must not
    // silently become an active SCIM user.
    user.setActive(Boolean.TRUE.equals(kcUser.isEnabled()));

    if (kcUser.getFirstName() != null || kcUser.getLastName() != null) {
      user.setName(
          Name.builder()
              .givenName(kcUser.getFirstName())
              .familyName(kcUser.getLastName())
              .build());
    }

    if (kcUser.getEmail() != null) {
      user.setEmails(
          List.of(Email.builder().value(kcUser.getEmail()).primary(true).build()));
    }

    return user;
  }
}
