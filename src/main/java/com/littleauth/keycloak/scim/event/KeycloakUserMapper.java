package com.littleauth.keycloak.scim.event;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.captaingoldfish.scim.sdk.common.resources.User;
import de.captaingoldfish.scim.sdk.common.resources.complex.Name;
import de.captaingoldfish.scim.sdk.common.resources.multicomplex.Email;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.Objects;
import org.keycloak.representations.idm.UserRepresentation;

/**
 * Translates a Keycloak {@code UserRepresentation} into a SCIM {@code User}, and -- for
 * {@code ReconciliationJob} (issue #6) -- merges those same fields onto an already-fetched
 * target resource instead of building a fresh one, so a diff-derived write never wipes a
 * field this plugin doesn't manage (mirrors the fetch-then-merge fix already proven for
 * {@code ScimTargetClient#setActive}'s PUT fallback).
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
   * Maps a Keycloak user representation (as JSON, e.g. from {@code
   * AdminEvent.getRepresentation()}) to a fresh SCIM {@code User}.
   *
   * @param keycloakUserId becomes the SCIM {@code externalId}, never {@code id}.
   */
  public static User toScimUser(String representationJson, String keycloakUserId) {
    return toScimUser(parseRepresentation(representationJson), keycloakUserId);
  }

  /** Maps a Keycloak user representation to a fresh SCIM {@code User}. */
  public static User toScimUser(UserRepresentation kcUser, String keycloakUserId) {
    return mergeOnto(new User(), kcUser, keycloakUserId);
  }

  /**
   * Overwrites {@code target}'s externalId/userName/active/name/emails with the values
   * derived from {@code kcUser}, leaving every other field (id, meta, and any SCIM
   * attribute this plugin doesn't model) untouched. Mutates and returns {@code target}.
   */
  public static User mergeOnto(User target, UserRepresentation kcUser, String keycloakUserId) {
    target.setExternalId(keycloakUserId);
    target.setUserName(kcUser.getUsername());
    // Keycloak's own default for "enabled" is null, not true -- an absent flag must not
    // silently become an active SCIM user.
    target.setActive(Boolean.TRUE.equals(kcUser.isEnabled()));

    if (kcUser.getFirstName() != null || kcUser.getLastName() != null) {
      target.setName(
          Name.builder()
              .givenName(kcUser.getFirstName())
              .familyName(kcUser.getLastName())
              .build());
    } else {
      target.setName(null);
    }

    if (kcUser.getEmail() != null) {
      target.setEmails(List.of(Email.builder().value(kcUser.getEmail()).primary(true).build()));
    } else {
      target.setEmails(List.of());
    }

    return target;
  }

  /**
   * True if any field this plugin manages (username/active/given name/family name/primary
   * email) differs between {@code current} (the target's actual state) and {@code desired}
   * (what Keycloak says it should be). Ignores every other field, by design -- reconciliation
   * only ever diffs and rewrites the subset it owns.
   */
  public static boolean differs(User current, User desired) {
    return !Objects.equals(current.getUserName().orElse(null), desired.getUserName().orElse(null))
        || !Objects.equals(current.isActive().orElse(null), desired.isActive().orElse(null))
        || !Objects.equals(givenName(current), givenName(desired))
        || !Objects.equals(familyName(current), familyName(desired))
        || !Objects.equals(primaryEmail(current), primaryEmail(desired));
  }

  private static String givenName(User user) {
    return user.getName().flatMap(Name::getGivenName).orElse(null);
  }

  private static String familyName(User user) {
    return user.getName().flatMap(Name::getFamilyName).orElse(null);
  }

  private static String primaryEmail(User user) {
    return user.getEmails().stream()
        .filter(Email::isPrimary)
        .findFirst()
        .or(() -> user.getEmails().stream().findFirst())
        .flatMap(Email::getValue)
        .orElse(null);
  }

  private static UserRepresentation parseRepresentation(String representationJson) {
    try {
      return MAPPER.readValue(representationJson, UserRepresentation.class);
    } catch (java.io.IOException e) {
      throw new UncheckedIOException("Malformed Keycloak user representation", e);
    }
  }
}
