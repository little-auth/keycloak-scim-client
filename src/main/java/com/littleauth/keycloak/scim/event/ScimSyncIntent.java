package com.littleauth.keycloak.scim.event;

/**
 * What a Keycloak Admin-API event implies should happen on the SCIM target.
 * {@code representationJson} is {@code null} for {@link Action#DELETE} by design -- a
 * delete event carries no representation, and this plugin must never depend on one
 * (see {@link AdminUserEventInterpreter}'s class doc).
 */
public record ScimSyncIntent(Action action, String keycloakUserId, String representationJson) {

  /** What should happen on the SCIM target. */
  public enum Action {
    CREATE,
    UPDATE,
    DELETE
  }
}
