package com.littleauth.keycloak.scim.event;

import java.util.Optional;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;

/**
 * Turns a Keycloak Admin-API event into a {@link ScimSyncIntent}, or nothing if this
 * event isn't a direct User create/update/delete this plugin handles.
 *
 * <p>mitodl/keycloak-scim NullPointerExceptions on every Admin-API user {@code DELETE}
 * because its handler re-fetches the user to build its outbound request -- but the row is
 * already gone by the time a {@code DELETE} admin event fires. This interpreter derives
 * everything it needs (just the Keycloak user ID) from {@link AdminEvent#getResourcePath()}
 * alone, never from a lookup or from {@link AdminEvent#getRepresentation()}, which a
 * delete event doesn't carry.
 */
public final class AdminUserEventInterpreter {

  private AdminUserEventInterpreter() {}

  /** Returns empty for anything that isn't a direct User create/update/delete. */
  public static Optional<ScimSyncIntent> interpret(AdminEvent event) {
    if (event.getResourceType() != ResourceType.USER) {
      return Optional.empty();
    }
    String resourcePath = event.getResourcePath();
    if (resourcePath == null) {
      return Optional.empty();
    }
    String[] segments = resourcePath.split("/");
    // Only a direct "users/{id}" path is a user CRUD event this plugin handles --
    // sub-resource paths like "users/{id}/groups/{gid}" are Slice 2's group-membership
    // scope, and "users/{id}/reset-password-email" is an action, not a sync-relevant change.
    if (segments.length != 2 || !"users".equals(segments[0])) {
      return Optional.empty();
    }
    String userId = segments[1];
    OperationType operationType = event.getOperationType();
    if (operationType == OperationType.CREATE) {
      return Optional.of(
          new ScimSyncIntent(ScimSyncIntent.Action.CREATE, userId, event.getRepresentation()));
    }
    if (operationType == OperationType.UPDATE) {
      return Optional.of(
          new ScimSyncIntent(ScimSyncIntent.Action.UPDATE, userId, event.getRepresentation()));
    }
    if (operationType == OperationType.DELETE) {
      return Optional.of(new ScimSyncIntent(ScimSyncIntent.Action.DELETE, userId, null));
    }
    return Optional.empty();
  }
}
