package com.littleauth.keycloak.scim.event;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;

/**
 * Interprets a Keycloak Admin-API event into a {@link ScimSyncIntent}, or nothing.
 *
 * <p>AC-3 / pre-mortem: a Keycloak {@code DELETE} admin event fires <em>after</em> the
 * user row is already gone -- mitodl's plugin NPEs here because it tries to re-fetch the
 * user to build its outbound request. This interpreter must derive everything it needs
 * for a delete from the event payload alone, never a lookup.
 */
class AdminUserEventInterpreterTest {

  private static AdminEvent userEvent(
      OperationType op, String resourcePath, String representation) {
    AdminEvent event = new AdminEvent();
    event.setResourceType(ResourceType.USER);
    event.setOperationType(op);
    event.setResourcePath(resourcePath);
    event.setRepresentation(representation);
    return event;
  }

  @Test
  void interpretsUserCreateEvent() {
    AdminEvent event =
        userEvent(OperationType.CREATE, "users/abc-123", "{\"userName\":\"bjensen\"}");
    Optional<ScimSyncIntent> intent = AdminUserEventInterpreter.interpret(event);
    assertTrue(intent.isPresent());
    assertEquals(ScimSyncIntent.Action.CREATE, intent.get().action());
    assertEquals("abc-123", intent.get().keycloakUserId());
    assertEquals("{\"userName\":\"bjensen\"}", intent.get().representationJson());
  }

  @Test
  void interpretsUserUpdateEvent() {
    AdminEvent event = userEvent(OperationType.UPDATE, "users/abc-123", "{\"active\":false}");
    Optional<ScimSyncIntent> intent = AdminUserEventInterpreter.interpret(event);
    assertTrue(intent.isPresent());
    assertEquals(ScimSyncIntent.Action.UPDATE, intent.get().action());
  }

  @Test
  void interpretsUserDeleteEventWithoutRequiringRepresentation() {
    // representation is null -- exactly what a real Keycloak DELETE admin event carries,
    // because the row is already gone by the time this fires.
    AdminEvent event = userEvent(OperationType.DELETE, "users/abc-123", null);
    Optional<ScimSyncIntent> intent = AdminUserEventInterpreter.interpret(event);
    assertTrue(intent.isPresent());
    assertEquals(ScimSyncIntent.Action.DELETE, intent.get().action());
    assertEquals("abc-123", intent.get().keycloakUserId());
  }

  @Test
  void ignoresNonUserResourceTypes() {
    AdminEvent event = new AdminEvent();
    event.setResourceType(ResourceType.REALM_ROLE);
    event.setOperationType(OperationType.CREATE);
    event.setResourcePath("roles/some-role");
    assertTrue(AdminUserEventInterpreter.interpret(event).isEmpty());
  }

  @Test
  void ignoresUserSubResourcePathsLikeGroupMembershipChanges() {
    // "users/{id}/groups/{gid}" -- group membership, out of Slice 1's Users-only scope.
    AdminEvent event = userEvent(OperationType.CREATE, "users/abc-123/groups/def-456", null);
    assertTrue(AdminUserEventInterpreter.interpret(event).isEmpty());
  }

  @Test
  void ignoresEventsWithNoResourcePath() {
    AdminEvent event = userEvent(OperationType.UPDATE, null, "{}");
    assertTrue(AdminUserEventInterpreter.interpret(event).isEmpty());
  }

  @Test
  void ignoresActionOperationType() {
    // e.g. "users/{id}/reset-password-email" -- an action, not a create/update/delete.
    AdminEvent event = userEvent(OperationType.ACTION, "users/abc-123/reset-password-email", null);
    assertTrue(AdminUserEventInterpreter.interpret(event).isEmpty());
  }
}
