package com.littleauth.keycloak.scim.event;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.littleauth.keycloak.scim.client.ScimTargetClient;
import com.littleauth.keycloak.scim.config.ScimTargetConfig;
import com.littleauth.keycloak.scim.store.ScimSyncMapping;
import de.captaingoldfish.scim.sdk.client.response.ServerResponse;
import de.captaingoldfish.scim.sdk.common.resources.User;
import org.junit.jupiter.api.Test;
import org.keycloak.component.ComponentModel;

/**
 * The dispatch decisions this provider makes -- exercised directly against package-private
 * methods with a mocked {@link ScimTargetClient}, since mocking the full Keycloak session
 * chain for these would obscure the actual logic under test with plumbing.
 */
@SuppressWarnings("unchecked")
class ScimEventListenerProviderTest {

  private final ScimEventListenerProvider provider = new ScimEventListenerProvider(null, null);

  private static ScimSyncIntent createIntent(String userId) {
    return new ScimSyncIntent(ScimSyncIntent.Action.CREATE, userId, "{\"username\":\"bjensen\"}");
  }

  private static ScimSyncMapping unsyncedMapping(String userId) {
    var mapping = new ScimSyncMapping();
    mapping.setKeycloakId(userId);
    return mapping;
  }

  private static ServerResponse<User> successWithScimId(String scimId) {
    ServerResponse<User> response = mock(ServerResponse.class);
    User resource = new User();
    resource.setId(scimId);
    when(response.isSuccess()).thenReturn(true);
    when(response.getResource()).thenReturn(resource);
    return response;
  }

  @Test
  void handleCreateCreatesWhenNoMappingScimIdExistsYet() {
    ScimTargetClient client = mock(ScimTargetClient.class);
    ServerResponse<User> created = successWithScimId("scim-1");
    when(client.createUser(any())).thenReturn(created);
    ScimSyncMapping mapping = unsyncedMapping("kc-1");

    ServerResponse<User> result = provider.handleCreate(client, mapping, createIntent("kc-1"));

    assertEquals(created, result);
    assertEquals("scim-1", mapping.getScimId());
    verify(client, never()).replaceUser(anyString(), any());
  }

  @Test
  void handleCreateUpdatesInsteadOfCreatingSecondResourceWhenAlreadySynced() {
    ScimTargetClient client = mock(ScimTargetClient.class);
    ServerResponse<User> updated = mock(ServerResponse.class);
    when(client.replaceUser(anyString(), any())).thenReturn(updated);
    ScimSyncMapping mapping = unsyncedMapping("kc-1");
    mapping.setScimId("scim-existing");

    ServerResponse<User> result = provider.handleCreate(client, mapping, createIntent("kc-1"));

    assertEquals(updated, result);
    verify(client, never()).createUser(any());
  }

  @Test
  void handleUpdateSelfHealsByCreatingWhenNoMappingExistsYet() {
    ScimTargetClient client = mock(ScimTargetClient.class);
    ServerResponse<User> created = successWithScimId("scim-2");
    when(client.createUser(any())).thenReturn(created);
    ScimSyncMapping mapping = unsyncedMapping("kc-2");
    var intent =
        new ScimSyncIntent(ScimSyncIntent.Action.UPDATE, "kc-2", "{\"username\":\"bjensen\"}");

    ServerResponse<User> result = provider.handleUpdate(client, mapping, intent);

    assertEquals(created, result);
    assertEquals("scim-2", mapping.getScimId());
  }

  @Test
  void handleUpdateReplacesWhenAlreadySynced() {
    ScimTargetClient client = mock(ScimTargetClient.class);
    ServerResponse<User> updated = mock(ServerResponse.class);
    when(client.replaceUser(eq("scim-3"), any())).thenReturn(updated);
    ScimSyncMapping mapping = unsyncedMapping("kc-3");
    mapping.setScimId("scim-3");
    var intent =
        new ScimSyncIntent(ScimSyncIntent.Action.UPDATE, "kc-3", "{\"username\":\"bjensen\"}");

    ServerResponse<User> result = provider.handleUpdate(client, mapping, intent);

    assertEquals(updated, result);
    verify(client, never()).createUser(any());
  }

  @Test
  void handleDeleteSkipsWhenTheEntityWasNeverSynced() {
    ScimTargetClient client = mock(ScimTargetClient.class);
    ScimSyncMapping mapping = unsyncedMapping("kc-4");

    ServerResponse<User> result =
        provider.handleDelete(client, mapping, new ScimTargetConfig(new ComponentModel()));

    assertNull(result);
    verify(client, never()).deprovision(anyString(), any(), any());
  }

  @Test
  void handleDeleteDeprovisionsWhenAlreadySynced() {
    ScimTargetClient client = mock(ScimTargetClient.class);
    ServerResponse<User> deleted = mock(ServerResponse.class);
    when(client.deprovision(any(), any(), any())).thenReturn(deleted);
    ScimSyncMapping mapping = unsyncedMapping("kc-5");
    mapping.setScimId("scim-5");

    ServerResponse<User> result =
        provider.handleDelete(client, mapping, new ScimTargetConfig(new ComponentModel()));

    assertEquals(deleted, result);
  }

  @Test
  void recordResultMarksSkippedWhenResponseIsNull() {
    ScimSyncMapping mapping = unsyncedMapping("kc-6");
    provider.recordResult(mapping, null);
    assertEquals(ScimSyncMapping.SyncResult.SKIPPED, mapping.getLastSyncResult());
  }

  @Test
  void recordResultMarksSuccessAndClearsPriorError() {
    ScimSyncMapping mapping = unsyncedMapping("kc-7");
    mapping.setLastSyncError("previous failure");
    ServerResponse<User> success = mock(ServerResponse.class);
    when(success.isSuccess()).thenReturn(true);

    provider.recordResult(mapping, success);

    assertEquals(ScimSyncMapping.SyncResult.SUCCESS, mapping.getLastSyncResult());
    assertNull(mapping.getLastSyncError());
  }

  @Test
  void recordResultMarksFailedWithHttpStatusAndBody() {
    ServerResponse<User> failure = mock(ServerResponse.class);
    when(failure.isSuccess()).thenReturn(false);
    when(failure.getHttpStatus()).thenReturn(400);
    when(failure.getResponseBody()).thenReturn("Bad Request");
    ScimSyncMapping mapping = unsyncedMapping("kc-8");

    provider.recordResult(mapping, failure);

    assertEquals(ScimSyncMapping.SyncResult.FAILED, mapping.getLastSyncResult());
    assertEquals("HTTP 400: Bad Request", mapping.getLastSyncError());
  }
}
