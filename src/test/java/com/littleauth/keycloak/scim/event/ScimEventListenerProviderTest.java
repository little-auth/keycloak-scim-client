package com.littleauth.keycloak.scim.event;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.littleauth.keycloak.scim.client.ScimTargetClient;
import com.littleauth.keycloak.scim.config.InvalidTargetUrlException;
import com.littleauth.keycloak.scim.config.ScimTargetConfig;
import com.littleauth.keycloak.scim.store.ScimSyncMapping;
import de.captaingoldfish.scim.sdk.client.ScimClientConfig;
import de.captaingoldfish.scim.sdk.client.response.ServerResponse;
import de.captaingoldfish.scim.sdk.common.resources.User;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;

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
    verify(client, never()).deprovision(anyString(), any());
  }

  @Test
  void handleDeleteDeprovisionsWhenAlreadySynced() {
    ScimTargetClient client = mock(ScimTargetClient.class);
    ServerResponse<User> deleted = mock(ServerResponse.class);
    when(client.deprovision(any(), any())).thenReturn(deleted);
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

  @Test
  void buildClientRejectsTargetUrlThatNoLongerPassesTheSsrfGuard() {
    // Re-validated on every dispatch, not just at config-save time -- closes the
    // DNS-rebinding TOCTOU gap where a hostname could resolve to a public address when
    // saved and an internal one later.
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_TARGET_URL, "https://10.0.0.5/scim/v2");
    var config = new ScimTargetConfig(model);
    KeycloakSession session = mock(KeycloakSession.class);

    assertThrows(
        InvalidTargetUrlException.class,
        () -> provider.buildClient(session, config));
  }

  @Test
  void buildScimClientConfigThrowsWhenAuthModeIsBasicAndUsernameIsBlank() {
    // Defense in depth: ScimTargetStorageProviderFactory.validateConfiguration already
    // rejects this combination at save time, but a config that bypasses or predates that
    // check must still fail loudly here rather than silently build a broken Basic header
    // with an empty username -- BasicAuth.getAuthorizationHeaderValue() treats a null
    // username as an empty string, not an error, so this can't rely on the SDK to catch it.
    var config = new ScimTargetConfig(basicAuthModelWithoutUsername());

    assertThrows(
        IllegalStateException.class, () -> provider.buildScimClientConfig(config, "s3cret"));
  }

  private static ComponentModel basicAuthModelWithoutUsername() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_AUTH_MODE, "BASIC");
    return model;
  }

  @Test
  void buildScimClientConfigSetsBasicAuthWhenAuthModeIsBasic() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_AUTH_MODE, "BASIC");
    model.put(ScimTargetConfig.KEY_USERNAME, "alice");
    var config = new ScimTargetConfig(model);

    ScimClientConfig clientConfig = provider.buildScimClientConfig(config, "s3cret");

    assertEquals(
        "Basic YWxpY2U6czNjcmV0", clientConfig.getBasicAuth().getAuthorizationHeaderValue());
  }

  @Test
  void buildScimClientConfigLeavesBasicAuthUnsetForBearerMode() {
    var config = new ScimTargetConfig(new ComponentModel());

    ScimClientConfig clientConfig = provider.buildScimClientConfig(config, "s3cret");

    assertNull(clientConfig.getBasicAuth());
  }

  @Test
  void buildAuthHeadersReturnsBearerHeaderForBearerMode() {
    var config = new ScimTargetConfig(new ComponentModel());

    assertEquals(
        Map.of("Authorization", "Bearer s3cret"), provider.buildAuthHeaders(config, "s3cret"));
  }

  @Test
  void buildAuthHeadersReturnsEmptyMapForBasicModeSoTheClientLevelBasicAuthFires() {
    // Passing an explicit Authorization header here would collide with the client-level
    // BasicAuth set in buildScimClientConfig -- ScimHttpClient only applies its own basic
    // auth when the outgoing request doesn't already carry an Authorization header.
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_AUTH_MODE, "BASIC");
    var config = new ScimTargetConfig(model);

    assertEquals(Map.of(), provider.buildAuthHeaders(config, "s3cret"));
  }
}
