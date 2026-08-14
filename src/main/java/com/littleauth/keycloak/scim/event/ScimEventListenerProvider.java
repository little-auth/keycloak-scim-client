package com.littleauth.keycloak.scim.event;

import com.littleauth.keycloak.scim.client.ScimTargetClient;
import com.littleauth.keycloak.scim.config.ScimTargetConfig;
import com.littleauth.keycloak.scim.config.ScimTargetStorageProviderFactory;
import com.littleauth.keycloak.scim.store.ScimSyncMapping;
import com.littleauth.keycloak.scim.store.ScimSyncMappingDao;
import de.captaingoldfish.scim.sdk.client.ScimClientConfig;
import de.captaingoldfish.scim.sdk.client.ScimRequestBuilder;
import de.captaingoldfish.scim.sdk.client.response.ServerResponse;
import de.captaingoldfish.scim.sdk.common.resources.User;
import jakarta.persistence.EntityManager;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.storage.UserStorageProvider;

/**
 * Turns interpreted admin events into outbound SCIM calls. {@link #onEvent(AdminEvent,
 * boolean)} only interprets the event and submits a job -- the actual push happens off this
 * (synchronous, request-bound) thread, in a fresh session opened via {@link
 * KeycloakModelUtils#runJobInTransaction}, so a slow or down SCIM target never blocks the
 * Keycloak admin action that triggered it (pre-mortem mitigation).
 *
 * <p>General {@code UPDATE} events always go through a full PUT: Keycloak's Admin REST API
 * has no native user PATCH, so every update carries a complete representation with no
 * cheap way to detect "only one field changed." The PATCH-with-PUT-fallback path is
 * exercised by deprovisioning instead (soft-delete is a genuinely minimal, single-field
 * change) -- see the implementation ticket's "AC-2 scope clarification."
 */
public class ScimEventListenerProvider implements EventListenerProvider {

  private static final Logger LOGGER = Logger.getLogger(ScimEventListenerProvider.class.getName());

  private final ExecutorService executorService;
  private final KeycloakSessionFactory sessionFactory;

  ScimEventListenerProvider(
      ExecutorService executorService, KeycloakSessionFactory sessionFactory) {
    this.executorService = executorService;
    this.sessionFactory = sessionFactory;
  }

  @Override
  public void onEvent(Event event) {
    // Self-service (user-facing) events aren't this plugin's scope: real provisioning
    // workflows go through the Admin API, the same direction Okta/Azure AD operate in.
  }

  @Override
  public void onEvent(AdminEvent event, boolean includeRepresentation) {
    AdminUserEventInterpreter.interpret(event)
        .ifPresent(
            intent -> {
              String realmId = event.getRealmId();
              executorService.submit(() -> dispatch(realmId, intent));
            });
  }

  private void dispatch(String realmId, ScimSyncIntent intent) {
    try {
      KeycloakModelUtils.runJobInTransaction(
          sessionFactory, session -> processIntent(session, realmId, intent));
    } catch (RuntimeException e) {
      // A sync failure must never propagate back to whatever triggered the original
      // event -- that Keycloak action already completed successfully.
      LOGGER.log(
          Level.WARNING,
          "SCIM sync failed for realm " + realmId + ", user " + intent.keycloakUserId(),
          e);
    }
  }

  private void processIntent(KeycloakSession session, String realmId, ScimSyncIntent intent) {
    RealmModel realm = session.realms().getRealm(realmId);
    if (realm == null) {
      return;
    }
    Optional<ScimTargetConfig> configOpt = loadConfig(realm);
    if (configOpt.isEmpty() || !configOpt.get().isSyncEnabled()) {
      return;
    }
    ScimTargetConfig config = configOpt.get();

    EntityManager entityManager =
        session.getProvider(JpaConnectionProvider.class).getEntityManager();
    var dao = new ScimSyncMappingDao(entityManager);
    ScimSyncMapping mapping =
        dao.findOrCreate(realmId, ScimSyncMapping.ResourceType.USER, intent.keycloakUserId());

    try (ScimTargetClient client = buildClient(session, config)) {
      ServerResponse<User> response = handle(client, mapping, intent, config);
      recordResult(mapping, response);
    } catch (RuntimeException e) {
      mapping.setLastSyncResult(ScimSyncMapping.SyncResult.FAILED);
      mapping.setLastSyncError(e.getMessage());
    }
    mapping.setLastSyncTime(System.currentTimeMillis());
  }

  private ServerResponse<User> handle(
      ScimTargetClient client,
      ScimSyncMapping mapping,
      ScimSyncIntent intent,
      ScimTargetConfig config) {
    return switch (intent.action()) {
      case CREATE -> handleCreate(client, mapping, intent);
      case UPDATE -> handleUpdate(client, mapping, intent);
      case DELETE -> handleDelete(client, mapping, config);
    };
  }

  ServerResponse<User> handleCreate(
      ScimTargetClient client, ScimSyncMapping mapping, ScimSyncIntent intent) {
    if (mapping.getScimId() != null) {
      // Already created (a retried/duplicate event) -- treat as an update instead of
      // risking a second SCIM resource for the same Keycloak user.
      return handleUpdate(client, mapping, intent);
    }
    User user = KeycloakUserMapper.toScimUser(intent.representationJson(), intent.keycloakUserId());
    ServerResponse<User> response = client.createUser(user);
    if (response.isSuccess()) {
      mapping.setScimId(response.getResource().getId().orElse(null));
    }
    return response;
  }

  ServerResponse<User> handleUpdate(
      ScimTargetClient client, ScimSyncMapping mapping, ScimSyncIntent intent) {
    User user = KeycloakUserMapper.toScimUser(intent.representationJson(), intent.keycloakUserId());
    if (mapping.getScimId() == null) {
      // Never created (a missed CREATE event) -- self-heal by creating instead of failing.
      ServerResponse<User> response = client.createUser(user);
      if (response.isSuccess()) {
        mapping.setScimId(response.getResource().getId().orElse(null));
      }
      return response;
    }
    return client.replaceUser(mapping.getScimId(), user);
  }

  ServerResponse<User> handleDelete(
      ScimTargetClient client, ScimSyncMapping mapping, ScimTargetConfig config) {
    if (mapping.getScimId() == null) {
      // Never synced to begin with -- nothing to deprovision on the target.
      return null;
    }
    User placeholder = new User();
    placeholder.setExternalId(mapping.getKeycloakId());
    return client.deprovision(mapping.getScimId(), config.getDeletePolicy(), placeholder);
  }

  void recordResult(ScimSyncMapping mapping, ServerResponse<User> response) {
    if (response == null) {
      mapping.setLastSyncResult(ScimSyncMapping.SyncResult.SKIPPED);
      return;
    }
    if (response.isSuccess()) {
      mapping.setLastSyncResult(ScimSyncMapping.SyncResult.SUCCESS);
      mapping.setLastSyncError(null);
    } else {
      mapping.setLastSyncResult(ScimSyncMapping.SyncResult.FAILED);
      mapping.setLastSyncError(
          "HTTP " + response.getHttpStatus() + ": " + response.getResponseBody());
    }
  }

  private Optional<ScimTargetConfig> loadConfig(RealmModel realm) {
    return realm
        .getComponentsStream(UserStorageProvider.class.getName())
        .filter(c -> ScimTargetStorageProviderFactory.ID.equals(c.getProviderId()))
        .findFirst()
        .map(ScimTargetConfig::new);
  }

  private ScimTargetClient buildClient(KeycloakSession session, ScimTargetConfig config) {
    String credential = config.resolveCredential(session);
    ScimClientConfig clientConfig =
        ScimClientConfig.builder()
            .httpHeaders(Map.of("Authorization", "Bearer " + credential))
            .connectTimeout(5)
            .requestTimeout(10)
            .socketTimeout(10)
            .build();
    var requestBuilder = new ScimRequestBuilder(config.getTargetUrl(), clientConfig);
    return new ScimTargetClient(requestBuilder);
  }

  @Override
  public void close() {
    // Per-request provider instance; the shared executor lives on the factory.
  }
}
