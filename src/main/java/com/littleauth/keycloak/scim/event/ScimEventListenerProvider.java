package com.littleauth.keycloak.scim.event;

import com.littleauth.keycloak.scim.client.ScimTargetClient;
import com.littleauth.keycloak.scim.client.ScimTargetClientFactory;
import com.littleauth.keycloak.scim.config.ScimTargetConfig;
import com.littleauth.keycloak.scim.config.ScimTargetConfigLookup;
import com.littleauth.keycloak.scim.store.ScimSyncMapping;
import com.littleauth.keycloak.scim.store.ScimSyncMappingDao;
import de.captaingoldfish.scim.sdk.client.ScimClientConfig;
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
    Optional<ScimSyncIntent> intentOpt = AdminUserEventInterpreter.interpret(event);
    LOGGER.info(
        "SCIM sync: onEvent resourceType="
            + event.getResourceType()
            + " op="
            + event.getOperationType()
            + " path="
            + event.getResourcePath()
            + " interpreted="
            + intentOpt.isPresent());
    intentOpt.ifPresent(
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
      LOGGER.warning("SCIM sync: no realm found for id " + realmId);
      return;
    }
    session.getContext().setRealm(realm);
    Optional<ScimTargetConfig> configOpt = loadConfig(realm);
    if (configOpt.isEmpty()) {
      LOGGER.info("SCIM sync: no keycloak-scim-target component configured for realm " + realmId);
      return;
    }
    if (!configOpt.get().isSyncEnabled()) {
      LOGGER.info("SCIM sync: sync disabled for realm " + realmId);
      return;
    }
    ScimTargetConfig config = configOpt.get();
    LOGGER.info(
        "SCIM sync: dispatching " + intent.action() + " for user " + intent.keycloakUserId());

    EntityManager entityManager =
        session.getProvider(JpaConnectionProvider.class).getEntityManager();
    var dao = new ScimSyncMappingDao(entityManager);
    ScimSyncMapping mapping =
        dao.findOrCreate(realmId, ScimSyncMapping.ResourceType.USER, intent.keycloakUserId());

    try (ScimTargetClient client = buildClient(session, config)) {
      ServerResponse<User> response = handle(client, mapping, intent, config);
      recordResult(mapping, response);
      LOGGER.info(
          "SCIM sync: "
              + intent.action()
              + " for "
              + intent.keycloakUserId()
              + " -> "
              + mapping.getLastSyncResult()
              + " ("
              + mapping.getLastSyncError()
              + ")");
    } catch (RuntimeException e) {
      LOGGER.log(Level.WARNING, "SCIM sync: dispatch threw for " + intent.keycloakUserId(), e);
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
    return client.deprovision(mapping.getScimId(), config.getDeletePolicy());
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
    return ScimTargetConfigLookup.forRealm(realm);
  }

  ScimTargetClient buildClient(KeycloakSession session, ScimTargetConfig config) {
    // Delegates to ScimTargetClientFactory, now shared with ReconciliationJob (issue #6) --
    // see that class's doc for the DNS-rebinding TOCTOU note on why this re-validates on
    // every call rather than caching, and for why auth-mode wiring (Basic vs Bearer, issue
    // #1) lives there too so reconciliation gets exactly the same behavior as event-driven
    // push.
    return ScimTargetClientFactory.build(session, config);
  }

  /**
   * Thin instance-method wrapper kept for this class's own tests; the actual auth-mode
   * wiring logic (including the Basic-auth username validation, issue #1) lives in {@link
   * ScimTargetClientFactory#buildScimClientConfig} so both this push path and reconciliation
   * (issue #6) share exactly one implementation.
   */
  ScimClientConfig buildScimClientConfig(ScimTargetConfig config, String credential) {
    return ScimTargetClientFactory.buildScimClientConfig(config, credential);
  }

  /**
   * Thin instance-method wrapper kept for this class's own tests; see {@link
   * ScimTargetClientFactory#buildAuthHeaders} for the actual Bearer-vs-Basic logic, shared
   * with reconciliation (issue #6).
   */
  Map<String, String> buildAuthHeaders(ScimTargetConfig config, String credential) {
    return ScimTargetClientFactory.buildAuthHeaders(config, credential);
  }

  @Override
  public void close() {
    // Per-request provider instance; the shared executor lives on the factory.
  }
}
