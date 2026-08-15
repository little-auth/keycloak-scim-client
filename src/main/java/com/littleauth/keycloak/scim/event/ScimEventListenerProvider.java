package com.littleauth.keycloak.scim.event;

import com.littleauth.keycloak.scim.client.ScimTargetClient;
import com.littleauth.keycloak.scim.config.ScimTargetConfig;
import com.littleauth.keycloak.scim.config.ScimTargetStorageProviderFactory;
import com.littleauth.keycloak.scim.config.TargetUrlValidator;
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
    // realm.getComponentsStream(providerType) (the filtered overload) does not reliably
    // return components created via the Admin REST API in this Keycloak version/storage
    // mode -- confirmed via the conformance harness against a real instance: the
    // unfiltered stream includes our component with an exactly-matching providerType,
    // the filtered overload returns none. Filtering the unfiltered stream ourselves
    // sidesteps whatever that overload's bug is.
    return realm
        .getComponentsStream()
        .filter(c -> UserStorageProvider.class.getName().equals(c.getProviderType()))
        .filter(c -> ScimTargetStorageProviderFactory.ID.equals(c.getProviderId()))
        .findFirst()
        .map(ScimTargetConfig::new);
  }

  ScimTargetClient buildClient(KeycloakSession session, ScimTargetConfig config) {
    // Re-validated here, not just at config-save time (ScimTargetStorageProviderFactory
    // .validateConfiguration): a save-time-only check is a DNS-rebinding TOCTOU gap -- an
    // admin-configured hostname that resolved to a public address at save time can be
    // repointed at an internal address before the next sync fires. This runs on every
    // dispatch (not cached) so a rebind is caught before the next outbound call, not just
    // the first one.
    new TargetUrlValidator(config.getAllowlistHosts()).validate(config.getTargetUrl());
    String credential = config.resolveCredential(session);
    ScimClientConfig clientConfig = buildScimClientConfig(config, credential);
    var requestBuilder = new ScimRequestBuilder(config.getTargetUrl(), clientConfig);
    Map<String, String> authHeaders = buildAuthHeaders(config, credential);
    return new ScimTargetClient(requestBuilder, authHeaders);
  }

  /**
   * Builds the SDK client config, wiring in HTTP Basic auth when {@link
   * ScimTargetConfig#getAuthMode()} is {@link ScimTargetConfig.AuthMode#BASIC} --
   * verified directly against {@code scim-sdk-client} 1.34.0's bytecode that {@code
   * ScimHttpClient.sendRequest} applies this to every request (all HTTP methods funnel
   * through that one method) whenever the request doesn't already carry an explicit
   * {@code Authorization} header, which is exactly what {@link #buildAuthHeaders} leaves
   * true for Basic mode.
   *
   * <p>Rejects a blank username here rather than trusting config-save-time validation
   * ({@code ScimTargetStorageProviderFactory.validateConfiguration}) alone: {@code
   * BasicAuth.getAuthorizationHeaderValue()} treats a {@code null} username as an empty
   * string, not an error, so an unvalidated config would otherwise silently build a
   * working-looking but wrong header instead of failing loudly -- the same class of
   * silent 401 this auth mode existed to fix in the first place.
   */
  ScimClientConfig buildScimClientConfig(ScimTargetConfig config, String credential) {
    var builder =
        ScimClientConfig.builder().connectTimeout(5).requestTimeout(10).socketTimeout(10);
    if (config.getAuthMode() == ScimTargetConfig.AuthMode.BASIC) {
      String username = config.getUsername();
      if (username == null || username.isBlank()) {
        throw new IllegalStateException(
            "Auth mode is Basic but no username is configured for this SCIM target");
      }
      builder.basic(username, credential);
    }
    return builder.build();
  }

  /**
   * Bearer still passes its header per-request: this SDK has no client-level convenience
   * for a bearer token the way {@code ScimClientConfig.builder().basic(...)} exists for
   * Basic auth (see {@link ScimTargetClient}'s doc). Basic auth leaves this map empty on
   * purpose: an explicit {@code Authorization} header here would collide with the
   * client-level {@code BasicAuth} set in {@link #buildScimClientConfig}, which only
   * applies when the outgoing request doesn't already carry one.
   */
  Map<String, String> buildAuthHeaders(ScimTargetConfig config, String credential) {
    return config.getAuthMode() == ScimTargetConfig.AuthMode.BASIC
        ? Map.of()
        : Map.of("Authorization", "Bearer " + credential);
  }

  @Override
  public void close() {
    // Per-request provider instance; the shared executor lives on the factory.
  }
}
