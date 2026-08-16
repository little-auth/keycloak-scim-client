package com.littleauth.keycloak.scim.reconcile;

import com.littleauth.keycloak.scim.client.ReconciliationWriteResult;
import com.littleauth.keycloak.scim.client.ScimTargetClient;
import com.littleauth.keycloak.scim.client.ScimTargetClientFactory;
import com.littleauth.keycloak.scim.config.ScimTargetConfig;
import com.littleauth.keycloak.scim.event.KeycloakUserMapper;
import com.littleauth.keycloak.scim.store.ScimReconciliationCheckpoint;
import com.littleauth.keycloak.scim.store.ScimReconciliationCheckpointDao;
import com.littleauth.keycloak.scim.store.ScimSyncMapping;
import com.littleauth.keycloak.scim.store.ScimSyncMappingDao;
import de.captaingoldfish.scim.sdk.client.response.ServerResponse;
import de.captaingoldfish.scim.sdk.common.resources.User;
import de.captaingoldfish.scim.sdk.common.resources.complex.Meta;
import de.captaingoldfish.scim.sdk.common.response.ListResponse;
import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

/**
 * N7 in the locked breadboard: periodic full-realm reconciliation, self-healing drift the
 * event-driven push (N6) misses (e.g. events lost during an outage). Walks Keycloak's local
 * user list page-by-page against a persisted, per-realm {@link ScimReconciliationCheckpoint}
 * -- issue #6 -- so an interrupted run (OOM, restart) resumes from the last completed page
 * rather than restarting the full scan, and applies each diff-derived write only after
 * checking the target's {@code meta.version}/{@code lastModified} immediately beforehand
 * ({@link ScimTargetClient#replaceIfVersionUnchanged}), mitigating (not fully eliminating --
 * see the implementation ticket's residual-risk note) the N6/N7 race that could otherwise
 * silently lose an update.
 *
 * <p>Deliberately does not promise gapless single-pass coverage: {@code
 * UserQueryMethodsProvider#searchForUserStream} has no documented stable ordering guarantee,
 * so a resumed pass could in principle skip or revisit a handful of users. This is acceptable
 * because reconciliation is idempotent self-healing and a full pass restarts immediately on
 * completion -- any pagination-order gap is corrected on the next pass, not left open
 * indefinitely.
 */
public final class ReconciliationJob {

  static final int PAGE_SIZE = 20;
  private static final long PASS_PAGE_WARNING_THRESHOLD = 10_000;
  private static final Logger LOGGER = Logger.getLogger(ReconciliationJob.class.getName());

  private ReconciliationJob() {}

  /** Processes one page for the given realm, advancing (or resetting) its checkpoint. */
  public static PageResult runOnePage(
      KeycloakSession session, RealmModel realm, ScimTargetConfig config) {
    EntityManager entityManager = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    var checkpointDao = new ScimReconciliationCheckpointDao(entityManager);
    var mappingDao = new ScimSyncMappingDao(entityManager);
    ScimReconciliationCheckpoint checkpoint =
        checkpointDao.findOrCreate(realm.getId(), ScimSyncMapping.ResourceType.USER);
    int offset = Math.max(0, checkpoint.getNextOffset());
    if (offset == 0) {
      checkpoint.setPassStartedTime(System.currentTimeMillis());
    }

    List<UserModel> page =
        session.users().searchForUserStream(realm, Map.of(), offset, PAGE_SIZE).toList();

    int created = 0;
    int updated = 0;
    int inSync = 0;
    int conflicts = 0;
    int failed = 0;
    if (!page.isEmpty()) {
      try (ScimTargetClient client = ScimTargetClientFactory.build(session, config)) {
        for (UserModel kcUser : page) {
          // A malformed representation must not block every other user in this page or
          // roll back the whole page's progress -- see reconcileUserSafely's doc for why
          // an uncaught exception inside the loop itself would be worse.
          UserOutcome outcome;
          try {
            UserRepresentation kcRep = ModelToRepresentation.toRepresentation(session, realm, kcUser);
            outcome = reconcileUserSafely(client, mappingDao, realm.getId(), kcUser.getId(), kcRep);
            // Flush this user's mapping write now rather than letting Hibernate's default
            // auto-flush defer it to the next query (which would run as part of some
            // *later* user's findOrCreate) or to the final commit -- either way, a
            // persistence-level failure here (not just an HTTP-level one) would otherwise
            // surface against the wrong user, or only at commit time when it's too late to
            // isolate from users that already succeeded.
            entityManager.flush();
          } catch (RuntimeException e) {
            LOGGER.log(
                Level.WARNING,
                "SCIM reconciliation: user " + kcUser.getId() + " threw, skipping",
                e);
            outcome = UserOutcome.FAILED;
          }
          switch (outcome) {
            case CREATED -> created++;
            case UPDATED -> updated++;
            case IN_SYNC -> inSync++;
            case CONFLICT -> conflicts++;
            case FAILED -> failed++;
          }
        }
      }
    }

    boolean passComplete = advanceCheckpoint(checkpoint, offset, PAGE_SIZE, page.size());

    PageResult result =
        new PageResult(
            realm.getId(), offset, page.size(), created, updated, inSync, conflicts, failed, passComplete);
    LOGGER.info("SCIM reconciliation: " + result);
    return result;
  }

  /**
   * Pure pagination/checkpoint bookkeeping -- no Keycloak or SCIM types involved, so this is
   * unit tested directly rather than through the full {@link #runOnePage} orchestration.
   * Advances {@code checkpoint.nextOffset} by the page's actual size, or resets to 0 (pass
   * complete) when the page came back shorter than {@code pageSize}.
   */
  static boolean advanceCheckpoint(
      ScimReconciliationCheckpoint checkpoint, int startOffset, int pageSize, int actualCount) {
    boolean passComplete = actualCount < pageSize;
    if (passComplete) {
      checkpoint.setNextOffset(0);
      checkpoint.setLastCompletedTime(System.currentTimeMillis());
      checkpoint.setPagesProcessedSincePassStart(0);
    } else {
      checkpoint.setNextOffset(startOffset + actualCount);
      long pages = checkpoint.getPagesProcessedSincePassStart() + 1;
      checkpoint.setPagesProcessedSincePassStart(pages);
      if (pages == PASS_PAGE_WARNING_THRESHOLD) {
        LOGGER.warning(
            "SCIM reconciliation: realm "
                + checkpoint.getRealmId()
                + " has not completed a full pass after "
                + pages
                + " pages -- it may be growing faster than reconciliation throughput");
      }
    }
    return passComplete;
  }

  /** What happened when reconciliation processed a single Keycloak user. */
  enum UserOutcome {
    CREATED,
    UPDATED,
    IN_SYNC,
    CONFLICT,
    FAILED
  }

  /**
   * Wraps {@link #reconcileUser} so one user's uncaught exception (an SDK-level throw that
   * isn't expressed as a {@code ServerResponse} failure, a null-pointer on an unexpected
   * shape, ...) never propagates out of the page loop. Left uncaught, it would roll back
   * the whole page's transaction -- including the checkpoint advance -- turning a single
   * bad record into a permanent stall, since the next tick would retry the exact same
   * offset forever rather than moving past it.
   */
  static UserOutcome reconcileUserSafely(
      ScimTargetClient client,
      ScimSyncMappingDao mappingDao,
      String realmId,
      String keycloakUserId,
      UserRepresentation kcRep) {
    try {
      return reconcileUser(client, mappingDao, realmId, keycloakUserId, kcRep);
    } catch (RuntimeException e) {
      LOGGER.log(
          Level.WARNING,
          "SCIM reconciliation: user " + keycloakUserId + " threw while reconciling, skipping",
          e);
      return UserOutcome.FAILED;
    }
  }

  static UserOutcome reconcileUser(
      ScimTargetClient client,
      ScimSyncMappingDao mappingDao,
      String realmId,
      String keycloakUserId,
      UserRepresentation kcRep) {
    ScimSyncMapping mapping =
        mappingDao.findOrCreate(realmId, ScimSyncMapping.ResourceType.USER, keycloakUserId);
    UserOutcome outcome =
        mapping.getScimId() == null
            ? selfHealCreate(client, mapping, kcRep)
            : reconcileExisting(client, mapping, kcRep);
    mapping.setLastSyncTime(System.currentTimeMillis());
    return outcome;
  }

  private static UserOutcome selfHealCreate(
      ScimTargetClient client, ScimSyncMapping mapping, UserRepresentation kcRep) {
    String keycloakUserId = mapping.getKeycloakId();
    // Duplicate-create guard (issue #6 pre-mortem): an event-driven create (N6) and this
    // reconciliation create can race across two separate transactions, each observing no
    // mapping yet. Check the target by externalId before creating a second resource.
    ServerResponse<ListResponse<User>> existing = client.findByExternalId(keycloakUserId);
    if (existing.isSuccess() && !existing.getResource().getListedResources().isEmpty()) {
      String scimId = existing.getResource().getListedResources().get(0).getId().orElse(null);
      mapping.setScimId(scimId);
      mapping.setLastSyncResult(ScimSyncMapping.SyncResult.SUCCESS);
      mapping.setLastSyncError(null);
      return UserOutcome.CREATED;
    }

    User desired = KeycloakUserMapper.toScimUser(kcRep, keycloakUserId);
    ServerResponse<User> response = client.createUser(desired);
    if (response.isSuccess()) {
      mapping.setScimId(response.getResource().getId().orElse(null));
      mapping.setLastSyncResult(ScimSyncMapping.SyncResult.SUCCESS);
      mapping.setLastSyncError(null);
      return UserOutcome.CREATED;
    }
    mapping.setLastSyncResult(ScimSyncMapping.SyncResult.FAILED);
    mapping.setLastSyncError("HTTP " + response.getHttpStatus() + ": " + response.getResponseBody());
    return UserOutcome.FAILED;
  }

  private static UserOutcome reconcileExisting(
      ScimTargetClient client, ScimSyncMapping mapping, UserRepresentation kcRep) {
    ServerResponse<User> current = client.getUser(mapping.getScimId());
    if (!current.isSuccess()) {
      if (Integer.valueOf(404).equals(current.getHttpStatus())) {
        // The target resource disappeared out-of-band -- self-heal by recreating under a
        // fresh SCIM id rather than failing every pass forever.
        mapping.setScimId(null);
        return selfHealCreate(client, mapping, kcRep);
      }
      mapping.setLastSyncResult(ScimSyncMapping.SyncResult.FAILED);
      mapping.setLastSyncError("HTTP " + current.getHttpStatus() + ": " + current.getResponseBody());
      return UserOutcome.FAILED;
    }

    User currentUser = current.getResource();
    User desired = KeycloakUserMapper.toScimUser(kcRep, mapping.getKeycloakId());
    if (!KeycloakUserMapper.differs(currentUser, desired)) {
      mapping.setLastSyncResult(ScimSyncMapping.SyncResult.SKIPPED);
      mapping.setLastSyncError(null);
      return UserOutcome.IN_SYNC;
    }

    Meta expectedMeta = currentUser.getMeta().orElse(null);
    // Fetch-then-merge (pre-mortem finding): build the write from the resource we just
    // fetched, not a bare new User(), so a full PUT never wipes a target-only field.
    User merged = KeycloakUserMapper.mergeOnto(currentUser, kcRep, mapping.getKeycloakId());
    ReconciliationWriteResult result =
        client.replaceIfVersionUnchanged(mapping.getScimId(), merged, expectedMeta);
    return switch (result.outcome()) {
      case APPLIED -> {
        mapping.setLastSyncResult(ScimSyncMapping.SyncResult.SUCCESS);
        mapping.setLastSyncError(null);
        yield UserOutcome.UPDATED;
      }
      case VERSION_CONFLICT -> {
        mapping.setLastSyncResult(ScimSyncMapping.SyncResult.SKIPPED);
        mapping.setLastSyncError(
            "skipped: concurrent modification detected on SCIM target since last read");
        yield UserOutcome.CONFLICT;
      }
      case FAILED -> {
        ServerResponse<User> response = result.response();
        mapping.setLastSyncResult(ScimSyncMapping.SyncResult.FAILED);
        mapping.setLastSyncError(
            response == null
                ? "reconciliation write failed"
                : "HTTP " + response.getHttpStatus() + ": " + response.getResponseBody());
        yield UserOutcome.FAILED;
      }
    };
  }
}
