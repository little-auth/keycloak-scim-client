package com.littleauth.keycloak.scim.reconcile;

import com.littleauth.keycloak.scim.config.ScimTargetConfig;
import com.littleauth.keycloak.scim.config.ScimTargetConfigLookup;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;

/**
 * One scheduler tick: for every realm with a configured, sync-and-reconciliation-enabled
 * SCIM target, process one {@link ReconciliationJob} page off the shared executor -- never
 * on the {@code TimerProvider}'s own thread (pre-mortem finding, issue #6: Keycloak's
 * `TimerProvider` backs onto a single scheduled thread, so running a whole page's
 * synchronous per-user HTTP calls directly on that callback would risk stalling
 * reconciliation, and any other plugin's timer-scheduled work, across every realm if one
 * target hangs).
 *
 * <p>{@link #IN_FLIGHT_REALM_IDS} skips a realm the tick would otherwise resubmit while its
 * previous page is still running -- a page's worst-case duration (up to {@code PAGE_SIZE}
 * users, each up to a couple of SCIM round trips at the client's configured timeouts) can
 * exceed the tick interval. Without this guard, two overlapping runs for the same realm
 * would both read the checkpoint's current offset and do duplicate work; each per-user step
 * is independently idempotent (see {@code ReconciliationJob}'s duplicate-create guard) so an
 * overlap was never a correctness hazard, but it is a real, easily-avoided waste of outbound
 * calls against the target -- found and fixed during this change's own review, not left as a
 * documented limitation.
 *
 * <p><b>Known limitation, explicitly out of this change's scope:</b> {@link
 * #IN_FLIGHT_REALM_IDS} is JVM-local. On a clustered (HA) Keycloak deployment, every node
 * runs its own timer and its own copy of this set, so the guard does not prevent two
 * *different nodes* from processing the same realm concurrently -- unlike the single-node
 * overlap case above, a cross-node race widens the duplicate-create window past what the
 * mapping table's unique constraint can catch (the outbound SCIM {@code POST} can already
 * have landed on the target before either node's local constraint would fire). Keycloak's
 * own {@code ClusterAwareScheduledTaskRunner}/{@code ClusterProvider} is the documented
 * answer to this class of problem; adopting it is real, valuable follow-up work, not
 * something this ticket's scope (pagination/checkpointing and the N6/N7 version-check race)
 * committed to solving.
 */
final class ReconciliationTick {

  private static final Logger LOGGER = Logger.getLogger(ReconciliationTick.class.getName());
  private static final Set<String> IN_FLIGHT_REALM_IDS = ConcurrentHashMap.newKeySet();

  private ReconciliationTick() {}

  static void run(KeycloakSessionFactory sessionFactory, ExecutorService executor) {
    List<String> realmIds =
        KeycloakModelUtils.runJobInTransactionWithResult(
            sessionFactory, session -> session.realms().getRealmsStream().map(RealmModel::getId).toList());
    for (String realmId : realmIds) {
      if (!IN_FLIGHT_REALM_IDS.add(realmId)) {
        LOGGER.info(
            "SCIM reconciliation: skipping realm "
                + realmId
                + " this tick -- its previous page is still running");
        continue;
      }
      try {
        executor.submit(
            () -> {
              try {
                runForRealm(sessionFactory, realmId);
              } finally {
                IN_FLIGHT_REALM_IDS.remove(realmId);
              }
            });
      } catch (RuntimeException e) {
        // submit() itself threw (e.g. RejectedExecutionException after the executor has
        // been shut down) -- the runnable above never ran, so its own finally never fired.
        // Without this, realmId would stay marked in-flight forever, silently blocking
        // this realm's reconciliation on every future tick for the life of the JVM.
        IN_FLIGHT_REALM_IDS.remove(realmId);
        LOGGER.log(Level.WARNING, "SCIM reconciliation: failed to submit realm " + realmId, e);
      }
    }
  }

  private static void runForRealm(KeycloakSessionFactory sessionFactory, String realmId) {
    try {
      KeycloakModelUtils.runJobInTransaction(
          sessionFactory,
          session -> {
            RealmModel realm = session.realms().getRealm(realmId);
            if (realm == null) {
              return;
            }
            session.getContext().setRealm(realm);
            Optional<ScimTargetConfig> configOpt = ScimTargetConfigLookup.forRealm(realm);
            if (configOpt.isEmpty()) {
              return;
            }
            ScimTargetConfig config = configOpt.get();
            if (!config.isSyncEnabled() || !config.isReconciliationEnabled()) {
              return;
            }
            ReconciliationJob.runOnePage(session, realm, config);
          });
    } catch (RuntimeException e) {
      // A single realm's reconciliation failure must never stop the tick from covering
      // every other realm, and must never propagate to the timer thread.
      LOGGER.log(Level.WARNING, "SCIM reconciliation tick failed for realm " + realmId, e);
    }
  }
}
