package com.littleauth.keycloak.scim.reconcile;

import com.littleauth.keycloak.scim.config.ScimTargetConfig;
import com.littleauth.keycloak.scim.config.ScimTargetConfigLookup;
import java.util.List;
import java.util.Optional;
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
 */
final class ReconciliationTick {

  private static final Logger LOGGER = Logger.getLogger(ReconciliationTick.class.getName());

  private ReconciliationTick() {}

  static void run(KeycloakSessionFactory sessionFactory, ExecutorService executor) {
    List<String> realmIds =
        KeycloakModelUtils.runJobInTransactionWithResult(
            sessionFactory, session -> session.realms().getRealmsStream().map(RealmModel::getId).toList());
    for (String realmId : realmIds) {
      executor.submit(() -> runForRealm(sessionFactory, realmId));
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
