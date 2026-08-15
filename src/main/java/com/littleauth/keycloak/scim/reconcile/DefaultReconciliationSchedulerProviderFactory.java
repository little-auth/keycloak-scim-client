package com.littleauth.keycloak.scim.reconcile;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.timer.TimerProvider;

/**
 * Registers N7's background reconciliation tick with Keycloak's {@code TimerProvider} once at
 * server boot (issue #6). Owns the executor that keeps a page's synchronous per-user SCIM
 * calls off the timer thread -- see {@link ReconciliationTick}'s doc for why that matters --
 * mirroring the same off-critical-path pattern {@code ScimEventListenerProviderFactory}
 * already established for N6.
 */
public class DefaultReconciliationSchedulerProviderFactory
    implements ReconciliationSchedulerProviderFactory {

  public static final String ID = "keycloak-scim-client-reconciliation";

  /**
   * How often the timer fires. Deliberately small and fixed (not admin-configurable) so a
   * page's worth of resumable progress happens promptly after a restart; a realm's actual
   * full-pass cadence naturally falls out of its user count and this tick interval rather
   * than a separate cooldown setting -- see the implementation ticket's follow-ups for the
   * configurable-cadence idea this deliberately leaves out of scope.
   */
  static final long TICK_INTERVAL_MS = 5 * 60 * 1000L;

  private static final String TIMER_TASK_NAME = "keycloak-scim-client-reconciliation-tick";
  private static final Logger LOGGER =
      Logger.getLogger(DefaultReconciliationSchedulerProviderFactory.class.getName());

  private ExecutorService executorService;
  private KeycloakSessionFactory sessionFactory;

  @Override
  public ReconciliationSchedulerProvider create(KeycloakSession session) {
    return new DefaultReconciliationSchedulerProvider();
  }

  @Override
  public void init(Config.Scope config) {
    ThreadFactory threadFactory =
        runnable -> {
          Thread thread = new Thread(runnable, "keycloak-scim-client-reconciliation");
          thread.setDaemon(true);
          return thread;
        };
    executorService = Executors.newFixedThreadPool(2, threadFactory);
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    this.sessionFactory = factory;
    KeycloakModelUtils.runJobInTransaction(
        factory,
        session -> {
          TimerProvider timer = session.getProvider(TimerProvider.class);
          if (timer != null) {
            timer.schedule(() -> ReconciliationTick.run(factory, executorService), TICK_INTERVAL_MS, TIMER_TASK_NAME);
          }
        });
  }

  @Override
  public void close() {
    if (sessionFactory != null) {
      try {
        KeycloakModelUtils.runJobInTransaction(
            sessionFactory,
            session -> {
              TimerProvider timer = session.getProvider(TimerProvider.class);
              if (timer != null) {
                timer.cancelTask(TIMER_TASK_NAME);
              }
            });
      } catch (RuntimeException e) {
        // Best-effort during shutdown -- the JVM going away cancels the timer regardless.
        LOGGER.log(Level.FINE, "SCIM reconciliation: could not cleanly cancel the timer task", e);
      }
    }
    if (executorService != null) {
      executorService.shutdown();
    }
  }

  @Override
  public String getId() {
    return ID;
  }
}
