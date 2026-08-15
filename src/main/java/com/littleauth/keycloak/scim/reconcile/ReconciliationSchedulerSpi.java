package com.littleauth.keycloak.scim.reconcile;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/**
 * Declares a small, dedicated custom SPI (issue #6) whose sole purpose is registering N7's
 * background reconciliation tick with Keycloak's {@code TimerProvider} once at server boot --
 * kept separate from the event-listener SPI ({@code ScimEventListenerProviderFactory})
 * rather than piggybacked onto its {@code postInit}, so scheduling concerns don't get
 * conflated with event-dispatch concerns. No admin-facing surface, so {@link #isInternal()}
 * is {@code true}.
 */
public class ReconciliationSchedulerSpi implements Spi {

  @Override
  public boolean isInternal() {
    return true;
  }

  @Override
  public String getName() {
    return "keycloak-scim-client-reconciliation-scheduler";
  }

  @Override
  public Class<? extends Provider> getProviderClass() {
    return ReconciliationSchedulerProvider.class;
  }

  @Override
  public Class<? extends ProviderFactory> getProviderFactoryClass() {
    return ReconciliationSchedulerProviderFactory.class;
  }
}
