package com.littleauth.keycloak.scim.reconcile;

import org.keycloak.provider.Provider;

/**
 * Marker provider for the {@code keycloak-scim-client-reconciliation-scheduler} SPI --
 * deliberately empty. The scheduler's actual state (shared executor, {@code TimerProvider}
 * registration) lives on {@link ReconciliationSchedulerProviderFactory}, not on a
 * per-request instance of this provider; see that factory's doc.
 */
public interface ReconciliationSchedulerProvider extends Provider {}
