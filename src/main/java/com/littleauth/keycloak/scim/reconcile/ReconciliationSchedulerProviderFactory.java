package com.littleauth.keycloak.scim.reconcile;

import org.keycloak.provider.ProviderFactory;

/**
 * Factory interface for the {@code keycloak-scim-client-reconciliation-scheduler} SPI.
 * {@link DefaultReconciliationSchedulerProviderFactory} is the (sole) implementation,
 * discovered via {@code META-INF/services}; declared separately per Keycloak's own SPI
 * convention (a small marker interface the Spi class points at, decoupled from the concrete
 * implementation).
 */
public interface ReconciliationSchedulerProviderFactory
    extends ProviderFactory<ReconciliationSchedulerProvider> {}
