package com.littleauth.keycloak.scim.reconcile;

/** Stateless -- see {@link DefaultReconciliationSchedulerProviderFactory} for the real state. */
public class DefaultReconciliationSchedulerProvider implements ReconciliationSchedulerProvider {

  @Override
  public void close() {
    // Per-request instance; nothing to release -- the shared timer/executor live on the
    // factory.
  }
}
