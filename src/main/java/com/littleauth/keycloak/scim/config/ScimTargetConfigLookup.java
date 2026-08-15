package com.littleauth.keycloak.scim.config;

import java.util.Optional;
import org.keycloak.models.RealmModel;
import org.keycloak.storage.UserStorageProvider;

/**
 * Finds a realm's {@code keycloak-scim-target} component, if configured -- shared by the
 * event-driven push path ({@code ScimEventListenerProvider}) and reconciliation ({@code
 * ReconciliationTick}, issue #6) so both look it up exactly the same way.
 */
public final class ScimTargetConfigLookup {

  private ScimTargetConfigLookup() {}

  /** Empty if the realm has no {@code keycloak-scim-target} component configured. */
  public static Optional<ScimTargetConfig> forRealm(RealmModel realm) {
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
}
