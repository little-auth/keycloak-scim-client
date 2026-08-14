package com.littleauth.keycloak.scim.config;

import org.keycloak.storage.UserStorageProvider;

/**
 * Deliberately empty: this Component exists purely to host {@link ScimTargetConfig} on
 * Keycloak's User Federation admin console page (which gets the generic config-form UI
 * for free), not to actually import/lookup users -- see the "Config hosting mechanism"
 * discovery in the implementation ticket. In Keycloak 25's storage SPI, {@code
 * UserStorageProvider} itself declares no lookup capability (those are separate, optional
 * interfaces), so there is nothing to implement here beyond {@link #close()}.
 */
public class ScimTargetStorageProvider implements UserStorageProvider {

  @Override
  public void close() {
    // Stateless -- nothing to release.
  }
}
