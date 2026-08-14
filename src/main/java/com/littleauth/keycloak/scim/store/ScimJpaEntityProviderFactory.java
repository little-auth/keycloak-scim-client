package com.littleauth.keycloak.scim.store;

import org.keycloak.Config;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/** Factory for {@link ScimJpaEntityProvider}, registered via {@code META-INF/services}. */
public class ScimJpaEntityProviderFactory implements JpaEntityProviderFactory {

  public static final String ID = "keycloak-scim-client";

  @Override
  public JpaEntityProvider create(KeycloakSession session) {
    return new ScimJpaEntityProvider();
  }

  @Override
  public void init(Config.Scope config) {
    // No configuration needed.
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // No cross-provider wiring needed at startup.
  }

  @Override
  public void close() {
    // Nothing to release.
  }

  @Override
  public String getId() {
    return ID;
  }
}
