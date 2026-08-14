package com.littleauth.keycloak.scim.store;

import java.util.List;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;

/** Registers {@link ScimSyncMapping} with Keycloak's own JPA {@code EntityManagerFactory}. */
public class ScimJpaEntityProvider implements JpaEntityProvider {

  @Override
  public List<Class<?>> getEntities() {
    return List.of(ScimSyncMapping.class);
  }

  @Override
  public String getChangelogLocation() {
    return "META-INF/scim-changelog.xml";
  }

  @Override
  public String getFactoryId() {
    return ScimJpaEntityProviderFactory.ID;
  }

  @Override
  public void close() {
    // Stateless -- nothing to release.
  }
}
