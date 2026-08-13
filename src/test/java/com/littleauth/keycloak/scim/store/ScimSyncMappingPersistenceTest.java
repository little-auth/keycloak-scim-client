package com.littleauth.keycloak.scim.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.UUID;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Proves the {@link ScimSyncMapping} JPA mapping against a real Hibernate
 * {@link SessionFactory} (H2 in-memory, same Hibernate version Keycloak 25.0.6 itself
 * runs) rather than just annotations that happen to compile -- and that the
 * {@code (realmId, resourceType, keycloakId)} uniqueness this plugin's idempotency
 * depends on is actually enforced at the database level, not just in application code.
 */
class ScimSyncMappingPersistenceTest {

  private static SessionFactory sessionFactory;

  @BeforeAll
  static void bootstrapSessionFactory() {
    sessionFactory =
        new Configuration()
            .addAnnotatedClass(ScimSyncMapping.class)
            .setProperty("hibernate.connection.driver_class", "org.h2.Driver")
            .setProperty(
                "hibernate.connection.url",
                "jdbc:h2:mem:scim-sync-mapping-test;DB_CLOSE_DELAY=-1")
            .setProperty("hibernate.hbm2ddl.auto", "create-drop")
            .setProperty("hibernate.show_sql", "false")
            .buildSessionFactory();
  }

  @AfterAll
  static void closeSessionFactory() {
    sessionFactory.close();
  }

  private static ScimSyncMapping mapping(String realmId, String keycloakId, String scimId) {
    var mapping = new ScimSyncMapping();
    mapping.setId(UUID.randomUUID().toString());
    mapping.setRealmId(realmId);
    mapping.setResourceType(ScimSyncMapping.ResourceType.USER);
    mapping.setKeycloakId(keycloakId);
    mapping.setScimId(scimId);
    mapping.setLastSyncResult(ScimSyncMapping.SyncResult.SUCCESS);
    mapping.setLastSyncTime(1_000L);
    return mapping;
  }

  @Test
  void persistsAndReloadsMapping() {
    ScimSyncMapping saved = mapping("realm-a", "kc-user-1", "scim-user-1");
    try (var session = sessionFactory.openSession()) {
      session.beginTransaction();
      session.persist(saved);
      session.getTransaction().commit();
    }

    try (var session = sessionFactory.openSession()) {
      ScimSyncMapping reloaded = session.find(ScimSyncMapping.class, saved.getId());
      assertEquals("scim-user-1", reloaded.getScimId());
      assertEquals(ScimSyncMapping.SyncResult.SUCCESS, reloaded.getLastSyncResult());
    }
  }

  @Test
  void rejectsDuplicateMappingForSameRealmResourceTypeAndKeycloakId() {
    ScimSyncMapping first = mapping("realm-b", "kc-user-dup", "scim-user-x");
    ScimSyncMapping duplicate = mapping("realm-b", "kc-user-dup", "scim-user-y");

    try (var session = sessionFactory.openSession()) {
      session.beginTransaction();
      session.persist(first);
      session.getTransaction().commit();
    }

    try (var session = sessionFactory.openSession()) {
      session.beginTransaction();
      session.persist(duplicate);
      assertThrows(ConstraintViolationException.class, () -> session.getTransaction().commit());
    }
  }
}
