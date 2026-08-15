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
 * Proves the {@link ScimReconciliationCheckpoint} JPA mapping against a real Hibernate
 * {@link SessionFactory} (H2 in-memory, mirrors {@code ScimSyncMappingPersistenceTest}) and
 * that {@code (realmId, resourceType)} uniqueness is enforced at the database level -- issue
 * #6: a realm has exactly one in-flight pagination checkpoint per resource type, never two
 * racing scans silently double-processing or corrupting each other's offset.
 */
class ScimReconciliationCheckpointPersistenceTest {

  private static SessionFactory sessionFactory;

  @BeforeAll
  static void bootstrapSessionFactory() {
    sessionFactory =
        new Configuration()
            .addAnnotatedClass(ScimReconciliationCheckpoint.class)
            .setProperty("hibernate.connection.driver_class", "org.h2.Driver")
            .setProperty(
                "hibernate.connection.url",
                "jdbc:h2:mem:scim-reconciliation-checkpoint-test;DB_CLOSE_DELAY=-1")
            .setProperty("hibernate.hbm2ddl.auto", "create-drop")
            .setProperty("hibernate.show_sql", "false")
            .buildSessionFactory();
  }

  @AfterAll
  static void closeSessionFactory() {
    sessionFactory.close();
  }

  private static ScimReconciliationCheckpoint checkpoint(String realmId, int nextOffset) {
    var checkpoint = new ScimReconciliationCheckpoint();
    checkpoint.setId(UUID.randomUUID().toString());
    checkpoint.setRealmId(realmId);
    checkpoint.setResourceType(ScimSyncMapping.ResourceType.USER);
    checkpoint.setNextOffset(nextOffset);
    return checkpoint;
  }

  @Test
  void persistsAndReloadsCheckpoint() {
    ScimReconciliationCheckpoint saved = checkpoint("realm-a", 40);
    try (var session = sessionFactory.openSession()) {
      session.beginTransaction();
      session.persist(saved);
      session.getTransaction().commit();
    }

    try (var session = sessionFactory.openSession()) {
      ScimReconciliationCheckpoint reloaded =
          session.find(ScimReconciliationCheckpoint.class, saved.getId());
      assertEquals("realm-a", reloaded.getRealmId());
      assertEquals(40, reloaded.getNextOffset());
      assertEquals(0L, reloaded.getPagesProcessedSincePassStart());
    }
  }

  @Test
  void rejectsSecondCheckpointForSameRealmAndResourceType() {
    ScimReconciliationCheckpoint first = checkpoint("realm-b", 0);
    ScimReconciliationCheckpoint duplicate = checkpoint("realm-b", 20);

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
