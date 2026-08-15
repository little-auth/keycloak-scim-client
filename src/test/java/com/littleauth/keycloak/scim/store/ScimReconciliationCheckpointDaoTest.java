package com.littleauth.keycloak.scim.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.persistence.EntityManager;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@link ScimReconciliationCheckpointDao#findOrCreate} is what lets {@code ReconciliationJob}
 * resume a realm's pagination from wherever it last got to (issue #6) -- a fresh checkpoint
 * starts at offset 0, and a second lookup for the same realm returns the same row rather than
 * a second, competing cursor.
 */
class ScimReconciliationCheckpointDaoTest {

  private static SessionFactory sessionFactory;
  private EntityManager entityManager;
  private ScimReconciliationCheckpointDao dao;

  @BeforeAll
  static void bootstrapSessionFactory() {
    sessionFactory =
        new Configuration()
            .addAnnotatedClass(ScimReconciliationCheckpoint.class)
            .setProperty("hibernate.connection.driver_class", "org.h2.Driver")
            .setProperty(
                "hibernate.connection.url",
                "jdbc:h2:mem:scim-reconciliation-checkpoint-dao-test;DB_CLOSE_DELAY=-1")
            .setProperty("hibernate.hbm2ddl.auto", "create-drop")
            .buildSessionFactory();
  }

  @AfterAll
  static void closeSessionFactory() {
    sessionFactory.close();
  }

  @BeforeEach
  void openEntityManager() {
    entityManager = sessionFactory.createEntityManager();
    dao = new ScimReconciliationCheckpointDao(entityManager);
  }

  @AfterEach
  void closeEntityManager() {
    entityManager.close();
  }

  @Test
  void findOrCreateInsertsFreshCheckpointStartingAtOffsetZero() {
    entityManager.getTransaction().begin();
    ScimReconciliationCheckpoint checkpoint =
        dao.findOrCreate("realm-a", ScimSyncMapping.ResourceType.USER);
    entityManager.getTransaction().commit();

    assertEquals("realm-a", checkpoint.getRealmId());
    assertEquals(0, checkpoint.getNextOffset());
  }

  @Test
  void findOrCreateReturnsExistingCheckpointInsteadOfInsertingSecondOne() {
    entityManager.getTransaction().begin();
    ScimReconciliationCheckpoint first =
        dao.findOrCreate("realm-b", ScimSyncMapping.ResourceType.USER);
    first.setNextOffset(60);
    entityManager.getTransaction().commit();

    entityManager.getTransaction().begin();
    ScimReconciliationCheckpoint second =
        dao.findOrCreate("realm-b", ScimSyncMapping.ResourceType.USER);
    entityManager.getTransaction().commit();

    assertEquals(first.getId(), second.getId());
    assertEquals(60, second.getNextOffset());
  }

  @Test
  void findReturnsEmptyWhenNoCheckpointExists() {
    var result = dao.find("realm-c", ScimSyncMapping.ResourceType.USER);
    assertTrue(result.isEmpty());
  }
}
