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
 * AC-1/AC-3: the DAO's find-or-create is what makes a Keycloak CREATE event idempotent
 * across retries (pre-mortem: a mapping write that isn't atomic with the SCIM POST must
 * not be able to produce a duplicate SCIM resource on the next attempt).
 */
class ScimSyncMappingDaoTest {

  private static SessionFactory sessionFactory;
  private EntityManager entityManager;
  private ScimSyncMappingDao dao;

  @BeforeAll
  static void bootstrapSessionFactory() {
    sessionFactory =
        new Configuration()
            .addAnnotatedClass(ScimSyncMapping.class)
            .setProperty("hibernate.connection.driver_class", "org.h2.Driver")
            .setProperty(
                "hibernate.connection.url", "jdbc:h2:mem:scim-sync-dao-test;DB_CLOSE_DELAY=-1")
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
    dao = new ScimSyncMappingDao(entityManager);
  }

  @AfterEach
  void closeEntityManager() {
    entityManager.close();
  }

  @Test
  void findOrCreateInsertsNewMappingWhenNoneExists() {
    entityManager.getTransaction().begin();
    ScimSyncMapping mapping =
        dao.findOrCreate("realm-a", ScimSyncMapping.ResourceType.USER, "kc-user-1");
    entityManager.getTransaction().commit();

    assertEquals("realm-a", mapping.getRealmId());
    assertEquals("kc-user-1", mapping.getKeycloakId());
  }

  @Test
  void findOrCreateReturnsExistingMappingInsteadOfInsertingSecondOne() {
    entityManager.getTransaction().begin();
    ScimSyncMapping first =
        dao.findOrCreate("realm-b", ScimSyncMapping.ResourceType.USER, "kc-user-2");
    first.setScimId("scim-user-2");
    entityManager.getTransaction().commit();

    entityManager.getTransaction().begin();
    ScimSyncMapping second =
        dao.findOrCreate("realm-b", ScimSyncMapping.ResourceType.USER, "kc-user-2");
    entityManager.getTransaction().commit();

    assertEquals(first.getId(), second.getId());
    assertEquals("scim-user-2", second.getScimId());
  }

  @Test
  void findByKeycloakIdReturnsEmptyWhenNoMappingExists() {
    var result = dao.findByKeycloakId("realm-c", ScimSyncMapping.ResourceType.USER, "unknown");
    assertTrue(result.isEmpty());
  }
}
