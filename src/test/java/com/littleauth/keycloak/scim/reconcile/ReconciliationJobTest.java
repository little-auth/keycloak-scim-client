package com.littleauth.keycloak.scim.reconcile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import com.littleauth.keycloak.scim.client.ReconciliationWriteResult;
import com.littleauth.keycloak.scim.client.ScimTargetClient;
import com.littleauth.keycloak.scim.store.ScimReconciliationCheckpoint;
import com.littleauth.keycloak.scim.store.ScimSyncMapping;
import com.littleauth.keycloak.scim.store.ScimSyncMappingDao;
import de.captaingoldfish.scim.sdk.client.response.ServerResponse;
import de.captaingoldfish.scim.sdk.common.resources.User;
import de.captaingoldfish.scim.sdk.common.response.ListResponse;
import jakarta.persistence.EntityManager;
import java.util.List;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.UserRepresentation;

/**
 * The heart of issue #6: checkpointed pagination ({@link
 * ReconciliationJob#advanceCheckpoint}, pure -- no mocking needed) and the per-user
 * reconciliation decision ({@link ReconciliationJob#reconcileUser} and its helpers,
 * exercised against a mocked {@link ScimTargetClient} plus a real H2-backed {@link
 * ScimSyncMappingDao}, mirroring {@code ScimEventListenerProviderTest}'s style). {@code
 * runOnePage} itself is thin Keycloak-session orchestration composed from these already-
 * tested pieces and isn't separately unit tested -- same documented scope split Slice 1 made
 * for {@code ScimEventListenerProvider}'s own dispatch/processIntent orchestration.
 */
@SuppressWarnings("unchecked")
class ReconciliationJobTest {

  private static SessionFactory sessionFactory;
  private EntityManager entityManager;
  private ScimSyncMappingDao mappingDao;

  @BeforeAll
  static void bootstrapSessionFactory() {
    sessionFactory =
        new Configuration()
            .addAnnotatedClass(ScimSyncMapping.class)
            .setProperty("hibernate.connection.driver_class", "org.h2.Driver")
            .setProperty(
                "hibernate.connection.url", "jdbc:h2:mem:reconciliation-job-test;DB_CLOSE_DELAY=-1")
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
    mappingDao = new ScimSyncMappingDao(entityManager);
  }

  @AfterEach
  void closeEntityManager() {
    entityManager.close();
  }

  private static UserRepresentation representation(String username, boolean enabled) {
    var rep = new UserRepresentation();
    rep.setUsername(username);
    rep.setEnabled(enabled);
    return rep;
  }

  private static ServerResponse<User> successWithScimId(String scimId) {
    ServerResponse<User> response = mock(ServerResponse.class);
    User resource = new User();
    resource.setId(scimId);
    when(response.isSuccess()).thenReturn(true);
    when(response.getResource()).thenReturn(resource);
    return response;
  }

  private static ServerResponse<User> errorResponse(int status) {
    ServerResponse<User> response = mock(ServerResponse.class);
    when(response.isSuccess()).thenReturn(false);
    when(response.getHttpStatus()).thenReturn(status);
    when(response.getResponseBody()).thenReturn("error body");
    return response;
  }

  // Real (not mocked) ListResponse instances: Mockito's inline mock maker cannot instrument
  // ListResponse's class hierarchy (it's deeply intertwined with Jackson's JsonNode family)
  // on this JDK -- see the implementation ticket's discovery log. A real instance populated
  // via its own public API is simpler than fighting that anyway.
  private static ServerResponse<ListResponse<User>> emptyListResponse() {
    ServerResponse<ListResponse<User>> response = mock(ServerResponse.class);
    ListResponse<User> listResponse = new ListResponse<>();
    listResponse.setListedResources(List.of());
    when(response.isSuccess()).thenReturn(true);
    when(response.getResource()).thenReturn(listResponse);
    return response;
  }

  private static ServerResponse<ListResponse<User>> foundByExternalId(String scimId) {
    ServerResponse<ListResponse<User>> response = mock(ServerResponse.class);
    User found = new User();
    found.setId(scimId);
    ListResponse<User> listResponse = new ListResponse<>();
    listResponse.setListedResources(List.<JsonNode>of(found));
    when(response.isSuccess()).thenReturn(true);
    when(response.getResource()).thenReturn(listResponse);
    return response;
  }

  // ---- advanceCheckpoint: pure pagination/checkpoint math, no mocks ----

  @Test
  void advanceCheckpointMovesOffsetForwardWhenPageIsFull() {
    var checkpoint = new ScimReconciliationCheckpoint();
    checkpoint.setNextOffset(40);

    boolean passComplete = ReconciliationJob.advanceCheckpoint(checkpoint, 40, 20, 20);

    assertFalse(passComplete);
    assertEquals(60, checkpoint.getNextOffset());
    assertEquals(1, checkpoint.getPagesProcessedSincePassStart());
    assertNull(checkpoint.getLastCompletedTime());
  }

  @Test
  void advanceCheckpointResetsToZeroAndMarksCompleteWhenPageIsShort() {
    var checkpoint = new ScimReconciliationCheckpoint();
    checkpoint.setNextOffset(40);
    checkpoint.setPagesProcessedSincePassStart(2);

    boolean passComplete = ReconciliationJob.advanceCheckpoint(checkpoint, 40, 20, 7);

    assertTrue(passComplete);
    assertEquals(0, checkpoint.getNextOffset());
    assertEquals(0, checkpoint.getPagesProcessedSincePassStart());
    assertNotNull(checkpoint.getLastCompletedTime());
  }

  @Test
  void advanceCheckpointTreatsAnEmptyPageAsPassComplete() {
    var checkpoint = new ScimReconciliationCheckpoint();
    checkpoint.setNextOffset(100);

    boolean passComplete = ReconciliationJob.advanceCheckpoint(checkpoint, 100, 20, 0);

    assertTrue(passComplete);
    assertEquals(0, checkpoint.getNextOffset());
  }

  @Test
  void advanceCheckpointResumesFromWhereverAnInterruptedPassLeftOff() {
    // Simulates a restart: a fresh checkpoint instance carrying only the persisted offset
    // (as ScimReconciliationCheckpointDao.findOrCreate would return it) must resume there,
    // not from zero.
    var resumed = new ScimReconciliationCheckpoint();
    resumed.setNextOffset(140);

    boolean passComplete = ReconciliationJob.advanceCheckpoint(resumed, 140, 20, 20);

    assertFalse(passComplete);
    assertEquals(160, resumed.getNextOffset());
  }

  // ---- reconcileUserSafely: one user's throw must not escape the page loop ----

  @Test
  void reconcileUserSafelyReturnsFailedInsteadOfPropagatingWhenReconcileUserThrows() {
    // An uncaught exception here would roll back the whole page's transaction -- including
    // the checkpoint advance -- turning one bad record into a permanent stall (the next
    // tick would retry the exact same offset forever). See ReconciliationJob's doc.
    ScimTargetClient client = mock(ScimTargetClient.class);
    when(client.findByExternalId("kc-9")).thenThrow(new IllegalStateException("SDK exploded"));

    entityManager.getTransaction().begin();
    ReconciliationJob.UserOutcome outcome =
        ReconciliationJob.reconcileUserSafely(
            client, mappingDao, "realm-c", "kc-9", representation("kjensen", true));
    entityManager.getTransaction().commit();

    assertEquals(ReconciliationJob.UserOutcome.FAILED, outcome);
  }

  // ---- reconcileUser / selfHealCreate / reconcileExisting ----

  @Test
  void selfHealsByCreatingWhenNoMappingAndNoExistingTargetResource() {
    ScimTargetClient client = mock(ScimTargetClient.class);
    ServerResponse<ListResponse<User>> noneFound = emptyListResponse();
    ServerResponse<User> created = successWithScimId("scim-new");
    when(client.findByExternalId("kc-1")).thenReturn(noneFound);
    when(client.createUser(any())).thenReturn(created);

    entityManager.getTransaction().begin();
    ReconciliationJob.UserOutcome outcome =
        ReconciliationJob.reconcileUser(client, mappingDao, "realm-a", "kc-1", representation("bjensen", true));
    entityManager.getTransaction().commit();

    assertEquals(ReconciliationJob.UserOutcome.CREATED, outcome);
    ScimSyncMapping mapping =
        mappingDao.findByKeycloakId("realm-a", ScimSyncMapping.ResourceType.USER, "kc-1").orElseThrow();
    assertEquals("scim-new", mapping.getScimId());
    assertEquals(ScimSyncMapping.SyncResult.SUCCESS, mapping.getLastSyncResult());
  }

  @Test
  void selfHealBackfillsMappingInsteadOfDuplicateCreatingWhenTargetAlreadyHasTheUser() {
    // The N6/N7 duplicate-create race (issue #6 pre-mortem): reconciliation must check the
    // target by externalId before creating, since an event-driven create could have already
    // landed there under a mapping row reconciliation hasn't observed yet.
    ScimTargetClient client = mock(ScimTargetClient.class);
    ServerResponse<ListResponse<User>> alreadyThere = foundByExternalId("scim-already-there");
    when(client.findByExternalId("kc-2")).thenReturn(alreadyThere);

    entityManager.getTransaction().begin();
    ReconciliationJob.UserOutcome outcome =
        ReconciliationJob.reconcileUser(client, mappingDao, "realm-a", "kc-2", representation("cjensen", true));
    entityManager.getTransaction().commit();

    assertEquals(ReconciliationJob.UserOutcome.CREATED, outcome);
    verify(client, never()).createUser(any());
    ScimSyncMapping mapping =
        mappingDao.findByKeycloakId("realm-a", ScimSyncMapping.ResourceType.USER, "kc-2").orElseThrow();
    assertEquals("scim-already-there", mapping.getScimId());
  }

  @Test
  void selfHealRecordsFailureWhenCreateFails() {
    ScimTargetClient client = mock(ScimTargetClient.class);
    ServerResponse<ListResponse<User>> noneFound = emptyListResponse();
    ServerResponse<User> createFailure = errorResponse(500);
    when(client.findByExternalId("kc-3")).thenReturn(noneFound);
    when(client.createUser(any())).thenReturn(createFailure);

    entityManager.getTransaction().begin();
    ReconciliationJob.UserOutcome outcome =
        ReconciliationJob.reconcileUser(client, mappingDao, "realm-a", "kc-3", representation("djensen", true));
    entityManager.getTransaction().commit();

    assertEquals(ReconciliationJob.UserOutcome.FAILED, outcome);
    ScimSyncMapping mapping =
        mappingDao.findByKeycloakId("realm-a", ScimSyncMapping.ResourceType.USER, "kc-3").orElseThrow();
    assertEquals(ScimSyncMapping.SyncResult.FAILED, mapping.getLastSyncResult());
  }

  private ScimSyncMapping existingMapping(String realmId, String keycloakId, String scimId) {
    entityManager.getTransaction().begin();
    ScimSyncMapping mapping = mappingDao.findOrCreate(realmId, ScimSyncMapping.ResourceType.USER, keycloakId);
    mapping.setScimId(scimId);
    entityManager.getTransaction().commit();
    return mapping;
  }

  @Test
  void reconcilesAsInSyncWhenTargetAlreadyMatchesDesiredState() {
    existingMapping("realm-b", "kc-4", "scim-4");
    ScimTargetClient client = mock(ScimTargetClient.class);
    User current = new User();
    current.setUserName("ejensen");
    current.setActive(true);
    ServerResponse<User> getResponse = successWithScimId("scim-4");
    when(getResponse.getResource()).thenReturn(current);
    when(client.getUser("scim-4")).thenReturn(getResponse);

    entityManager.getTransaction().begin();
    ReconciliationJob.UserOutcome outcome =
        ReconciliationJob.reconcileUser(client, mappingDao, "realm-b", "kc-4", representation("ejensen", true));
    entityManager.getTransaction().commit();

    assertEquals(ReconciliationJob.UserOutcome.IN_SYNC, outcome);
    verify(client, never()).replaceIfVersionUnchanged(any(), any(), any());
  }

  @Test
  void reconcilesByMergingAndWritingWhenTargetDiffersFromDesiredState() {
    existingMapping("realm-b", "kc-5", "scim-5");
    ScimTargetClient client = mock(ScimTargetClient.class);
    User current = new User();
    current.setUserName("fjensen");
    current.setActive(false);
    ServerResponse<User> getResponse = successWithScimId("scim-5");
    when(getResponse.getResource()).thenReturn(current);
    when(client.getUser("scim-5")).thenReturn(getResponse);
    when(client.replaceIfVersionUnchanged(any(), any(), any()))
        .thenReturn(new ReconciliationWriteResult(ReconciliationWriteResult.Outcome.APPLIED, null));

    entityManager.getTransaction().begin();
    ReconciliationJob.UserOutcome outcome =
        ReconciliationJob.reconcileUser(client, mappingDao, "realm-b", "kc-5", representation("fjensen", true));
    entityManager.getTransaction().commit();

    assertEquals(ReconciliationJob.UserOutcome.UPDATED, outcome);
    verify(client).replaceIfVersionUnchanged("scim-5", current, current.getMeta().orElse(null));
    assertTrue(current.isActive().orElseThrow(), "the merged (mutated) current object is what gets sent");
  }

  @Test
  void reconcileMarksSkippedNotFailedOnVersionConflict() {
    existingMapping("realm-b", "kc-6", "scim-6");
    ScimTargetClient client = mock(ScimTargetClient.class);
    User current = new User();
    current.setUserName("gjensen");
    current.setActive(false);
    ServerResponse<User> getResponse = successWithScimId("scim-6");
    when(getResponse.getResource()).thenReturn(current);
    when(client.getUser("scim-6")).thenReturn(getResponse);
    when(client.replaceIfVersionUnchanged(any(), any(), any()))
        .thenReturn(
            new ReconciliationWriteResult(ReconciliationWriteResult.Outcome.VERSION_CONFLICT, null));

    entityManager.getTransaction().begin();
    ReconciliationJob.UserOutcome outcome =
        ReconciliationJob.reconcileUser(client, mappingDao, "realm-b", "kc-6", representation("gjensen", true));
    entityManager.getTransaction().commit();

    assertEquals(ReconciliationJob.UserOutcome.CONFLICT, outcome);
    ScimSyncMapping mapping =
        mappingDao.findByKeycloakId("realm-b", ScimSyncMapping.ResourceType.USER, "kc-6").orElseThrow();
    assertEquals(ScimSyncMapping.SyncResult.SKIPPED, mapping.getLastSyncResult());
  }

  @Test
  void reconcileSelfHealsByRecreatingWhenTheTargetResourceIsGone() {
    existingMapping("realm-b", "kc-7", "scim-stale");
    ScimTargetClient client = mock(ScimTargetClient.class);
    ServerResponse<User> notFound = errorResponse(404);
    ServerResponse<ListResponse<User>> noneFound = emptyListResponse();
    ServerResponse<User> recreated = successWithScimId("scim-recreated");
    when(client.getUser("scim-stale")).thenReturn(notFound);
    when(client.findByExternalId("kc-7")).thenReturn(noneFound);
    when(client.createUser(any())).thenReturn(recreated);

    entityManager.getTransaction().begin();
    ReconciliationJob.UserOutcome outcome =
        ReconciliationJob.reconcileUser(client, mappingDao, "realm-b", "kc-7", representation("hjensen", true));
    entityManager.getTransaction().commit();

    assertEquals(ReconciliationJob.UserOutcome.CREATED, outcome);
    ScimSyncMapping mapping =
        mappingDao.findByKeycloakId("realm-b", ScimSyncMapping.ResourceType.USER, "kc-7").orElseThrow();
    assertEquals("scim-recreated", mapping.getScimId());
  }

  @Test
  void reconcileRecordsFailureOnAnUnrelatedGetError() {
    existingMapping("realm-b", "kc-8", "scim-8");
    ScimTargetClient client = mock(ScimTargetClient.class);
    ServerResponse<User> serverError = errorResponse(503);
    when(client.getUser("scim-8")).thenReturn(serverError);

    entityManager.getTransaction().begin();
    ReconciliationJob.UserOutcome outcome =
        ReconciliationJob.reconcileUser(client, mappingDao, "realm-b", "kc-8", representation("ijensen", true));
    entityManager.getTransaction().commit();

    assertEquals(ReconciliationJob.UserOutcome.FAILED, outcome);
    verify(client, never()).createUser(any());
  }
}
