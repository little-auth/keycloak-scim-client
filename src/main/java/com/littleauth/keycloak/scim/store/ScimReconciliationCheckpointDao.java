package com.littleauth.keycloak.scim.store;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.TypedQuery;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository over {@link ScimReconciliationCheckpoint}. {@link #findOrCreate} gives
 * {@code ReconciliationJob} the single per-realm-per-resource-type cursor it advances page by
 * page and resets on pass completion -- issue #6's persisted-checkpoint requirement.
 */
public class ScimReconciliationCheckpointDao {

  private final EntityManager entityManager;

  /** Wraps the given entity manager; reads/writes go through it directly, no caching. */
  public ScimReconciliationCheckpointDao(EntityManager entityManager) {
    this.entityManager = entityManager;
  }

  /** Empty if no checkpoint exists yet for this realm/resource type. */
  public Optional<ScimReconciliationCheckpoint> find(
      String realmId, ScimSyncMapping.ResourceType resourceType) {
    TypedQuery<ScimReconciliationCheckpoint> query =
        entityManager.createQuery(
            "select c from ScimReconciliationCheckpoint c where c.realmId = :realmId "
                + "and c.resourceType = :resourceType",
            ScimReconciliationCheckpoint.class);
    query.setParameter("realmId", realmId);
    query.setParameter("resourceType", resourceType);
    try {
      return Optional.of(query.getSingleResult());
    } catch (NoResultException e) {
      return Optional.empty();
    }
  }

  /** Call within an active transaction; the caller owns commit/rollback. */
  public ScimReconciliationCheckpoint findOrCreate(
      String realmId, ScimSyncMapping.ResourceType resourceType) {
    return find(realmId, resourceType)
        .orElseGet(
            () -> {
              var checkpoint = new ScimReconciliationCheckpoint();
              checkpoint.setId(UUID.randomUUID().toString());
              checkpoint.setRealmId(realmId);
              checkpoint.setResourceType(resourceType);
              checkpoint.setNextOffset(0);
              entityManager.persist(checkpoint);
              return checkpoint;
            });
  }
}
