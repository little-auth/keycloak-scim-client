package com.littleauth.keycloak.scim.store;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.TypedQuery;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository over {@link ScimSyncMapping}. {@link #findOrCreate} is what makes a Keycloak
 * CREATE event idempotent across retries: a second attempt for the same entity finds the
 * row {@link #findOrCreate}'s first call already inserted, rather than the caller building
 * a second SCIM POST from a fresh mapping (pre-mortem: duplicate SCIM resources from a
 * mapping write that wasn't atomic with the SCIM request).
 */
public class ScimSyncMappingDao {

  private final EntityManager entityManager;

  /** Wraps the given entity manager; reads/writes go through it directly, no caching. */
  public ScimSyncMappingDao(EntityManager entityManager) {
    this.entityManager = entityManager;
  }

  /** Empty if no mapping exists yet for this Keycloak entity. */
  public Optional<ScimSyncMapping> findByKeycloakId(
      String realmId, ScimSyncMapping.ResourceType resourceType, String keycloakId) {
    TypedQuery<ScimSyncMapping> query =
        entityManager.createQuery(
            "select m from ScimSyncMapping m where m.realmId = :realmId "
                + "and m.resourceType = :resourceType and m.keycloakId = :keycloakId",
            ScimSyncMapping.class);
    query.setParameter("realmId", realmId);
    query.setParameter("resourceType", resourceType);
    query.setParameter("keycloakId", keycloakId);
    try {
      return Optional.of(query.getSingleResult());
    } catch (NoResultException e) {
      return Optional.empty();
    }
  }

  /** Call within an active transaction; the caller owns commit/rollback. */
  public ScimSyncMapping findOrCreate(
      String realmId, ScimSyncMapping.ResourceType resourceType, String keycloakId) {
    return findByKeycloakId(realmId, resourceType, keycloakId)
        .orElseGet(
            () -> {
              var mapping = new ScimSyncMapping();
              mapping.setId(UUID.randomUUID().toString());
              mapping.setRealmId(realmId);
              mapping.setResourceType(resourceType);
              mapping.setKeycloakId(keycloakId);
              entityManager.persist(mapping);
              return mapping;
            });
  }
}
