package com.littleauth.keycloak.scim.reconcile;

/**
 * Summary of one {@link ReconciliationJob#runOnePage} call -- logged per page/pass to satisfy
 * context.md's Observability Goal ("reconciliation drift count per run"), and useful for a
 * future Slice 4 admin sync-status view to read.
 */
public record PageResult(
    String realmId,
    int startOffset,
    int pageSize,
    int created,
    int updated,
    int inSync,
    int conflicts,
    int failed,
    boolean passComplete) {}
