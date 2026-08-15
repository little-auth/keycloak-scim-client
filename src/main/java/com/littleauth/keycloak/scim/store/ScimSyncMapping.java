package com.littleauth.keycloak.scim.store;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.util.regex.Pattern;

/**
 * The Keycloak-ID &harr; SCIM-ID mapping and per-entity sync status (S2 in the breadboard):
 * what makes create/update/delete idempotent across retries, and what an admin's sync
 * status view (Slice 4) reads from.
 *
 * <p>{@code (realmId, resourceType, keycloakId)} is unique -- a second create attempt for
 * the same Keycloak entity in the same realm finds the existing row instead of producing a
 * duplicate SCIM resource (pre-mortem: non-atomic create-then-record-mapping).
 */
@Entity
@Table(
    name = "SCIM_SYNC_MAPPING",
    uniqueConstraints =
        @UniqueConstraint(columnNames = {"REALM_ID", "RESOURCE_TYPE", "KEYCLOAK_ID"}))
public class ScimSyncMapping {

  private static final int MAX_ERROR_LENGTH = 1024;

  // Covers every AuthMode this plugin currently supports (Bearer and Basic). This is the
  // one place a raw HTTP error body from the SCIM target lands in storage, so a future
  // AuthMode's HTTP auth scheme name must be added here in the same change that adds the
  // mode -- an unredacted scheme leaks a trivially-reversible credential into the DB and
  // logs the moment a target echoes the Authorization header back in an error body.
  //
  // The token class is bounded to common JSON/text delimiters, not just whitespace:
  // "Bearer"/"Basic" also name the (non-secret) WWW-Authenticate challenge scheme, and a
  // target's 401 body commonly echoes one back as unspaced JSON -- an unbounded match
  // would consume everything to the end of such a body once nothing else in it contains
  // whitespace, destroying the status/traceId an operator needs to diagnose the failure.
  // Deliberately has no minimum length: a length floor would under-redact a short-but-real
  // credential, which is a strictly worse failure than the residual over-redaction of a
  // short non-secret challenge parameter.
  private static final Pattern CREDENTIAL_HEADER =
      Pattern.compile("(?i)(Bearer|Basic)\\s+[^\\s\",;}\\]]+");

  @Id
  @Column(name = "ID", length = 36)
  private String id;

  @Column(name = "REALM_ID", nullable = false, length = 36)
  private String realmId;

  @Enumerated(EnumType.STRING)
  @Column(name = "RESOURCE_TYPE", nullable = false, length = 16)
  private ResourceType resourceType;

  @Column(name = "KEYCLOAK_ID", nullable = false, length = 36)
  private String keycloakId;

  @Column(name = "SCIM_ID", length = 64)
  private String scimId;

  @Column(name = "LAST_SYNC_TIME")
  private Long lastSyncTime;

  @Enumerated(EnumType.STRING)
  @Column(name = "LAST_SYNC_RESULT", length = 16)
  private SyncResult lastSyncResult;

  @Column(name = "LAST_SYNC_ERROR", length = MAX_ERROR_LENGTH)
  private String lastSyncError;

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getRealmId() {
    return realmId;
  }

  public void setRealmId(String realmId) {
    this.realmId = realmId;
  }

  public ResourceType getResourceType() {
    return resourceType;
  }

  public void setResourceType(ResourceType resourceType) {
    this.resourceType = resourceType;
  }

  public String getKeycloakId() {
    return keycloakId;
  }

  public void setKeycloakId(String keycloakId) {
    this.keycloakId = keycloakId;
  }

  public String getScimId() {
    return scimId;
  }

  public void setScimId(String scimId) {
    this.scimId = scimId;
  }

  public Long getLastSyncTime() {
    return lastSyncTime;
  }

  public void setLastSyncTime(Long lastSyncTime) {
    this.lastSyncTime = lastSyncTime;
  }

  public SyncResult getLastSyncResult() {
    return lastSyncResult;
  }

  public void setLastSyncResult(SyncResult lastSyncResult) {
    this.lastSyncResult = lastSyncResult;
  }

  public String getLastSyncError() {
    return lastSyncError;
  }

  /**
   * Redacts any {@code Bearer <token>} or {@code Basic <credential>} substring and
   * truncates to the column length.
   */
  public void setLastSyncError(String rawMessage) {
    if (rawMessage == null) {
      this.lastSyncError = null;
      return;
    }
    String redacted = CREDENTIAL_HEADER.matcher(rawMessage).replaceAll("$1 [redacted]");
    this.lastSyncError =
        redacted.length() > MAX_ERROR_LENGTH ? redacted.substring(0, MAX_ERROR_LENGTH) : redacted;
  }

  /** What kind of Keycloak entity this mapping tracks. Only {@code USER} exists in Slice 1. */
  public enum ResourceType {
    USER
  }

  /** The outcome of the most recent sync attempt for this entity. */
  public enum SyncResult {
    SUCCESS,
    FAILED,
    SKIPPED
  }
}
