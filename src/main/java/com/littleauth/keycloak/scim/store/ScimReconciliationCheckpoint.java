package com.littleauth.keycloak.scim.store;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

/**
 * A realm's persisted pagination cursor for {@code ReconciliationJob} (N7 in the breadboard)
 * -- issue #6's binding requirement: an interrupted reconciliation run (OOM, restart) must
 * resume from the last completed page rather than restart the full scan on a large realm.
 *
 * <p>{@code (realmId, resourceType)} is unique -- a realm has exactly one in-flight scan per
 * resource type. {@code nextOffset} is the {@code firstResult} to resume at (0 when idle or
 * starting a fresh pass); it only ever advances by a completed page's actual size or resets
 * to 0 when a page returns fewer than the page size (the scan has reached the end of the
 * realm's users). {@code pagesProcessedSincePassStart} is a cheap safety-valve counter --
 * see {@code ReconciliationJob}'s pass-not-completing warning.
 */
@Entity
@Table(
    name = "SCIM_RECONCILIATION_CHECKPOINT",
    uniqueConstraints = @UniqueConstraint(columnNames = {"REALM_ID", "RESOURCE_TYPE"}))
public class ScimReconciliationCheckpoint {

  @Id
  @Column(name = "ID", length = 36)
  private String id;

  @Column(name = "REALM_ID", nullable = false, length = 36)
  private String realmId;

  @Enumerated(EnumType.STRING)
  @Column(name = "RESOURCE_TYPE", nullable = false, length = 16)
  private ScimSyncMapping.ResourceType resourceType;

  @Column(name = "NEXT_OFFSET", nullable = false)
  private int nextOffset;

  @Column(name = "PASS_STARTED_TIME")
  private Long passStartedTime;

  @Column(name = "LAST_COMPLETED_TIME")
  private Long lastCompletedTime;

  @Column(name = "PAGES_SINCE_PASS_START", nullable = false)
  private long pagesProcessedSincePassStart;

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

  public ScimSyncMapping.ResourceType getResourceType() {
    return resourceType;
  }

  public void setResourceType(ScimSyncMapping.ResourceType resourceType) {
    this.resourceType = resourceType;
  }

  public int getNextOffset() {
    return nextOffset;
  }

  public void setNextOffset(int nextOffset) {
    this.nextOffset = nextOffset;
  }

  public Long getPassStartedTime() {
    return passStartedTime;
  }

  public void setPassStartedTime(Long passStartedTime) {
    this.passStartedTime = passStartedTime;
  }

  public Long getLastCompletedTime() {
    return lastCompletedTime;
  }

  public void setLastCompletedTime(Long lastCompletedTime) {
    this.lastCompletedTime = lastCompletedTime;
  }

  public long getPagesProcessedSincePassStart() {
    return pagesProcessedSincePassStart;
  }

  public void setPagesProcessedSincePassStart(long pagesProcessedSincePassStart) {
    this.pagesProcessedSincePassStart = pagesProcessedSincePassStart;
  }
}
