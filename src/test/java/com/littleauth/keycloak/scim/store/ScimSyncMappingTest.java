package com.littleauth.keycloak.scim.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Pre-mortem mitigation: audit/error surfacing must redact bearer tokens, not just avoid
 * logging them elsewhere -- {@link ScimSyncMapping#setLastSyncError} is the one place a raw
 * HTTP error body from the SCIM target lands in storage, so redaction belongs here, not
 * left to every caller to remember.
 */
class ScimSyncMappingTest {

  @Test
  void redactsBearerTokenFromStoredErrorMessage() {
    var mapping = new ScimSyncMapping();
    mapping.setLastSyncError("PATCH failed: Authorization: Bearer s3cr3t-token-value not accepted");

    String stored = mapping.getLastSyncError();
    assertFalse(stored.contains("s3cr3t-token-value"), "raw bearer token must be redacted");
    assertTrue(stored.contains("Bearer [redacted]"));
  }

  @Test
  void leavesErrorMessagesWithoutCredentialsUnchanged() {
    var mapping = new ScimSyncMapping();
    mapping.setLastSyncError("PATCH failed: 400 Bad Request");
    assertEquals("PATCH failed: 400 Bad Request", mapping.getLastSyncError());
  }

  @Test
  void truncatesOverlongErrorMessagesToFitTheColumn() {
    var mapping = new ScimSyncMapping();
    mapping.setLastSyncError("x".repeat(2000));
    assertTrue(mapping.getLastSyncError().length() <= 1024);
  }

  @Test
  void handlesNullErrorMessageAsNoError() {
    var mapping = new ScimSyncMapping();
    mapping.setLastSyncError(null);
    assertEquals(null, mapping.getLastSyncError());
  }
}
