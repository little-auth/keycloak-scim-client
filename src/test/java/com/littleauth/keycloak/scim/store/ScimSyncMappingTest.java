package com.littleauth.keycloak.scim.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Pre-mortem mitigation: audit/error surfacing must redact auth credentials (whichever
 * HTTP auth scheme is configured), not just avoid logging them elsewhere -- {@link
 * ScimSyncMapping#setLastSyncError} is the one place a raw HTTP error body from the SCIM
 * target lands in storage, so redaction belongs here, not left to every caller to
 * remember.
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
  void redactsBasicAuthCredentialFromStoredErrorMessage() {
    // AuthMode.BASIC sends "Authorization: Basic <base64(user:pass)>" -- a target that
    // echoes the received header back in a verbose/debug error body would otherwise leak
    // a trivially-reversible credential into storage, exactly the class of leak this
    // redaction control exists to prevent (previously scoped to "Bearer" only).
    var mapping = new ScimSyncMapping();
    mapping.setLastSyncError(
        "PATCH failed: Authorization: Basic YWxpY2U6czNjcmV0 not accepted");

    String stored = mapping.getLastSyncError();
    assertFalse(stored.contains("YWxpY2U6czNjcmV0"), "raw basic auth credential must be redacted");
    assertTrue(stored.contains("Basic [redacted]"));
  }

  @Test
  void redactsVeryShortBasicCredentialWithoutLengthFloor() {
    // The redaction pattern must never rely on a minimum-length threshold to decide
    // what counts as a credential -- that would under-redact a short-but-real one, which
    // is a strictly worse failure than the over-redaction this class already accepts.
    var mapping = new ScimSyncMapping();
    mapping.setLastSyncError("Authorization: Basic YTpi rejected");

    String stored = mapping.getLastSyncError();
    assertFalse(stored.contains("YTpi"), "even a very short credential must be redacted");
  }

  @Test
  void doesNotDestroyDiagnosticInfoFollowingChallengeHeaderValue() {
    // "Basic"/"Bearer" also name the (non-secret) WWW-Authenticate challenge scheme, not
    // just a sent credential -- a target's 401 error body commonly echoes one back, often
    // as unspaced JSON. The prior unbounded match (\S+) would consume everything to the
    // end of such a body once nothing else in it contained whitespace, destroying the
    // status/traceId an operator actually needs to diagnose the failure. Bounding the
    // match to stop at JSON/text delimiters keeps that diagnostic content intact.
    var mapping = new ScimSyncMapping();
    mapping.setLastSyncError(
        "{\"status\":\"401\",\"challenge\":\"Basic realm=\\\"scim-prod\\\"\","
            + "\"traceId\":\"abc123\"}");

    String stored = mapping.getLastSyncError();
    assertTrue(stored.contains("\"traceId\":\"abc123\"}"), "diagnostic info after the "
        + "challenge value must survive: " + stored);
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
