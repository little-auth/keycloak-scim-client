package com.littleauth.keycloak.scim.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.node.BooleanNode;
import com.littleauth.keycloak.scim.config.ScimTargetConfig.DeletePolicy;
import de.captaingoldfish.scim.sdk.client.ScimRequestBuilder;
import de.captaingoldfish.scim.sdk.client.builder.DeleteBuilder;
import de.captaingoldfish.scim.sdk.client.builder.GetBuilder;
import de.captaingoldfish.scim.sdk.client.builder.ListBuilder;
import de.captaingoldfish.scim.sdk.client.builder.PatchBuilder;
import de.captaingoldfish.scim.sdk.client.builder.UpdateBuilder;
import de.captaingoldfish.scim.sdk.client.response.ServerResponse;
import de.captaingoldfish.scim.sdk.common.etag.ETag;
import de.captaingoldfish.scim.sdk.common.resources.User;
import de.captaingoldfish.scim.sdk.common.resources.complex.Meta;
import de.captaingoldfish.scim.sdk.common.response.ListResponse;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * AC-2/AC-3: the active-flag PATCH-with-PUT-fallback path, exercised against a mocked SDK
 * so the pre-mortem mitigations (fallback on client error, never mask a server error) are
 * verifiable without a live target. Full request-shape correctness is proven separately by
 * the keycloak-it conformance harness.
 *
 * <p>The fetch-then-merge tests exist specifically because the previous placeholder-based
 * PUT-fallback design risked wiping a target user's other fields during deprovisioning
 * (SCIM PUT is a full replace) -- a bug the council-code-review pass caught precisely
 * because no earlier test exercised this interaction concretely.
 */
@SuppressWarnings("unchecked")
class ScimTargetClientTest {

  private static ServerResponse<User> successResponse() {
    ServerResponse<User> response = mock(ServerResponse.class);
    when(response.isSuccess()).thenReturn(true);
    return response;
  }

  private static ServerResponse<User> errorResponse(int status) {
    ServerResponse<User> response = mock(ServerResponse.class);
    when(response.isSuccess()).thenReturn(false);
    when(response.getHttpStatus()).thenReturn(status);
    return response;
  }

  private static PatchBuilder<User> mockPatchBuilder(
      ScimRequestBuilder requestBuilder, String scimId) {
    PatchBuilder<User> patchBuilder = mock(PatchBuilder.class);
    PatchBuilder.PatchOperationBuilder<User> opBuilder =
        mock(PatchBuilder.PatchOperationBuilder.class);
    when(requestBuilder.patch(User.class, "/Users", scimId)).thenReturn(patchBuilder);
    when(patchBuilder.addOperation()).thenReturn(opBuilder);
    when(opBuilder.path("active")).thenReturn(opBuilder);
    when(opBuilder.op(any())).thenReturn(opBuilder);
    when(opBuilder.valueNode(any(BooleanNode.class))).thenReturn(opBuilder);
    when(opBuilder.build()).thenReturn(patchBuilder);
    return patchBuilder;
  }

  private static UpdateBuilder<User> mockUpdateBuilder(
      ScimRequestBuilder requestBuilder, String scimId) {
    UpdateBuilder<User> updateBuilder = mock(UpdateBuilder.class);
    when(requestBuilder.update(User.class, "/Users", scimId)).thenReturn(updateBuilder);
    when(updateBuilder.setResource(anyString())).thenReturn(updateBuilder);
    return updateBuilder;
  }

  private static GetBuilder<User> mockGetBuilder(
      ScimRequestBuilder requestBuilder, String scimId) {
    GetBuilder<User> getBuilder = mock(GetBuilder.class);
    when(requestBuilder.get(User.class, "/Users", scimId)).thenReturn(getBuilder);
    return getBuilder;
  }

  private static String anyString() {
    return org.mockito.ArgumentMatchers.anyString();
  }

  @Test
  void setActiveSendsPatchWithNativeBooleanNodeWhenSupported() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    PatchBuilder<User> patchBuilder = mockPatchBuilder(requestBuilder, "scim-123");
    ServerResponse<User> success = successResponse();
    when(patchBuilder.sendRequest(any())).thenReturn(success);

    var client = new ScimTargetClient(requestBuilder, new PatchCapability(true), Map.of());
    ServerResponse<User> result = client.setActive("scim-123", false);

    assertEquals(success, result);
    verify(requestBuilder, never()).update(any(), any(), any());
    verify(requestBuilder, never()).get(any(), any(), any());
  }

  @Test
  void setActiveFallsBackToFetchAndPutWhenDiscoveryNeverAdvertisedPatchSupport() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);

    User currentResource = new User();
    currentResource.setUserName("bjensen");
    ServerResponse<User> getResponse = successResponse();
    when(getResponse.getResource()).thenReturn(currentResource);
    GetBuilder<User> getBuilder = mockGetBuilder(requestBuilder, "scim-123");
    when(getBuilder.sendRequest(any())).thenReturn(getResponse);

    UpdateBuilder<User> updateBuilder = mockUpdateBuilder(requestBuilder, "scim-123");
    ServerResponse<User> putSuccess = successResponse();
    when(updateBuilder.sendRequest(any())).thenReturn(putSuccess);

    var client = new ScimTargetClient(requestBuilder, new PatchCapability(false), Map.of());
    ServerResponse<User> result = client.setActive("scim-123", false);

    assertEquals(putSuccess, result);
    verify(requestBuilder, never()).patch(any(), any(), any());
    // The fetched resource -- with userName still set -- is what gets PUT, not a
    // minimal/placeholder representation that would wipe it.
    assertEquals("bjensen", currentResource.getUserName().orElseThrow());
    assertFalse(currentResource.isActive().orElseThrow());
  }

  @Test
  void setActiveFallsBackToFetchAndPutAndRecordsFailureWhenPatchReturnsClientError() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    PatchBuilder<User> patchBuilder = mockPatchBuilder(requestBuilder, "scim-123");
    ServerResponse<User> patchError = errorResponse(400);
    when(patchBuilder.sendRequest(any())).thenReturn(patchError);

    User currentResource = new User();
    ServerResponse<User> getResponse = successResponse();
    when(getResponse.getResource()).thenReturn(currentResource);
    GetBuilder<User> getBuilder = mockGetBuilder(requestBuilder, "scim-123");
    when(getBuilder.sendRequest(any())).thenReturn(getResponse);

    UpdateBuilder<User> updateBuilder = mockUpdateBuilder(requestBuilder, "scim-123");
    ServerResponse<User> putSuccess = successResponse();
    when(updateBuilder.sendRequest(any())).thenReturn(putSuccess);

    var capability = new PatchCapability(true);
    var client = new ScimTargetClient(requestBuilder, capability, Map.of());
    ServerResponse<User> result = client.setActive("scim-123", false);

    assertEquals(putSuccess, result);
    assertFalse(capability.shouldAttemptPatch(), "a client-error PATCH must record failure");
  }

  @Test
  void setActiveDoesNotFallBackOnServerErrorAndSurfacesItInstead() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    PatchBuilder<User> patchBuilder = mockPatchBuilder(requestBuilder, "scim-123");
    ServerResponse<User> serverError = errorResponse(503);
    when(patchBuilder.sendRequest(any())).thenReturn(serverError);

    var capability = new PatchCapability(true);
    var client = new ScimTargetClient(requestBuilder, capability, Map.of());
    ServerResponse<User> result = client.setActive("scim-123", false);

    assertEquals(serverError, result);
    verify(requestBuilder, never()).update(any(), any(), any());
    verify(requestBuilder, never()).get(any(), any(), any());
    assertTrue(capability.shouldAttemptPatch(), "a server error must not disable PATCH");
  }

  @Test
  void setActiveSurfacesGetFailureInsteadOfPuttingAnIncompleteRepresentation() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    ServerResponse<User> getFailure = errorResponse(404);
    GetBuilder<User> getBuilder = mockGetBuilder(requestBuilder, "scim-123");
    when(getBuilder.sendRequest(any())).thenReturn(getFailure);

    var client = new ScimTargetClient(requestBuilder, new PatchCapability(false), Map.of());
    ServerResponse<User> result = client.setActive("scim-123", false);

    assertEquals(getFailure, result);
    // Must never PUT without first confirming what the current resource actually looks
    // like -- an incomplete PUT here would silently wipe fields on the target.
    verify(requestBuilder, never()).update(any(), any(), any());
  }

  @Test
  void deprovisionWithHardDeletePolicyCallsDelete() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    DeleteBuilder<User> deleteBuilder = mock(DeleteBuilder.class);
    when(requestBuilder.delete(User.class, "/Users", "scim-123")).thenReturn(deleteBuilder);
    ServerResponse<User> success = successResponse();
    when(deleteBuilder.sendRequest(any())).thenReturn(success);

    var client = new ScimTargetClient(requestBuilder, new PatchCapability(true), Map.of());
    ServerResponse<User> result = client.deprovision("scim-123", DeletePolicy.HARD_DELETE);

    assertEquals(success, result);
    verify(requestBuilder, times(1)).delete(User.class, "/Users", "scim-123");
  }

  @Test
  void deprovisionWithSoftDeletePolicyPatchesActiveFalseInsteadOfDeleting() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    PatchBuilder<User> patchBuilder = mockPatchBuilder(requestBuilder, "scim-123");
    ServerResponse<User> success = successResponse();
    when(patchBuilder.sendRequest(any())).thenReturn(success);

    var client = new ScimTargetClient(requestBuilder, new PatchCapability(true), Map.of());
    ServerResponse<User> result = client.deprovision("scim-123", DeletePolicy.SOFT_DELETE);

    assertEquals(success, result);
    verify(requestBuilder, never()).delete(any(), any(), any());
  }

  @Test
  void getUserSendsPlainGetByScimId() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    User resource = new User();
    ServerResponse<User> success = successResponse();
    when(success.getResource()).thenReturn(resource);
    GetBuilder<User> getBuilder = mockGetBuilder(requestBuilder, "scim-123");
    when(getBuilder.sendRequest(any())).thenReturn(success);

    var client = new ScimTargetClient(requestBuilder, new PatchCapability(true), Map.of());
    ServerResponse<User> result = client.getUser("scim-123");

    assertEquals(success, result);
  }

  @SuppressWarnings("unchecked")
  private static ListBuilder<User> mockListBuilder(ScimRequestBuilder requestBuilder) {
    ListBuilder<User> listBuilder = mock(ListBuilder.class);
    when(requestBuilder.list(User.class, "/Users")).thenReturn(listBuilder);
    when(listBuilder.filter(anyString())).thenReturn(listBuilder);
    return listBuilder;
  }

  @SuppressWarnings("unchecked")
  private static ListBuilder.GetRequestBuilder<User> mockListGetRequestBuilder(
      ListBuilder<User> listBuilder) {
    ListBuilder.GetRequestBuilder<User> getRequestBuilder = mock(ListBuilder.GetRequestBuilder.class);
    when(listBuilder.get()).thenReturn(getRequestBuilder);
    return getRequestBuilder;
  }

  @Test
  void findByExternalIdFiltersOnExternalIdEquality() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    ListBuilder<User> listBuilder = mockListBuilder(requestBuilder);
    ListBuilder.GetRequestBuilder<User> getRequestBuilder = mockListGetRequestBuilder(listBuilder);

    ServerResponse<ListResponse<User>> success = mock(ServerResponse.class);
    when(getRequestBuilder.sendRequest(any())).thenReturn(success);

    var client = new ScimTargetClient(requestBuilder, new PatchCapability(true), Map.of());
    ServerResponse<ListResponse<User>> result = client.findByExternalId("kc-user-1");

    assertEquals(success, result);
    verify(listBuilder).filter("externalId eq \"kc-user-1\"");
  }

  @Test
  void findByExternalIdEscapesQuotesAndBackslashesInTheFilterValue() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    ListBuilder<User> listBuilder = mockListBuilder(requestBuilder);
    ListBuilder.GetRequestBuilder<User> getRequestBuilder = mockListGetRequestBuilder(listBuilder);
    ServerResponse<ListResponse<User>> success = mock(ServerResponse.class);
    when(getRequestBuilder.sendRequest(any())).thenReturn(success);

    var client = new ScimTargetClient(requestBuilder, new PatchCapability(true), Map.of());
    client.findByExternalId("weird\"\\id");

    verify(listBuilder).filter("externalId eq \"weird\\\"\\\\id\"");
  }

  @Test
  void replaceIfVersionUnchangedAppliesWithIfMatchWhenAnExpectedVersionIsPresent() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    UpdateBuilder<User> updateBuilder = mockUpdateBuilder(requestBuilder, "scim-123");
    ServerResponse<User> putSuccess = successResponse();
    when(updateBuilder.sendRequest(any())).thenReturn(putSuccess);

    ETag version = ETag.parseETag("\"v1\"");
    Meta expectedMeta = Meta.builder().version(version).build();

    var client = new ScimTargetClient(requestBuilder, new PatchCapability(true), Map.of());
    User desired = new User();
    ReconciliationWriteResult result =
        client.replaceIfVersionUnchanged("scim-123", desired, expectedMeta);

    assertEquals(ReconciliationWriteResult.Outcome.APPLIED, result.outcome());
    assertEquals(putSuccess, result.response());
    verify(updateBuilder).setETagForIfMatch(version);
  }

  @Test
  void replaceIfVersionUnchangedDoesNotSetIfMatchWhenNoVersionIsAdvertised() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    UpdateBuilder<User> updateBuilder = mockUpdateBuilder(requestBuilder, "scim-123");
    ServerResponse<User> putSuccess = successResponse();
    when(updateBuilder.sendRequest(any())).thenReturn(putSuccess);

    var client = new ScimTargetClient(requestBuilder, new PatchCapability(true), Map.of());
    ReconciliationWriteResult result =
        client.replaceIfVersionUnchanged("scim-123", new User(), null);

    assertEquals(ReconciliationWriteResult.Outcome.APPLIED, result.outcome());
    verify(updateBuilder, never()).setETagForIfMatch(any(ETag.class));
  }

  @Test
  void replaceIfVersionUnchangedRechecksLastModifiedWhenNoEtagAdvertisedAndAppliesWhenUnchanged() {
    // The only check possible against a target with no ETag support (issue #6: this is the
    // real-world case for scimitar, the plugin's own test target, per issue #5) -- a fresh
    // GET immediately before the write, compared against what was read earlier.
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    Instant lastModified = Instant.parse("2026-08-15T10:00:00Z");
    Meta expectedMeta = new Meta();
    expectedMeta.setLastModified(lastModified);

    User rechecked = new User();
    Meta recheckedMeta = new Meta();
    recheckedMeta.setLastModified(lastModified);
    rechecked.setMeta(recheckedMeta);
    ServerResponse<User> recheckResponse = successResponse();
    when(recheckResponse.getResource()).thenReturn(rechecked);
    GetBuilder<User> getBuilder = mockGetBuilder(requestBuilder, "scim-123");
    when(getBuilder.sendRequest(any())).thenReturn(recheckResponse);

    UpdateBuilder<User> updateBuilder = mockUpdateBuilder(requestBuilder, "scim-123");
    ServerResponse<User> putSuccess = successResponse();
    when(updateBuilder.sendRequest(any())).thenReturn(putSuccess);

    var client = new ScimTargetClient(requestBuilder, new PatchCapability(true), Map.of());
    ReconciliationWriteResult result =
        client.replaceIfVersionUnchanged("scim-123", new User(), expectedMeta);

    assertEquals(ReconciliationWriteResult.Outcome.APPLIED, result.outcome());
    verify(updateBuilder, never()).setETagForIfMatch(any(ETag.class));
  }

  @Test
  void replaceIfVersionUnchangedReportsConflictWhenLastModifiedChangedSinceRead() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    Meta expectedMeta = new Meta();
    expectedMeta.setLastModified(Instant.parse("2026-08-15T10:00:00Z"));

    User rechecked = new User();
    Meta recheckedMeta = new Meta();
    recheckedMeta.setLastModified(Instant.parse("2026-08-15T10:05:00Z"));
    rechecked.setMeta(recheckedMeta);
    ServerResponse<User> recheckResponse = successResponse();
    when(recheckResponse.getResource()).thenReturn(rechecked);
    GetBuilder<User> getBuilder = mockGetBuilder(requestBuilder, "scim-123");
    when(getBuilder.sendRequest(any())).thenReturn(recheckResponse);

    var client = new ScimTargetClient(requestBuilder, new PatchCapability(true), Map.of());
    ReconciliationWriteResult result =
        client.replaceIfVersionUnchanged("scim-123", new User(), expectedMeta);

    assertEquals(ReconciliationWriteResult.Outcome.VERSION_CONFLICT, result.outcome());
    // Must never PUT once a concurrent modification is detected -- that would silently
    // overwrite whatever the concurrent writer just did.
    verify(requestBuilder, never()).update(any(), any(), any());
  }

  @Test
  void replaceIfVersionUnchangedSurfacesRecheckFailureAsFailedWithoutWriting() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    Meta expectedMeta = new Meta();
    expectedMeta.setLastModified(Instant.parse("2026-08-15T10:00:00Z"));

    ServerResponse<User> recheckFailure = errorResponse(500);
    GetBuilder<User> getBuilder = mockGetBuilder(requestBuilder, "scim-123");
    when(getBuilder.sendRequest(any())).thenReturn(recheckFailure);

    var client = new ScimTargetClient(requestBuilder, new PatchCapability(true), Map.of());
    ReconciliationWriteResult result =
        client.replaceIfVersionUnchanged("scim-123", new User(), expectedMeta);

    assertEquals(ReconciliationWriteResult.Outcome.FAILED, result.outcome());
    verify(requestBuilder, never()).update(any(), any(), any());
  }

  @Test
  void replaceIfVersionUnchangedReportsVersionConflictOn412() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    UpdateBuilder<User> updateBuilder = mockUpdateBuilder(requestBuilder, "scim-123");
    ServerResponse<User> preconditionFailed = errorResponse(412);
    when(updateBuilder.sendRequest(any())).thenReturn(preconditionFailed);

    var client = new ScimTargetClient(requestBuilder, new PatchCapability(true), Map.of());
    ReconciliationWriteResult result =
        client.replaceIfVersionUnchanged("scim-123", new User(), null);

    assertEquals(ReconciliationWriteResult.Outcome.VERSION_CONFLICT, result.outcome());
  }

  @Test
  void replaceIfVersionUnchangedReportsFailedOnAnUnrelatedError() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    UpdateBuilder<User> updateBuilder = mockUpdateBuilder(requestBuilder, "scim-123");
    ServerResponse<User> serverError = errorResponse(503);
    when(updateBuilder.sendRequest(any())).thenReturn(serverError);

    var client = new ScimTargetClient(requestBuilder, new PatchCapability(true), Map.of());
    ReconciliationWriteResult result =
        client.replaceIfVersionUnchanged("scim-123", new User(), null);

    assertEquals(ReconciliationWriteResult.Outcome.FAILED, result.outcome());
  }
}
