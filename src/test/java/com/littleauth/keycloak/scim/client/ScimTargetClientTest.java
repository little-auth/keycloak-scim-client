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
import de.captaingoldfish.scim.sdk.client.builder.PatchBuilder;
import de.captaingoldfish.scim.sdk.client.builder.UpdateBuilder;
import de.captaingoldfish.scim.sdk.client.response.ServerResponse;
import de.captaingoldfish.scim.sdk.common.resources.User;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * AC-2/AC-3: the active-flag PATCH-with-PUT-fallback path, exercised against a mocked SDK
 * so the pre-mortem mitigations (fallback on client error, never mask a server error) are
 * verifiable without a live target. Full request-shape correctness is proven separately by
 * the keycloak-it conformance harness.
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

  private static String anyString() {
    return org.mockito.ArgumentMatchers.anyString();
  }

  @Test
  void setActiveSendsPatchWithNativeBooleanNodeWhenSupported() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    PatchBuilder<User> patchBuilder = mockPatchBuilder(requestBuilder, "scim-123");
    ServerResponse<User> success = successResponse();
    when(patchBuilder.sendRequest(any())).thenReturn(success);

    var client =
        new ScimTargetClient(requestBuilder, new PatchCapability(true), Map.of());
    ServerResponse<User> result = client.setActive("scim-123", false, new User());

    assertEquals(success, result);
    verify(requestBuilder, never()).update(any(), any(), any());
  }

  @Test
  void setActiveFallsBackToPutWhenDiscoveryNeverAdvertisedPatchSupport() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    UpdateBuilder<User> updateBuilder = mockUpdateBuilder(requestBuilder, "scim-123");
    ServerResponse<User> success = successResponse();
    when(updateBuilder.sendRequest(any())).thenReturn(success);

    var client =
        new ScimTargetClient(requestBuilder, new PatchCapability(false), Map.of());
    ServerResponse<User> result = client.setActive("scim-123", false, new User());

    assertEquals(success, result);
    verify(requestBuilder, never()).patch(any(), any(), any());
  }

  @Test
  void setActiveFallsBackToPutAndRecordsFailureWhenPatchReturnsClientError() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    PatchBuilder<User> patchBuilder = mockPatchBuilder(requestBuilder, "scim-123");
    ServerResponse<User> patchError = errorResponse(400);
    when(patchBuilder.sendRequest(any())).thenReturn(patchError);
    UpdateBuilder<User> updateBuilder = mockUpdateBuilder(requestBuilder, "scim-123");
    ServerResponse<User> putSuccess = successResponse();
    when(updateBuilder.sendRequest(any())).thenReturn(putSuccess);

    var capability = new PatchCapability(true);
    var client =
        new ScimTargetClient(requestBuilder, capability, Map.of());
    ServerResponse<User> result = client.setActive("scim-123", false, new User());

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
    var client =
        new ScimTargetClient(requestBuilder, capability, Map.of());
    ServerResponse<User> result = client.setActive("scim-123", false, new User());

    assertEquals(serverError, result);
    verify(requestBuilder, never()).update(any(), any(), any());
    assertTrue(capability.shouldAttemptPatch(), "a server error must not disable PATCH");
  }

  @Test
  void deprovisionWithHardDeletePolicyCallsDelete() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    DeleteBuilder<User> deleteBuilder = mock(DeleteBuilder.class);
    when(requestBuilder.delete(User.class, "/Users", "scim-123")).thenReturn(deleteBuilder);
    ServerResponse<User> success = successResponse();
    when(deleteBuilder.sendRequest(any())).thenReturn(success);

    var client =
        new ScimTargetClient(requestBuilder, new PatchCapability(true), Map.of());
    ServerResponse<User> result =
        client.deprovision("scim-123", DeletePolicy.HARD_DELETE, new User());

    assertEquals(success, result);
    verify(requestBuilder, times(1)).delete(User.class, "/Users", "scim-123");
  }

  @Test
  void deprovisionWithSoftDeletePolicyPatchesActiveFalseInsteadOfDeleting() {
    ScimRequestBuilder requestBuilder = mock(ScimRequestBuilder.class);
    PatchBuilder<User> patchBuilder = mockPatchBuilder(requestBuilder, "scim-123");
    ServerResponse<User> success = successResponse();
    when(patchBuilder.sendRequest(any())).thenReturn(success);

    var client =
        new ScimTargetClient(requestBuilder, new PatchCapability(true), Map.of());
    ServerResponse<User> result =
        client.deprovision("scim-123", DeletePolicy.SOFT_DELETE, new User());

    assertEquals(success, result);
    verify(requestBuilder, never()).delete(any(), any(), any());
  }
}
