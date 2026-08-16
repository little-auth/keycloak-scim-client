package com.littleauth.keycloak.scim.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/** AC-5: the SSRF guard is actually wired to config-save time, not just implemented. */
class ScimTargetStorageProviderFactoryTest {

  private final ScimTargetStorageProviderFactory factory = new ScimTargetStorageProviderFactory();
  private final KeycloakSession session = mock(KeycloakSession.class);
  private final RealmModel realm = mock(RealmModel.class);

  @Test
  void rejectsPrivateAddressTargetUrlAtSaveTime() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_TARGET_URL, "https://10.0.0.5/scim/v2");

    assertThrows(
        ComponentValidationException.class,
        () -> factory.validateConfiguration(session, realm, model));
  }

  @Test
  void acceptsPublicHttpsTargetUrl() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_TARGET_URL, "https://93.184.216.34/scim/v2");

    assertDoesNotThrow(() -> factory.validateConfiguration(session, realm, model));
  }

  @Test
  void allowsAnUnconfiguredComponentToBeSaved() {
    assertDoesNotThrow(
        () -> factory.validateConfiguration(session, realm, new ComponentModel()));
  }

  @Test
  void configPropertiesIncludeAllScimTargetConfigFields() {
    List<String> names = factory.getConfigProperties().stream().map(p -> p.getName()).toList();
    assertTrue(names.contains(ScimTargetConfig.KEY_TARGET_URL));
    assertTrue(names.contains(ScimTargetConfig.KEY_ALLOWLIST_HOSTS));
    assertTrue(names.contains(ScimTargetConfig.KEY_CREDENTIAL_VAULT_REF));
    assertTrue(names.contains(ScimTargetConfig.KEY_DELETE_POLICY));
    assertTrue(names.contains(ScimTargetConfig.KEY_SYNC_ENABLED));
    assertTrue(names.contains(ScimTargetConfig.KEY_AUTH_MODE));
    assertTrue(names.contains(ScimTargetConfig.KEY_USERNAME));
    assertTrue(names.contains(ScimTargetConfig.KEY_RECONCILIATION_ENABLED));
    assertTrue(names.contains(ScimTargetConfig.KEY_HARD_DELETE_CONFIRMATION));
  }

  @Test
  void rejectsBasicAuthModeWithoutUsernameAtSaveTime() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_TARGET_URL, "https://93.184.216.34/scim/v2");
    model.put(ScimTargetConfig.KEY_AUTH_MODE, "BASIC");

    assertThrows(
        ComponentValidationException.class,
        () -> factory.validateConfiguration(session, realm, model));
  }

  @Test
  void rejectsBasicAuthModeWithBlankUsernameAtSaveTime() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_TARGET_URL, "https://93.184.216.34/scim/v2");
    model.put(ScimTargetConfig.KEY_AUTH_MODE, "BASIC");
    model.put(ScimTargetConfig.KEY_USERNAME, "   ");

    assertThrows(
        ComponentValidationException.class,
        () -> factory.validateConfiguration(session, realm, model));
  }

  @Test
  void rejectsBasicAuthModeWhenUsernameContainsColon() {
    // RFC 7617 SS2: a colon in the userid makes the resulting Basic auth header
    // ambiguous to decode (see ScimEventListenerProvider.buildScimClientConfig's doc).
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_TARGET_URL, "https://93.184.216.34/scim/v2");
    model.put(ScimTargetConfig.KEY_AUTH_MODE, "BASIC");
    model.put(ScimTargetConfig.KEY_USERNAME, "alice:bob");

    assertThrows(
        ComponentValidationException.class,
        () -> factory.validateConfiguration(session, realm, model));
  }

  @Test
  void acceptsBasicAuthModeWithUsernameAtSaveTime() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_TARGET_URL, "https://93.184.216.34/scim/v2");
    model.put(ScimTargetConfig.KEY_AUTH_MODE, "BASIC");
    model.put(ScimTargetConfig.KEY_USERNAME, "svc-account");

    assertDoesNotThrow(() -> factory.validateConfiguration(session, realm, model));
  }

  @Test
  void acceptsDefaultBearerAuthModeWithoutUsername() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_TARGET_URL, "https://93.184.216.34/scim/v2");

    assertDoesNotThrow(() -> factory.validateConfiguration(session, realm, model));
  }

  /**
   * Pre-mortem mitigation (#7): HARD_DELETE must not be enableable via a bare toggle --
   * saving it requires a matching, realm-specific confirmation phrase, enforced here so no
   * save path (Admin Console UI or Admin REST API) can bypass it.
   */
  @Test
  void rejectsHardDeletePolicyWithoutConfirmationPhrase() {
    when(realm.getName()).thenReturn("acme");
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_DELETE_POLICY, "HARD_DELETE");

    assertThrows(
        ComponentValidationException.class,
        () -> factory.validateConfiguration(session, realm, model));
  }

  @Test
  void rejectsHardDeletePolicyWithWrongConfirmationPhrase() {
    when(realm.getName()).thenReturn("acme");
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_DELETE_POLICY, "HARD_DELETE");
    model.put(ScimTargetConfig.KEY_HARD_DELETE_CONFIRMATION, "ENABLE HARD DELETE");

    assertThrows(
        ComponentValidationException.class,
        () -> factory.validateConfiguration(session, realm, model));
  }

  @Test
  void acceptsHardDeletePolicyWithExactRealmSpecificConfirmationPhrase() {
    when(realm.getName()).thenReturn("acme");
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_DELETE_POLICY, "HARD_DELETE");
    model.put(ScimTargetConfig.KEY_HARD_DELETE_CONFIRMATION, "ENABLE HARD DELETE FOR ACME");

    assertDoesNotThrow(() -> factory.validateConfiguration(session, realm, model));
  }

  @Test
  void softDeletePolicyDoesNotRequireConfirmation() {
    // DeletePolicy defaults to SOFT_DELETE when unset -- confirmation must never be required.
    assertDoesNotThrow(
        () -> factory.validateConfiguration(session, realm, new ComponentModel()));
  }

  /**
   * The LIST_TYPE dropdown only constrains the Admin Console UI, not an Admin REST API
   * caller -- an invalid deletePolicy value must fail as a clean ComponentValidationException,
   * not an unwrapped IllegalArgumentException from DeletePolicy.valueOf() (which
   * validateConfiguration's contract doesn't declare and Keycloak won't render as an
   * actionable admin-facing message).
   */
  @Test
  void rejectsInvalidDeletePolicyValueAsComponentValidationExceptionNotIllegalArgument() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_DELETE_POLICY, "GARBAGE");

    assertThrows(
        ComponentValidationException.class,
        () -> factory.validateConfiguration(session, realm, model));
  }

  /**
   * Nothing ever cleared a stale, previously-valid confirmation phrase when the policy left
   * HARD_DELETE, so a later flip back to HARD_DELETE silently re-armed off the leftover
   * value -- exactly the bare-toggle bypass issue #7 exists to close, just one save later
   * instead of the first one.
   */
  @Test
  void reEnablingHardDeleteAfterSwitchingAwayRequiresFreshConfirmation() {
    when(realm.getName()).thenReturn("acme");
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_DELETE_POLICY, "HARD_DELETE");
    model.put(ScimTargetConfig.KEY_HARD_DELETE_CONFIRMATION, "ENABLE HARD DELETE FOR ACME");
    assertDoesNotThrow(() -> factory.validateConfiguration(session, realm, model));

    // A later, unrelated save switches back to SOFT_DELETE -- must always succeed.
    model.put(ScimTargetConfig.KEY_DELETE_POLICY, "SOFT_DELETE");
    assertDoesNotThrow(() -> factory.validateConfiguration(session, realm, model));

    // Someone flips back to HARD_DELETE without retyping the confirmation -- the stale
    // phrase from the earlier save must not silently re-arm it.
    model.put(ScimTargetConfig.KEY_DELETE_POLICY, "HARD_DELETE");
    assertThrows(
        ComponentValidationException.class,
        () -> factory.validateConfiguration(session, realm, model));
  }

  @Test
  void switchingAwayFromHardDeleteClearsTheStoredConfirmationValue() {
    when(realm.getName()).thenReturn("acme");
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_DELETE_POLICY, "SOFT_DELETE");
    model.put(ScimTargetConfig.KEY_HARD_DELETE_CONFIRMATION, "ENABLE HARD DELETE FOR ACME");

    factory.validateConfiguration(session, realm, model);

    assertNull(model.get(ScimTargetConfig.KEY_HARD_DELETE_CONFIRMATION));
  }

  /**
   * Keycloak's Admin REST API has no cardinality check on component config -- a caller can
   * submit deletePolicy as a two-element list. Reading only the first value would let this
   * save through as SOFT_DELETE (skipping the confirmation gate, and worse, clearing any
   * stored confirmation) while a later runtime read of the same persisted row -- via a
   * separately reconstructed ComponentModel, subject to unordered Set iteration -- could
   * see HARD_DELETE instead, hard-deleting SCIM users with the gate never having fired.
   */
  @Test
  void rejectsMultiValuedDeletePolicyEvenWhenTheFirstValueWouldOtherwiseBeSoftDelete() {
    when(realm.getName()).thenReturn("acme");
    ComponentModel model = new ComponentModel();
    model.getConfig()
        .put(ScimTargetConfig.KEY_DELETE_POLICY, List.of("SOFT_DELETE", "HARD_DELETE"));

    assertThrows(
        ComponentValidationException.class,
        () -> factory.validateConfiguration(session, realm, model));
  }
}
