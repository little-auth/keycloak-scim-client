package com.littleauth.keycloak.scim.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
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
    assertTrue(names.contains(ScimTargetConfig.KEY_HARD_DELETE_CONFIRMATION));
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
   * Council code-review confirmation-pass finding: the LIST_TYPE dropdown only constrains the
   * Admin Console UI, not an Admin REST API caller -- an invalid deletePolicy value must fail
   * as a clean ComponentValidationException, not an unwrapped IllegalArgumentException from
   * DeletePolicy.valueOf() (which validateConfiguration's contract doesn't declare and Keycloak
   * won't render as an actionable admin-facing message).
   */
  @Test
  void rejectsInvalidDeletePolicyValueAsComponentValidationExceptionNotIllegalArgument() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_DELETE_POLICY, "GARBAGE");

    assertThrows(
        ComponentValidationException.class,
        () -> factory.validateConfiguration(session, realm, model));
  }
}
