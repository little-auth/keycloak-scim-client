package com.littleauth.keycloak.scim.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

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
}
