package com.littleauth.keycloak.scim.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.vault.VaultStringSecret;
import org.keycloak.vault.VaultTranscriber;

/**
 * AC-4: the SCIM target's credential is never stored as plaintext in the component config
 * -- only a Keycloak Vault SPI reference (`${vault.ID}`) is, resolved at the point of use.
 */
class ScimTargetConfigTest {

  private static final String RAW_SECRET = "s3cr3t-bearer-token-value";
  private static final String VAULT_REF = "${vault.scim-bearer-token}";

  private KeycloakSession sessionResolving(String vaultRef, String resolvedValue) {
    VaultStringSecret secret = mock(VaultStringSecret.class);
    when(secret.get()).thenReturn(Optional.ofNullable(resolvedValue));
    VaultTranscriber transcriber = mock(VaultTranscriber.class);
    when(transcriber.getStringSecret(vaultRef)).thenReturn(secret);
    KeycloakSession session = mock(KeycloakSession.class);
    when(session.vault()).thenReturn(transcriber);
    return session;
  }

  @Test
  void resolveCredentialResolvesVaultReferenceAndNeverStoresRawSecretInComponentConfig() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_CREDENTIAL_VAULT_REF, VAULT_REF);
    var config = new ScimTargetConfig(model);

    String resolved = config.resolveCredential(sessionResolving(VAULT_REF, RAW_SECRET));

    assertEquals(RAW_SECRET, resolved);
    String storedConfig = model.getConfig().toString();
    assertFalse(storedConfig.contains(RAW_SECRET), "raw secret must never be in component config");
    assertTrue(storedConfig.contains("${vault."), "component config should hold a vault reference");
  }

  @Test
  void resolveCredentialThrowsWhenNoVaultReferenceIsConfigured() {
    var config = new ScimTargetConfig(new ComponentModel());
    KeycloakSession session = mock(KeycloakSession.class);
    assertThrows(IllegalStateException.class, () -> config.resolveCredential(session));
  }

  @Test
  void resolveCredentialThrowsWhenTheVaultCannotResolveTheReference() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_CREDENTIAL_VAULT_REF, VAULT_REF);
    var config = new ScimTargetConfig(model);

    assertThrows(
        IllegalStateException.class,
        () -> config.resolveCredential(sessionResolving(VAULT_REF, null)));
  }

  @Test
  void getTargetUrlReturnsTheConfiguredValue() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_TARGET_URL, "https://scim.example.com/scim/v2");
    var config = new ScimTargetConfig(model);
    assertEquals("https://scim.example.com/scim/v2", config.getTargetUrl());
  }

  @Test
  void getAllowlistHostsReturnsConfiguredMultivaluedList() {
    ComponentModel model = new ComponentModel();
    model.getConfig()
        .put(ScimTargetConfig.KEY_ALLOWLIST_HOSTS, List.of("a.internal", "b.internal"));
    var config = new ScimTargetConfig(model);
    assertEquals(List.of("a.internal", "b.internal"), config.getAllowlistHosts());
  }

  @Test
  void getAllowlistHostsReturnsEmptyListWhenUnset() {
    var config = new ScimTargetConfig(new ComponentModel());
    assertTrue(config.getAllowlistHosts().isEmpty());
  }

  @Test
  void deletePolicyDefaultsToSoftDelete() {
    var config = new ScimTargetConfig(new ComponentModel());
    assertEquals(ScimTargetConfig.DeletePolicy.SOFT_DELETE, config.getDeletePolicy());
  }

  @Test
  void deletePolicyHonorsExplicitHardDeleteConfiguration() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_DELETE_POLICY, "HARD_DELETE");
    var config = new ScimTargetConfig(model);
    assertEquals(ScimTargetConfig.DeletePolicy.HARD_DELETE, config.getDeletePolicy());
  }

  @Test
  void syncEnabledDefaultsToFalse() {
    var config = new ScimTargetConfig(new ComponentModel());
    assertFalse(config.isSyncEnabled());
  }

  @Test
  void syncEnabledHonorsExplicitConfiguration() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_SYNC_ENABLED, true);
    var config = new ScimTargetConfig(model);
    assertTrue(config.isSyncEnabled());
  }

  @Test
  void reconciliationEnabledDefaultsToTrue() {
    // Independent kill switch (issue #6, pre-mortem): defaults on once sync itself is on,
    // but can be turned off without disabling real-time event-driven push.
    var config = new ScimTargetConfig(new ComponentModel());
    assertTrue(config.isReconciliationEnabled());
  }

  @Test
  void reconciliationEnabledHonorsExplicitOptOut() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_RECONCILIATION_ENABLED, false);
    var config = new ScimTargetConfig(model);
    assertFalse(config.isReconciliationEnabled());
  }
}
