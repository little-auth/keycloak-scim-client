package com.littleauth.keycloak.scim.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
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

  /**
   * Keycloak component config is multi-valued by design (MultivaluedHashMap), and nothing
   * at the framework level rejects submitting more than one value for a field the admin
   * console's LIST_TYPE dropdown only ever renders as single-select -- an Admin REST caller
   * can submit deletePolicy: ["SOFT_DELETE", "HARD_DELETE"] directly. Reading only the
   * first value (Keycloak's ComponentModel.get() default) would make which policy actually
   * applies depend on JPA Set-iteration order, which can differ between the validate-time
   * read and a later runtime read of the same row -- letting HARD_DELETE apply at dispatch
   * time despite validate time seeing (and accepting as) SOFT_DELETE. Must fail loud instead.
   */
  @Test
  void getDeletePolicyThrowsWhenMultipleValuesAreSubmittedForThisSingleValuedField() {
    ComponentModel model = new ComponentModel();
    model.getConfig()
        .put(ScimTargetConfig.KEY_DELETE_POLICY, List.of("SOFT_DELETE", "HARD_DELETE"));
    var config = new ScimTargetConfig(model);
    assertThrows(IllegalArgumentException.class, config::getDeletePolicy);
  }

  @Test
  void getDeletePolicyDefaultsToSoftDeleteWhenExplicitlySetToAnEmptyList() {
    ComponentModel model = new ComponentModel();
    model.getConfig().put(ScimTargetConfig.KEY_DELETE_POLICY, List.of());
    var config = new ScimTargetConfig(model);
    assertEquals(ScimTargetConfig.DeletePolicy.SOFT_DELETE, config.getDeletePolicy());
  }

  /**
   * Unlike the multi-value case, a single stored value that is itself null must not throw
   * -- it must default the same as an absent key. model.getConfig().get(KEY) can hand back
   * a singleton list containing null (a NULL config row read back from the database, with
   * no upstream null-filtering guaranteed at that layer), and Enum.valueOf(null) throws
   * NullPointerException, not IllegalArgumentException -- a bare "get the first value"
   * read handled this safely before the cardinality check was added; the cardinality check
   * must not reopen it.
   */
  @Test
  void getDeletePolicyDefaultsToSoftDeleteWhenTheSingleStoredValueIsNull() {
    ComponentModel model = new ComponentModel();
    model.getConfig().put(ScimTargetConfig.KEY_DELETE_POLICY, Arrays.asList((String) null));
    var config = new ScimTargetConfig(model);
    assertEquals(ScimTargetConfig.DeletePolicy.SOFT_DELETE, config.getDeletePolicy());
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
  void authModeDefaultsToBearerWhenKeyIsEntirelyAbsent() {
    // Every pre-existing production realm has no authMode key at all -- this default
    // path is what keeps every already-shipped Bearer-only config working post-upgrade.
    var config = new ScimTargetConfig(new ComponentModel());
    assertEquals(ScimTargetConfig.AuthMode.BEARER, config.getAuthMode());
  }

  @Test
  void authModeDefaultsToBearerWhenValueIsBlankNotJustAbsent() {
    // A Keycloak form re-save could plausibly turn "key absent" into "key present but
    // empty string" for a newly-added LIST_TYPE property -- must not throw.
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_AUTH_MODE, "");
    var config = new ScimTargetConfig(model);
    assertEquals(ScimTargetConfig.AuthMode.BEARER, config.getAuthMode());
  }

  @Test
  void authModeHonorsExplicitBasicConfiguration() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_AUTH_MODE, "BASIC");
    var config = new ScimTargetConfig(model);
    assertEquals(ScimTargetConfig.AuthMode.BASIC, config.getAuthMode());
  }

  @Test
  void getUsernameReturnsNullWhenUnset() {
    var config = new ScimTargetConfig(new ComponentModel());
    assertEquals(null, config.getUsername());
  }

  @Test
  void getUsernameReturnsTheConfiguredValue() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_USERNAME, "svc-account");
    var config = new ScimTargetConfig(model);
    assertEquals("svc-account", config.getUsername());
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

  private static RealmModel realmNamed(String name) {
    RealmModel realm = mock(RealmModel.class);
    when(realm.getName()).thenReturn(name);
    return realm;
  }

  @Test
  void isHardDeleteConfirmedReturnsFalseWhenConfirmationUnset() {
    var config = new ScimTargetConfig(new ComponentModel());
    assertFalse(config.isHardDeleteConfirmed(realmNamed("acme")));
  }

  @Test
  void isHardDeleteConfirmedReturnsFalseWhenConfirmationExplicitlySetToEmptyString() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_HARD_DELETE_CONFIRMATION, "");
    var config = new ScimTargetConfig(model);
    assertFalse(config.isHardDeleteConfirmed(realmNamed("acme")));
  }

  @Test
  void isHardDeleteConfirmedReturnsFalseWhenConfirmationDoesNotMatchRealmSpecificPhrase() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_HARD_DELETE_CONFIRMATION, "ENABLE HARD DELETE FOR OTHER-REALM");
    var config = new ScimTargetConfig(model);
    assertFalse(config.isHardDeleteConfirmed(realmNamed("acme")));
  }

  @Test
  void isHardDeleteConfirmedReturnsTrueWhenConfirmationMatchesExactRealmSpecificPhrase() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_HARD_DELETE_CONFIRMATION, "ENABLE HARD DELETE FOR ACME");
    var config = new ScimTargetConfig(model);
    assertTrue(config.isHardDeleteConfirmed(realmNamed("acme")));
  }

  @Test
  void isHardDeleteConfirmedTrimsSurroundingWhitespace() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_HARD_DELETE_CONFIRMATION, "  ENABLE HARD DELETE FOR ACME  ");
    var config = new ScimTargetConfig(model);
    assertTrue(config.isHardDeleteConfirmed(realmNamed("acme")));
  }

  /**
   * A realm name carrying incidental surrounding whitespace must not produce a required
   * phrase no trimmed admin-typed input could ever match -- that would permanently block
   * HARD_DELETE for that realm.
   */
  @Test
  void requiredHardDeleteConfirmationPhraseTrimsTheRealmNameToo() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_HARD_DELETE_CONFIRMATION, "ENABLE HARD DELETE FOR ACME");
    var config = new ScimTargetConfig(model);
    assertTrue(config.isHardDeleteConfirmed(realmNamed("acme ")));
  }

  @Test
  void isHardDeleteConfirmedIsCaseSensitive() {
    ComponentModel model = new ComponentModel();
    model.put(ScimTargetConfig.KEY_HARD_DELETE_CONFIRMATION, "enable hard delete for acme-realm");
    var config = new ScimTargetConfig(model);
    // Same realm, same text modulo case -- the mismatch here is case alone, not realm name.
    assertFalse(config.isHardDeleteConfirmed(realmNamed("Acme-Realm")));
  }
}
