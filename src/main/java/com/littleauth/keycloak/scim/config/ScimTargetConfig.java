package com.littleauth.keycloak.scim.config;

import java.util.List;
import java.util.Locale;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.vault.VaultStringSecret;

/**
 * Typed view over the {@link ComponentModel} that holds a realm's SCIM target
 * configuration (hosted on a User Storage Provider SPI component -- see the
 * "Config hosting mechanism" discovery in the implementation ticket -- purely as a vehicle
 * for Keycloak's generic config-form UI, decoupled from that SPI's storage semantics).
 *
 * <p>The credential field only ever holds a Keycloak Vault SPI reference
 * ({@code ${vault.ID}}); {@link #resolveCredential} is the one place the raw secret value
 * is ever materialized, and only in memory, never written back to the component config.
 */
public class ScimTargetConfig {

  public static final String KEY_TARGET_URL = "targetUrl";
  public static final String KEY_ALLOWLIST_HOSTS = "targetUrlAllowlistHosts";
  public static final String KEY_CREDENTIAL_VAULT_REF = "credentialVaultRef";
  public static final String KEY_DELETE_POLICY = "deletePolicy";
  public static final String KEY_SYNC_ENABLED = "syncEnabled";
  public static final String KEY_HARD_DELETE_CONFIRMATION = "hardDeleteConfirmation";

  private final ComponentModel model;

  /** Wraps the given component's config; reads through to it live, never copies. */
  public ScimTargetConfig(ComponentModel model) {
    this.model = model;
  }

  /** The configured SCIM target base URL, or {@code null} if unset. */
  public String getTargetUrl() {
    return model.get(KEY_TARGET_URL);
  }

  /** Hosts exempt from {@link TargetUrlValidator}'s default private-range rejection. */
  public List<String> getAllowlistHosts() {
    List<String> hosts = model.getConfig().get(KEY_ALLOWLIST_HOSTS);
    return hosts == null ? List.of() : List.copyOf(hosts);
  }

  /**
   * How Keycloak deletions map to the SCIM target. Defaults to {@link
   * DeletePolicy#SOFT_DELETE}.
   *
   * @throws IllegalArgumentException if more than one value is stored for this field.
   *     Keycloak's component config is multi-valued by design and nothing at the framework
   *     level enforces single-value cardinality on a LIST_TYPE field for an Admin REST
   *     caller (only the Admin Console UI's dropdown happens to submit one value) -- reading
   *     just the first value would make which policy actually applies depend on JPA
   *     Set-iteration order, which can differ between this read and a later one of the same
   *     persisted row, silently letting {@link DeletePolicy#HARD_DELETE} apply at dispatch
   *     time despite a validate-time read seeing (and accepting as) {@code SOFT_DELETE}.
   */
  public DeletePolicy getDeletePolicy() {
    List<String> values = model.getConfig().get(KEY_DELETE_POLICY);
    if (values == null || values.isEmpty()) {
      return DeletePolicy.SOFT_DELETE;
    }
    if (values.size() > 1) {
      throw new IllegalArgumentException(
          "Multiple values submitted for " + KEY_DELETE_POLICY + " " + values
              + " -- exactly one is required.");
    }
    return DeletePolicy.valueOf(values.get(0));
  }

  public boolean isSyncEnabled() {
    return model.get(KEY_SYNC_ENABLED, false);
  }

  /**
   * Resolves the SCIM target credential through Keycloak's Vault SPI.
   *
   * @throws IllegalStateException if no vault reference is configured, or the vault
   *     cannot resolve it -- this never falls back to treating the raw config value as
   *     the secret itself.
   */
  public String resolveCredential(KeycloakSession session) {
    String vaultRef = model.get(KEY_CREDENTIAL_VAULT_REF);
    if (vaultRef == null || vaultRef.isBlank()) {
      throw new IllegalStateException(
          "No SCIM target credential configured (" + KEY_CREDENTIAL_VAULT_REF + ")");
    }
    try (VaultStringSecret secret = session.vault().getStringSecret(vaultRef)) {
      return secret
          .get()
          .orElseThrow(
              () ->
                  new IllegalStateException(
                      "SCIM target credential vault reference did not resolve to a value"));
    }
  }

  /**
   * The exact phrase an admin must type into {@link #KEY_HARD_DELETE_CONFIRMATION} to enable
   * {@link DeletePolicy#HARD_DELETE} for the given realm. Embeds the realm's own name so a
   * single copy-pasted literal can't silently re-enable hard-delete across every realm in an
   * IaC-managed config -- a global fixed phrase alone doesn't hold up against that (pre-mortem
   * mitigation, see the implementation ticket).
   */
  public static String requiredHardDeleteConfirmationPhrase(RealmModel realm) {
    // Trimmed like the admin-typed input is (see isHardDeleteConfirmed) -- a realm name
    // carrying incidental surrounding whitespace must not produce a phrase no trimmed input
    // could ever match, which would permanently block HARD_DELETE for that realm.
    return "ENABLE HARD DELETE FOR " + realm.getName().trim().toUpperCase(Locale.ROOT);
  }

  /**
   * Whether {@link #KEY_HARD_DELETE_CONFIRMATION} matches the realm-specific phrase required
   * to enable {@link DeletePolicy#HARD_DELETE} -- the high-friction confirmation gate this
   * exists for is a bare toggle otherwise. Only whitespace around the value is forgiven; the
   * phrase itself stays exact-match (case included) by design.
   */
  public boolean isHardDeleteConfirmed(RealmModel realm) {
    String raw = model.get(KEY_HARD_DELETE_CONFIRMATION);
    return raw != null && requiredHardDeleteConfirmationPhrase(realm).equals(raw.trim());
  }

  /** How a Keycloak user delete maps to the SCIM target. */
  public enum DeletePolicy {
    SOFT_DELETE,
    HARD_DELETE
  }
}
