package com.littleauth.keycloak.scim.config;

import java.util.Arrays;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.UserStorageProviderFactory;

/**
 * Factory for {@link ScimTargetStorageProvider} -- the vehicle for {@link ScimTargetConfig}'s
 * admin console form (Keycloak's generic "Provider Config" UI, pre-declarative-ui fallback;
 * see the UI mechanism decision in context.md). {@link #validateConfiguration} wires in
 * {@link TargetUrlValidator}'s SSRF guard at config-save time -- AC-5 -- and also enforces
 * that {@link ScimTargetConfig.DeletePolicy#HARD_DELETE} can't be enabled by the delete-policy
 * dropdown alone: it requires a matching, realm-specific confirmation phrase (issue #7's
 * pre-mortem mitigation), rejected identically whether the save came from the Admin Console
 * UI or the Admin REST API.
 */
public class ScimTargetStorageProviderFactory
    implements UserStorageProviderFactory<ScimTargetStorageProvider> {

  public static final String ID = "keycloak-scim-target";

  @Override
  public ScimTargetStorageProvider create(KeycloakSession session, ComponentModel model) {
    return new ScimTargetStorageProvider();
  }

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public String getHelpText() {
    return "Configures the external SCIM 2.0 target this realm's users sync to.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return List.of(
        new ProviderConfigProperty(
            ScimTargetConfig.KEY_TARGET_URL,
            "SCIM target base URL",
            "The base URL of the external SCIM 2.0 service provider, e.g. "
                + "https://scim.example.com/scim/v2",
            ProviderConfigProperty.STRING_TYPE,
            null),
        new ProviderConfigProperty(
            ScimTargetConfig.KEY_ALLOWLIST_HOSTS,
            "Allowlisted target hosts",
            "Hosts exempt from the default rejection of private/internal address ranges "
                + "(and from the HTTPS-only requirement) -- for legitimate internal "
                + "deployments or local/CI conformance targets.",
            ProviderConfigProperty.MULTIVALUED_STRING_TYPE,
            null),
        new ProviderConfigProperty(
            ScimTargetConfig.KEY_CREDENTIAL_VAULT_REF,
            "Credential (vault reference)",
            "A Keycloak Vault SPI reference (${vault.ID}), never a raw secret -- see "
                + "Server Administration Guide \"Using a vault to obtain secrets\". Sent as "
                + "a Bearer token; Basic auth isn't implemented yet (tracked separately).",
            ProviderConfigProperty.STRING_TYPE,
            null,
            true),
        new ProviderConfigProperty(
            ScimTargetConfig.KEY_DELETE_POLICY,
            "Delete policy",
            "How a Keycloak user delete maps to the SCIM target. Selecting HARD_DELETE also "
                + "requires filling in the \"Hard-delete confirmation\" field below -- it "
                + "cannot be enabled by this dropdown alone.",
            ProviderConfigProperty.LIST_TYPE,
            ScimTargetConfig.DeletePolicy.SOFT_DELETE.name(),
            ScimTargetConfig.DeletePolicy.SOFT_DELETE.name(),
            ScimTargetConfig.DeletePolicy.HARD_DELETE.name()),
        new ProviderConfigProperty(
            ScimTargetConfig.KEY_HARD_DELETE_CONFIRMATION,
            "Hard-delete confirmation",
            "Required only when Delete policy above is HARD_DELETE. Hard-delete permanently "
                + "removes the user's SCIM resource on every Keycloak user delete -- this "
                + "cannot be undone. To enable it, type the exact phrase \"ENABLE HARD DELETE "
                + "FOR <REALM NAME>\", replacing <REALM NAME> with this realm's own name in "
                + "upper case (e.g. realm \"acme\" -> \"ENABLE HARD DELETE FOR ACME\").",
            ProviderConfigProperty.STRING_TYPE,
            null),
        new ProviderConfigProperty(
            ScimTargetConfig.KEY_SYNC_ENABLED,
            "Sync enabled",
            "Live kill switch: takes effect on the next event, no restart needed.",
            ProviderConfigProperty.BOOLEAN_TYPE,
            Boolean.FALSE));
  }

  @Override
  public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model)
      throws ComponentValidationException {
    var config = new ScimTargetConfig(model);
    ScimTargetConfig.DeletePolicy deletePolicy;
    try {
      deletePolicy = config.getDeletePolicy();
    } catch (IllegalArgumentException e) {
      // The LIST_TYPE config property only constrains the Admin Console UI's dropdown, not
      // an Admin REST API caller -- an invalid value must fail as a clean, admin-actionable
      // ComponentValidationException, not an unwrapped enum-parsing IllegalArgumentException.
      throw new ComponentValidationException(
          "Invalid "
              + ScimTargetConfig.KEY_DELETE_POLICY
              + " value -- must be one of "
              + Arrays.toString(ScimTargetConfig.DeletePolicy.values()),
          e);
    }
    if (deletePolicy == ScimTargetConfig.DeletePolicy.HARD_DELETE) {
      if (!config.isHardDeleteConfirmed(realm)) {
        throw new ComponentValidationException(
            "Hard-delete mode permanently removes the user's SCIM resource on every Keycloak "
                + "user delete and cannot be undone -- to enable it, set \"Hard-delete "
                + "confirmation\" to the exact phrase: \""
                + ScimTargetConfig.requiredHardDeleteConfirmationPhrase(realm)
                + "\".");
      }
    } else if (model.getConfig().containsKey(ScimTargetConfig.KEY_HARD_DELETE_CONFIRMATION)) {
      // Every save that leaves (or never enters) HARD_DELETE clears any stored confirmation
      // value -- otherwise a stale, previously-valid phrase would silently re-arm HARD_DELETE
      // on a later flip back with no re-confirmation, exactly the bare-toggle bypass this
      // gate exists to close (adversarial-confirmation-pass finding, not caught by the
      // council rounds: HARD_DELETE -> SOFT_DELETE -> HARD_DELETE re-enabled with zero
      // friction the second time).
      model.getConfig().remove(ScimTargetConfig.KEY_HARD_DELETE_CONFIRMATION);
    }
    String targetUrl = config.getTargetUrl();
    if (targetUrl == null || targetUrl.isBlank()) {
      return; // Allow saving an unconfigured/disabled instance.
    }
    try {
      new TargetUrlValidator(config.getAllowlistHosts()).validate(targetUrl);
    } catch (InvalidTargetUrlException e) {
      throw new ComponentValidationException(e.getMessage(), e);
    }
  }

  @Override
  public void init(Config.Scope config) {
    // No global configuration needed.
  }
}
