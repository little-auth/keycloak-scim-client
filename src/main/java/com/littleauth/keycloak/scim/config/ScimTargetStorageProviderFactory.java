package com.littleauth.keycloak.scim.config;

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
 * {@link TargetUrlValidator}'s SSRF guard at config-save time -- AC-5.
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
            "How a Keycloak user delete maps to the SCIM target.",
            ProviderConfigProperty.LIST_TYPE,
            ScimTargetConfig.DeletePolicy.SOFT_DELETE.name(),
            ScimTargetConfig.DeletePolicy.SOFT_DELETE.name(),
            ScimTargetConfig.DeletePolicy.HARD_DELETE.name()),
        new ProviderConfigProperty(
            ScimTargetConfig.KEY_SYNC_ENABLED,
            "Sync enabled",
            "Live kill switch: takes effect on the next event, no restart needed.",
            ProviderConfigProperty.BOOLEAN_TYPE,
            Boolean.FALSE),
        new ProviderConfigProperty(
            ScimTargetConfig.KEY_RECONCILIATION_ENABLED,
            "Reconciliation enabled",
            "Independent kill switch for the periodic background reconciliation pass "
                + "(self-heals drift from missed events) -- can be turned off without "
                + "disabling real-time sync. Takes effect on the next scheduled tick.",
            ProviderConfigProperty.BOOLEAN_TYPE,
            Boolean.TRUE));
  }

  @Override
  public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model)
      throws ComponentValidationException {
    var config = new ScimTargetConfig(model);
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
