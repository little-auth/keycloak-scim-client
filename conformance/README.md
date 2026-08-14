# Conformance harness

Brings up a real Keycloak 25.0.6 with `keycloak-scim-client` installed, pointed at
`scim-it-server` (the disposable SCIM consumer from
[mario/scimitar](https://github.com/mario/scimitar)'s `keycloak-it/`) — the same target
that harness used to characterize `mitodl/keycloak-scim`'s real bugs, reused here rather
than building an equivalent from scratch (per the implementation ticket's "Conformance
testing target" decision).

## What this proved (2026-08-14)

Running end-to-end against a real Keycloak instance confirmed:

- Both provider factories (`ScimJpaEntityProviderFactory`, `ScimEventListenerProviderFactory`)
  register correctly and Keycloak loads them without error.
- The Liquibase changelog (`scim-changelog.xml`) runs cleanly and creates `SCIM_SYNC_MAPPING`.
- `ScimEventListenerProvider.onEvent` fires on real Admin-API user CREATE/UPDATE events and
  `AdminUserEventInterpreter` correctly filters/interprets them.
- The component-hosting/config-lookup workaround (`loadConfig` filtering the *unfiltered*
  `getComponentsStream()` rather than the filtered overload) is necessary: the filtered
  `realm.getComponentsStream(providerType)` overload does not reliably return
  Admin-REST-created components in this Keycloak version — confirmed directly, not assumed.
- Outbound HTTP requests are correctly shaped: `POST /Users`, `Content-Type:
  application/scim+json`, discovery (`GET /ServiceProviderConfig`) all reach the real target
  and get real (non-crash) SCIM-shaped responses back.
- Error handling (`recordResult`, redaction in `ScimSyncMapping.setLastSyncError`) behaves
  correctly against a real 401 response body.

## Vault-backed credential resolution — proven live (2026-08-14)

Resolved. `ScimTargetConfig.resolveCredential` was previously only verified at the unit
level; it's now proven end-to-end against a real Keycloak instance with a real resolved
secret, not a placeholder.

**Root cause of the earlier gap**: `--vault=file` at build time only makes the
file-vault provider *available* — it must be selected again at **runtime** via
`KC_VAULT=file` (docker-compose.yml), or `session.vault()` silently returns Keycloak's
no-op provider. Confirmed directly: with `KC_VAULT` unset (even with the directory
correctly configured via `KC_SPI_VAULT_FILES_PLAINTEXT_DIR`), enabling `DEBUG` logging
for `org.keycloak.vault` produced **zero** log output — `FilesPlainTextVaultProviderFactory`
was never even instantiated. The correct runtime pairing is `KC_VAULT=file` +
`KC_VAULT_DIR=<dir>` (the friendly-alias env vars, not the SPI-prefixed
`KC_SPI_VAULT_FILES_PLAINTEXT_DIR`, which had no effect despite matching the provider's
actual `getId()`). Once paired correctly, Keycloak logs
`Configured PlainTextVaultProviderFactory with directory ...` at DEBUG on startup —
that line is the tell that it's actually wired up.

**Live proof**: with a realm `test`, a vault secret file `test_scim-target-token`
(REALM_UNDERSCORE_KEY convention) containing a random token, and a `keycloak-scim-target`
component with `credentialVaultRef=${vault.scim-target-token}` pointed at a header-capturing
HTTP server, creating a Keycloak user produced a real outbound `POST /Users` carrying
`Authorization: Bearer <the-real-secret-value>` — the exact value from the vault file, not
the literal `${vault.scim-target-token}` placeholder and not empty. AC-4 is now proven
end-to-end, not just at the unit level.

This also retroactively explains an earlier, separate misdiagnosis
(little-auth/keycloak-scim-client#3): a diagnostic interceptor once saw what looked like
an unauthenticated request on the wire, attributed at the time to a `scim-sdk-client`
header-configuration bug. Isolated repros against the SDK directly showed no such bug —
the real cause was this same vault gap: an unresolved credential meant the SDK was
correctly sending the header, just with the wrong (unresolved) value baked in by our own
code before the SDK ever saw it.

## Running it

```sh
# 1. Build scim-it-server (from a checkout of mario/scimitar)
cd path/to/scimitar && cargo build -p keycloak-it
SCIM_IT_BEARER_TOKEN=test-bearer-token SCIM_IT_PORT=8087 ./target/debug/scim-it-server &

# 2. Build the plugin jar and copy it into the docker build context
cd path/to/keycloak-scim-client
./mvnw package -DskipTests
cp target/keycloak-scim-client-*.jar conformance/docker/keycloak-scim-client.jar

# 3. Create the vault secret Keycloak will resolve (REALM_UNDERSCORE_KEY convention:
#    <realmName>_<vaultKey>, referenced in config as ${vault.<vaultKey>})
mkdir -p conformance/docker/vault
printf '%s' 'your-target-bearer-token' > conformance/docker/vault/test_scim-target-token

# 4. Bring up Keycloak with the plugin installed
cd conformance/docker
docker compose up --build -d

# 5. Configure a realm, the SCIM target component, and drive it via Admin REST --
#    see the implementation ticket's progress log for the exact API calls used to
#    prove this end-to-end.
```
