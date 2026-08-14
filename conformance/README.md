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

## Known gap: vault-backed credential resolution

Neither `--vault=file` (builds successfully, but `session.vault()` silently falls back to
Keycloak's built-in null-provider — confirmed via bytecode reading of
`DefaultVaultTranscriber` and a diagnostic `HttpRequestInterceptor` showing the raw
`${vault.X}` key being echoed back instead of resolved) nor
`--spi-vault-provider=files-plaintext` (fails outright at build time: "Failed to find
provider files-plaintext for vault") actually enables a working file-based vault backend
in this harness, despite `FilesPlainTextVaultProviderFactory` being present on the
classpath with exactly that provider ID.

This is a local harness provisioning gap, not a plugin bug:
`ScimTargetConfig.resolveCredential`'s use of `session.vault().getStringSecret()` was
verified byte-for-byte against Keycloak's actual `DefaultVaultTranscriber`/
`AbstractVaultProvider`/`FilesPlainTextVaultProvider` implementations, and matches the
documented Vault SPI contract exactly. AC-4 ("never plaintext in component config") is
proven at the unit level (`ScimTargetConfigTest`), just not yet end-to-end against a real
resolved secret in this harness.

**Follow-up**: find the correct Keycloak 25.0.6 Quarkus-CLI incantation to actually enable
`files-plaintext` (or switch the harness to `--spi-vault-provider=env` / a simpler
env-var-backed vault for local testing, if that provider exists and is easier to wire up).

## Running it

```sh
# 1. Build scim-it-server (from a checkout of mario/scimitar)
cd path/to/scimitar && cargo build -p keycloak-it
SCIM_IT_BEARER_TOKEN=test-bearer-token SCIM_IT_PORT=8087 ./target/debug/scim-it-server &

# 2. Build the plugin jar and copy it into the docker build context
cd path/to/keycloak-scim-client
./mvnw package -DskipTests
cp target/keycloak-scim-client-*.jar conformance/docker/keycloak-scim-client.jar

# 3. Bring up Keycloak with the plugin installed
cd conformance/docker
docker compose up --build -d

# 4. Configure a realm, the SCIM target component, and drive it via Admin REST --
#    see the implementation ticket's progress log for the exact API calls used to
#    prove this end-to-end.
```
