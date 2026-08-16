# keycloak-scim-client

A Keycloak SPI plugin: a full SCIM 2.0 client that pushes and syncs Keycloak users and
groups to an external SCIM 2.0 service provider (Users, Groups, PATCH-with-PUT-fallback,
discovery-driven capability detection, periodic reconciliation), configured through a
custom admin console tab rather than Keycloak's generic auto-generated provider form.

Replaces [mitodl/keycloak-scim](https://github.com/mitodl/keycloak-scim) for our use with
[little-auth-scim](https://github.com/little-auth/little-auth-scim)-based SCIM targets — see
that project's `keycloak-it` harness for the conformance findings that shaped several
decisions here (the DELETE-after-row-gone bug, the silent `emailVerified` gate,
PATCH-off-by-default) and for the disposable SCIM server this project's own conformance
tests point at.

## Status

Early, pre-alpha.

## Build

Requires JDK 17 (matching Keycloak 25.0.6's own build; a newer JDK breaks Mockito's
bytecode instrumentation for the test suite). `.tool-versions` pins
`temurin-17.0.20+8` via [asdf](https://asdf-vm.com/); `asdf install` fetches it,
scoped to just this project.

```sh
asdf install
export JAVA_HOME="$(asdf where java)"
./mvnw clean package
```

Produces `target/keycloak-scim-client-<version>.jar`, dropped into Keycloak's
`providers/` directory.

## Releasing

See [RELEASING.md](RELEASING.md).

## License

Apache-2.0 — see `LICENSE`.
