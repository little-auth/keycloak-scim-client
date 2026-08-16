# Releasing

keycloak-scim-client doesn't publish to a package registry (crates.io / Maven Central) --
it's an internal-use Keycloak SPI plugin, distributed as a downloadable jar attached to a
GitHub Release, built via a tag-triggered GitHub Actions workflow
(`.github/workflows/release.yml`). The mechanism mirrors little-auth-scim's release process
(see that repo's `RELEASING.md`), adapted for a jar-on-GitHub-Releases target instead of
crates.io.

## How it works

1. Bump the version in `pom.xml` (`<version>X.Y.Z</version>`, dropping the `-SNAPSHOT` suffix)
   on a normal PR into `main`, reviewed like any other change.
2. Once that PR is merged, tag the commit on `main`: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. The tag push triggers two jobs:
   - **`verify`**: re-runs the full gate against the tagged commit (a tag push skips the PR
     run entirely, so this redoes it) -- `./mvnw clean test`. Also checks that the tagged
     commit is actually an ancestor of `main` (a tag can point anywhere; without this check,
     tagging is a way around every branch protection the repo has) and that the tag's version
     matches `pom.xml`'s `<version>` (a `-SNAPSHOT` still present at tag time means the
     version bump was never actually made -- catches that before it produces a mislabeled
     release). Builds the jar and uploads it as a workflow artifact for the next job.
   - **`github_release`**: gated behind the `release` GitHub Environment, which requires a
     manual approval from a listed reviewer before it runs. Creates the GitHub Release and
     attaches the built jar as a downloadable asset.
4. Approve the `github_release` job (Actions tab -> the running workflow run -> Review
   deployments), or from the CLI: `gh run list --workflow=release.yml` then
   `gh run view <run-id>` for the review link.
5. Deploy: download the jar from the release and drop it into Keycloak's `providers/`
   directory, per the root README's Build section.

## One-time setup already done

- The `release` environment exists on this repo with `mario` as a required reviewer
  (repo Settings -> Environments -> release -> Deployment protection rules). Add more
  reviewers there if the maintainer set grows.

## Why gate the GitHub Release instead of a separate publish step

Unlike little-auth-scim (where the release page and the crates.io publish are two genuinely
separate, independently-useful actions -- the page can exist before anyone approves shipping
to the registry), this repo's only real "release" artifact *is* the GitHub Release with its
attached jar. There's nothing meaningful to publish immediately and something else to gate --
so the approval gate sits on the release step itself, not on a downstream publish job.

## Known gap this release process could eventually close

little-auth-scim's `keycloak-conformance.yml` CI workflow currently can't check out this repo
at all in CI (tracked as
[little-auth/little-auth-scim#19](https://github.com/little-auth/little-auth-scim/issues/19)
-- it references a `KEYCLOAK_SCIM_CLIENT_PAT` secret that was never created). Once this repo
has tagged releases with a downloadable jar, that CI job could pull the released jar directly
(a public download, no cross-repo token needed) instead of an authenticated private-repo
checkout-and-build. Not done as part of this change -- see
[little-auth/keycloak-scim-client#21](https://github.com/little-auth/keycloak-scim-client/issues/21)
for the tracking issue this release process implements.

## Also added this session, adjacent to this work

- `.github/workflows/ci.yml` -- this repo had **no CI at all** before now, everything was
  verified by running `./mvnw clean test` locally. `release.yml`'s `verify` job assumes a
  `ci.yml` gate already exists on `main` (mirroring `drey`'s own reasoning: "a tag push skips
  the pull-request run, so redo it here"), so a baseline CI workflow was added alongside the
  release workflow rather than leaving that assumption unmet.
- `checkstyle.xml` exists in this repo but isn't wired into `pom.xml` or CI at all --
  deliberately left out of both new workflows rather than guessing at a fix. See
  [#22](https://github.com/little-auth/keycloak-scim-client/issues/22).
