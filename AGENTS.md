# AGENTS.md

## Project overview

FTL (`pihole-FTL`) is Pi-hole's DNS/DHCP engine. It embeds a modified `dnsmasq`, adds a query database, statistics, and a REST API, and serves the web interface via an embedded web server. It is written in C, built with CMake, and targets Linux only.

## Repository layout

- `src/` - FTL source code (C)
- `src/dnsmasq/` - embedded dnsmasq (do not modify; see "Vendored code policy" below)
- `src/api/` - REST API implementation and OpenAPI specification
- `src/config/` - configuration handling (`pihole.toml`)
- `src/database/` - query database (SQLite3)
- `src/webserver/` - embedded web server (CivetWeb) and Lua handling
- `test/` - test suite (BATS-based, plus API and regression tests)
- `tools/` - standalone helper scripts (TLS cert generation, MAC vendor lookup, TOML-to-Markdown docs)
- `cmake/` - build output directory created by `build.sh`; gitignored, not part of a checkout

## Vendored code policy

FTL vendors several third-party libraries. For all of them, the default is to send a fix upstream, not to carry it as a local patch; a patch is only justified for something genuinely Pi-hole specific with little or no chance of upstream acceptance.

- `src/dnsmasq/` tracks upstream dnsmasq and must not be modified, no exceptions. The `FTL_*()` calls already present in it are the complete set of Pi-hole additions and are not a precedent for more: every one of them is a call into `src/dnsmasq_interface.c`, which is where Pi-hole-specific behavior belongs.  Send `dnsmasq` related fixes to the [`dnsmasq-discuss` mailing list](https://lists.thekelleys.org.uk/cgi-bin/mailman/listinfo/dnsmasq-discuss). They reach us through a merge once they land in dnsmasq master.
- CivetWeb (`src/webserver/`), the bundled Lua, and SQLite3 are the only vendored components with a local patch mechanism: genuinely Pi-hole-specific changes (URI rewriting, the CSRF token, bundled Lua script loading, etc.) live as patch files under `patch/<library>/`, applied via the matching `patch/<library>.sh` script manually after each drop-in copy from upstream (only done by the FTL maintainers team). What is committed in the tree is the already-patched source.
- Other vendored code (`src/tre-regex`, `src/webserver/cJSON`, `src/zip/miniz`, `src/config/tomlc17`, `src/database/sqlite3_rsync.c`) has no patch mechanism at all - the upstream-first rule applies with no local exception mechanism.

## Dev environment tips

- Build on Linux (or in a Linux container) with `./build.sh`. Run `./build.sh -h` for all options.
- Useful options: `clean` (clean build), `dev` (build, install, restart, tail logs), `test` (run tests after building), `clang` (build with clang).
- CI builds use the `pihole/ftl-build` container images. Building can happen on a host with the right toolchain, but always run the test suite inside the container - see Testing instructions.
- The project does not build on macOS or Windows.

## Testing instructions

- Run the test suite inside the `pihole/ftl-build` container, never on a host that runs a real Pi-hole: `./build.sh test` (via `test/run.sh`) creates a `pihole` system user, kills any running `pihole-FTL`, and wipes `/etc/pihole`, `/etc/dnsmasq.d`, `/var/log/pihole` and `/dev/shm/FTL-*` before seeding its own fixtures.
- Tests exercise a real FTL instance (DNS resolution, API, configuration).
- Add or extend tests for any behavioral change.
- Fix any compiler warnings your change introduces in FTL code; CI treats them as errors there. The vendored trees and the regression-test harness binaries (e.g. the tar, dotdoh and gzip parser harnesses) are deliberately built with lighter warning flags - don't "fix" warnings in those.

## PR instructions

- Base all work on the `development` branch; pull requests target `development`.
- Read the [contributors guide](https://docs.pi-hole.net/guides/github/contributing/) and the [pull request template](.github/PULL_REQUEST_TEMPLATE.md).
- Every commit must be signed off (DCO): use `git commit -s`.
- Commits must also be cryptographically signed (GPG or SSH) so GitHub marks them Verified; DCO sign-off alone does not satisfy branch protection. See [GitHub's guide to commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification).
- Run the test suite before committing.
- Use Unix line endings (LF).
- Code is licensed under the EUPL 1.2; contributions must be compatible.
- Follow the existing code style of surrounding code (indentation, naming, comment density). Comment non-obvious logic.
- Stability comes before features: prefer small, well-tested, focused changes over speculative refactors. Do not bundle unrelated changes in one PR.
- API changes must keep the OpenAPI specification under `src/api/docs/` in sync with the implementation; CI checks this with the "API validation" workflow.
- Match American spelling in code, comments and docs (`behavior`, not `behaviour`) - the existing codebase uses American English throughout, and CI runs a "Codespell" check.
- The correct project spelling is "Pi-hole" (capital P, lowercase h, hyphen).

## Security considerations

- FTL is a network-facing daemon handling untrusted DNS and HTTP input. Treat all parsing paths as security-sensitive: bounds-check buffers, validate lengths, and be careful with string handling in C.
- The API enforces authentication; never add endpoints or parameters that bypass session checks.
- Do not log secrets (API passwords, session tokens) at any verbosity level.
- If you believe you have found a vulnerability, do not open a public issue or PR; report it privately per the organization's security policy (disclosure@pi-hole.net).

## Common pitfalls

- Modifying `src/dnsmasq/` at all, instead of sending the fix upstream or using the interface hooks in `src/dnsmasq_interface.c`.
- Running the test suite on a host that isn't the `pihole/ftl-build` container; `test/run.sh` wipes `/etc/pihole` and related paths.
- Assuming the project builds on macOS or Windows; it does not.
- Forgetting the DCO sign-off, or forgetting that commits must also be cryptographically signed.
- Changing API behavior without updating the OpenAPI specification or tests.
- "Fixing" compiler warnings in vendored code or the regression-test harnesses; they intentionally use lighter warning flags.
