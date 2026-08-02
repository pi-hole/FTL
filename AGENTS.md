# AGENTS.md

## Project overview

FTL (`pihole-FTL`) is Pi-hole's DNS/DHCP engine. It embeds a modified `dnsmasq`, adds a query database, statistics, and a REST API, and serves the web interface via an embedded web server. It is written in C, built with CMake, and targets Linux only.

## Repository layout

- `src/` - FTL source code (C)
- `src/dnsmasq/` - embedded dnsmasq. This is vendored upstream code that is regularly synced with dnsmasq upstream. Do not make changes here unless strictly necessary; Pi-hole-specific hooks live in `src/dnsmasq_interface.c`. Any unavoidable modification to vendored source (dnsmasq, or the other vendored libraries under `patch/`) must be minimal, clearly marked so it survives upstream merges, and captured as a patch file under `patch/<library>/` applied via the matching `patch/<library>.sh` script.
- `src/api/` - REST API implementation and OpenAPI specification
- `src/config/` - configuration handling (`pihole.toml`)
- `src/database/` - query database (SQLite3)
- `src/webserver/` - embedded web server (CivetWeb) and Lua handling
- `test/` - test suite (BATS-based, plus API and regression tests)
- `cmake/` - CMake modules

## Dev environment tips

- Build on Linux (or in a Linux container) with `./build.sh`. Run `./build.sh -h` for all options.
- Useful options: `clean` (clean build), `dev` (build, install, restart, tail logs), `test` (run tests after building), `clang` (build with clang).
- CI builds use the `pihole/ftl-build` container images; use those if your host lacks the toolchain.
- The project does not build on macOS or Windows.

## Testing instructions

- Build and run the full suite from the repository root: `./build.sh test` (or `test/run.sh` directly after building).
- Tests exercise a real FTL instance (DNS resolution, API, configuration), so they must run on Linux with the built binary present.
- Add or extend tests for any behavioural change.
- Fix any compiler warnings your change introduces; CI treats them as errors.

## PR instructions

- Base all work on the `development` branch; pull requests target `development`.
- Read the [contributors guide](https://docs.pi-hole.net/guides/github/contributing/)
- Every commit must be signed off (DCO): use `git commit -s`.
- Commits must also be cryptographically signed (GPG or SSH) so GitHub marks them Verified; DCO sign-off alone does not satisfy branch protection. See [GitHub's guide to commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification).
- Run the test suite before committing.
- Use Unix line endings (LF).
- Code is licensed under the EUPL 1.2; contributions must be compatible.
- Follow the existing code style of surrounding code (indentation, naming, comment density). Comment non-obvious logic.
- Stability comes before features: prefer small, well-tested, focused changes over speculative refactors. Do not bundle unrelated changes in one PR.
- API changes must keep the OpenAPI specification under `src/api/docs/` in sync with the implementation.
- The correct project spelling is "Pi-hole" (capital P, lowercase h, hyphen).

## Security considerations

- FTL is a network-facing daemon handling untrusted DNS and HTTP input. Treat all parsing paths as security-sensitive: bounds-check buffers, validate lengths, and be careful with string handling in C.
- The API enforces authentication; never add endpoints or parameters that bypass session checks.
- Do not log secrets (API passwords, session tokens) at any verbosity level.
- If you believe you have found a vulnerability, do not open a public issue or PR; report it privately per the organisation's security policy (disclosure@pi-hole.net).

## Common pitfalls

- Editing `src/dnsmasq/` directly instead of using the interface hooks.
- Assuming the project builds on macOS or Windows; it does not.
- Forgetting the DCO sign-off on commits.
- Changing API behaviour without updating the OpenAPI specification or tests.
