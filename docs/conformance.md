# AuthZEN 1.0 scope and verification

The target is [Authorization API 1.0 Final (January 11, 2026)](https://openid.net/specs/authorization-api-1_0.html).
This library is a **PEP-side client** for Action Policy, not a PDP server or an
officially certified implementation.

## API coverage

| Specification | Client API | Coverage |
| --- | --- | --- |
| Section 6: evaluation | `evaluate`, `allowed?` | Allow/deny, properties, context, malformed responses, transport failures |
| Section 7: batch evaluation | `evaluations` | Defaults, whole-object replacement, empty arrays, all three semantics, short-circuit position, individual errors |
| Section 8.4: subject search | `search_subjects`, `each_subject` | Type-only search target and result validation |
| Section 8.5: resource search | `search_resources`, `each_resource` | Type-only search target and Action Policy scopes |
| Section 8.6: action search | `search_actions`, `each_action` | Requests without action, result name validation |
| Section 8.2: pagination | `page:`, `each_*` | Opaque tokens, zero limit, empty pages, termination, cycles, immutable query |
| Section 9: discovery | `Client.discover`, `configuration`, `metadata` | Tenant paths, exact identity, advertised URLs, absent optional endpoints |
| Section 10: transport | All methods | JSON objects, HTTP 200, Content-Type, X-Request-ID, TLS certificate and hostname verification |

Policy helpers add the `authzen_` prefix to instance methods, except the
client-only `metadata` reader. Decisions must be booleans. Invalid or partial
responses are never interpreted as authorization. Unknown response fields are
preserved but do not influence decisions.

## Optional features and boundaries

- **Signed metadata:** intentionally unsupported. Section 9.1.3 permits a PEP to ignore `signed_metadata`; the client validates plain JSON metadata only.
- **Capabilities:** exposed as metadata, not automatically implemented. Unsupported pagination extension keys are rejected; use standard `page.properties` for implementation-specific attributes.
- **Authentication:** outside the specification's scope. Supply bearer tokens or other headers through `headers:`; token issuance and renewal belong to the application.
- **HTTPS:** required by default. `allow_http: true` is an explicit local-test exception. `ca_file:` configures a trusted CA without disabling verification.
- **Discovery:** cross-origin endpoints require `trusted_origins:`. Missing advertised optional endpoints raise `UnsupportedEndpoint`; nondiscovery configurations use standard paths.
- **Search:** not an atomic permission snapshot. Deduplication and reauthorization before an operation belong to the application.
- **Decision context:** preserved, including reasons, errors, and obligations. Application-specific obligations are not executed automatically.

## PDP targets

- [OpenFGA 1.21.0](https://github.com/openfga/openfga/releases/tag/v1.21.0): tested with `authzen` enabled. Native APIs provision stores/models/tuples; AuthZEN exercises evaluation, batch, all searches, and discovery. Its [documented lack of pagination](https://openfga.dev/docs/interacting/authzen) is not used as pagination evidence.
- [OPA AuthZEN plugin 0.8.0](https://github.com/kanywst/opa-authzen-plugin/tree/v0.8.0): a separate extension, not stock OPA. Tested across all six endpoints, all batch semantics, paginated searches, reauthorization, and Action Policy integration. The Linux x86_64 runner pins the binary SHA-256.
- [Topaz 0.33.20](https://github.com/aserto-dev/topaz/releases/tag/v0.33.20): all endpoints and `execute_all` work. It ignores short-circuit options; tests verify client rejection. Returning all search results despite `limit`, with an empty token, is permitted by scenario c-4-5-4 and is not itself nonconformance.
- Cerbos and Keycloak were investigated, but all three locally testable search endpoints were not established, so they were not selected for full-API testing.

## Verification evidence

The [official scenario matrix](official-scenarios.md) separates applicable client
checks from PDP-only requirements and unsupported optional features.

Recorded baseline on September 22, 2026, using Ruby 3.2.1:

| Target | Tests | Assertions | Result |
| --- | ---: | ---: | --- |
| Unit HTTP/TLS, including scenario regressions | 65 | 237 | Passed |
| OpenFGA 1.21.0 | 4 | 23 | Passed |
| OPA AuthZEN plugin 0.8.0 | 3 | 35 | Passed |
| Official WG scenario / OPA plugin 0.8.0 | 35 | 152 | Passed using a project-owned runner |
| Topaz 0.33.20 | 7 | 25 | Passed, including known-incompatibility checks |

These PDP tests used official release binaries locally. Topaz Compose and GitHub
Actions were not executed in that environment because Docker was unavailable.
Ruby/shell syntax and gem build checks passed. The minimum supported Ruby version
is now 3.3, and CI is configured for Ruby 3.3, 3.4, and 4.0. The Ruby 3.2.1 results
are historical evidence, not verification on the currently supported versions.

`bundle exec rake test` uses local HTTP/TLS servers for valid and malformed
responses, short-circuit positions, pagination, metadata, and certificate failures.
`bundle exec rake integration` uses `OPENFGA_URL`, `TOPAZ_URL`, `OPA_URL`, and
`OFFICIAL_PDP_URL`. The official fixture needs a separate PDP process/port from
the basic OPA fixture. Only unset URLs skip tests; configured service failures fail.

Interop results are not official certification or a guarantee of compatibility
with every PDP.

After the documentation translation and client cleanup, Ruby 3.2.1 verification
passed 66 unit tests / 253 assertions, 35 official-scenario tests / 152 assertions,
and 3 OPA integration tests / 35 assertions, with no failures, errors, or skips.
Ruby/shell/YAML syntax and gem build checks also passed. OpenFGA, Topaz, and GitHub
Actions were not rerun for this cleanup; their results above are earlier evidence.

After raising the minimum Ruby version to 3.3, local verification on Ruby 3.3.5
passed 66 unit tests / 253 assertions with no failures, errors, or skips. Ruby
requirement checks, workflow YAML parsing, and gem build also passed. PDP
integration tests and the Ruby 3.4/4.0 CI jobs were not rerun for this change.
