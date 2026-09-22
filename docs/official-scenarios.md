# Official AuthZEN scenario coverage

## Pinned source

- [OpenID AuthZEN WG Certification Scenario](https://github.com/openid/authzen/blob/6ed00bad5daa8f6eef6f2aef1f124442beeb8382/certification/authorization-api-1_0-scenario.md)
- Repository: `openid/authzen`
- Commit: `6ed00bad5daa8f6eef6f2aef1f124442beeb8382`
- File: `certification/authorization-api-1_0-scenario.md`
- SHA-256: `dc6846304169f32077c2f4a74a0912fff2df734a20999762b0055e15ac8ce534`
- Retrieved: September 22, 2026

These are **project-owned PEP interoperability and regression tests based on the
official scenario**, not results from the OpenID Foundation Java conformance
suite. The scenario targets PDPs; PDP responsibilities are not counted as PEP passes.

The normative reference is [Authorization API 1.0 Final](https://openid.net/specs/authorization-api-1_0.html).
The scenario revision is pinned to prevent silent changes to expectations.
References use upstream `c-...` anchors rather than rendered section numbers.

## Running the tests

```sh
bundle exec rake test
bash script/test-opa official
```

The second command downloads a checksum-pinned OPA AuthZEN plugin 0.8.0 binary for
Linux x86_64 and loads a dedicated Rego fixture implementing the eight decision
rules and S1-S6. It is separate from the basic OPA fixture. The runner stops its
process on exit and is included in the CI OPA job.

For an existing test PDP loaded with the same fixture:

```sh
OFFICIAL_PDP_URL=http://127.0.0.1:18181 bundle exec ruby -Itest test/integration/official_scenario_test.rb
```

Only an unset URL skips tests. This runner additionally checks OPA's multipage
support, so an external PDP must support pagination too, although the official
scenario allows it to be absent. Local HTTP integration and TLS unit tests are
separate evidence.

The September 22, 2026 baseline on Ruby 3.2.1 recorded **35 integration tests / 152
assertions**, with no failures, errors, or skips. All 31 JSON request fixtures were
checked for structural equality with the pinned source. Scenario-specific unit
checks passed **12 tests / 46 assertions**; the full unit baseline was **65 tests /
237 assertions**. These counts are not official case or certification pass counts.

## Coverage matrix

- **Live:** official requests and expected results exercised through the gem against the dedicated OPA fixture.
- **PEP:** corresponding client-side input/response checks, not execution of the official PDP test.
- **Out of scope:** PDP server behavior, excluded from this gem's pass count.
- **Partial:** tested subset with exclusions stated explicitly.

`I` means `test/integration/official_scenario_test.rb`; `U` means
`test/official_scenario_test.rb`. Their test names retain case IDs. Other references
name existing regression tests under `test/`.

| Official ID | Coverage | Evidence and boundary |
| --- | --- | --- |
| c-1-4 / c-1-5 | Live | I: eight decision rules and S1-S6; test-only policy |
| c-2-1 / c-3-1 / c-4-1 | Live / PEP | I; `search_test.rb#test_each_search_uses_its_own_schema_and_path`; `discovery_test.rb#test_discovered_client_uses_advertised_nonstandard_urls` |
| c-2-2-1 through c-2-2-8 | Live | I: allow, deny, context, and entity properties |
| c-2-2-9 | Out of scope | PDP ignores unknown top-level request fields. The typed client has no API to send them. U checks that unknown response fields do not affect decisions |
| c-2-3-1 / c-2-3-2 | PEP | U: decision presence/type and context shape/preservation; malformed JSON in `client_test.rb#test_rejects_non_boolean_or_missing_decisions` |
| c-2-4-1 / c-2-4-2 / c-2-4-6 | PEP | U: missing fields/sub-fields and invalid types rejected before HTTP. PDP generation of HTTP 400 is out of scope |
| c-2-4-3 / c-2-4-4 / c-2-4-5 | Out of scope | PDP handling of invalid Content-Type, malformed JSON, and empty bodies. The gem generates JSON objects. Received HTTP 400 is covered by `client_test.rb#test_http_errors_and_redirects_never_authorize` |
| c-2-5-1 | Partial | U: explicit X-Request-ID sent. Server echo is not checked; the client does not expose response headers |
| c-2-5-2 | Out of scope | PDP acceptance without a request ID. Client-generated IDs are tested in `client_test.rb#test_serializes_authzen_request_and_preserves_endpoint_and_headers` |
| c-2-6 | Live | I: repeated identical fixture requests |
| c-3-2-1 through c-3-2-7 | Live | I: independent items, defaults, properties, context inheritance, whole-object replacement |
| c-3-3-1 through c-3-3-4 | Live / PEP | I and U: decision order, count, and types; top-level decision does not override individual results |
| c-3-4-1 | Partial | U: preserve individual false/error responses. The official resource-less item is rejected by client input validation, not sent to a PDP |
| c-3-4-2 / c-3-4-3 | Live / PEP | I: absent/empty evaluations; `evaluations_test.rb#test_absent_and_empty_evaluations_support_single_response` accepts a single decision or one-element array |
| c-4-2-1 through c-4-2-4 | Live | I: subject search, context, ignored target ID, resource properties |
| c-4-3-1 through c-4-3-4 | Live | I: resource search, context, ignored target ID, subject properties |
| c-4-4-1 through c-4-4-3 | Live | I: action search, context, properties |
| c-4-5-1 / c-4-5-2 | Live | I: limit and opaque token, with additional multipage checks |
| c-4-5-3 | Live / PEP | I; `search_test.rb#test_invalid_search_responses_are_rejected`: page/token/count/total types and termination |
| c-4-5-4 | PEP | U: accept unpaginated results, absent page, empty token, and ignored limit |
| c-4-6-1 / c-4-6-2 | Live | I: empty results for unknown identifiers/types |
| c-4-7-1 / c-4-7-2 | PEP | U: required search fields/sub-fields rejected before HTTP. PDP generation of HTTP 400 is out of scope |
| c-5 | Partial | `tls_test.rb`: CA/hostname verification and explicit HTTP opt-in. U: JSON and ID. PDP unknown-field handling and header echo are out of scope |
| c-6-1 | PEP | `discovery_test.rb#test_configuration_inserts_well_known_before_tenant_path`: GET and tenant path |
| c-6-2 / c-6-3 | PEP | `discovery_test.rb#test_malformed_metadata_is_rejected` and `test_discovery_rejects_non_json_content_type`: required values, URLs, JSON types |
| c-6-4 / c-6-5 | Partial | `discovery_test.rb`: optional endpoints/capabilities, exact identity, unknown fields. Signed metadata is intentionally unsupported, not verified |
| c-6-6 | PEP | U: discovery 404 raises; an explicit nondiscovery configuration can use default paths |

## Adaptations and limits

- **Pagination is optional (c-4-5-4).** Ignoring `limit` and returning all results with an empty token is permitted. This describes Topaz's search behavior, independently of its short-circuit incompatibility.
- **Stable pagination query:** the c-4-5-2 example omits the initial `limit`; our follow-up preserves all values except the token, following Final Section 8.2.1.
- **Search matching:** official expectations require inclusion, not an exact result set. Adding context or a search-target ID must also leave the baseline results unchanged.
- **Signed metadata:** the PDP scenario includes signature checks; this PEP intentionally does not implement the optional feature, as allowed by Final Section 9.1.3.
- **Suite boundary:** this matrix maps the pinned WG scenario, not every GitLab conformance-suite module.

## Updating the source

Update the commit and SHA-256, compare added/removed `c-...` anchors, request JSON,
and expected results, then update the matrix and tests or record a coverage gap.
Run CI before claiming new coverage. Tests never fetch expectations from `main`
at runtime.
