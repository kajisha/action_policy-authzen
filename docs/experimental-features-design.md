# Experimental COAZ, access requests, and Dry Run

Status: design accepted after independent Astra adversarial review. The AARP
requester subset is now implemented; see the
[access-request guide](experimental-access-requests.md) for its actual API and
limits. COAZ and shadow evaluation remain proposals. Written 2026-09-23 against
repository baseline `d4d688c`. Public API examples below are proposals, not working
library calls unless documented in the access-request guide. Adversarial review
and source pinning are recorded at the end.

## Outcome and boundaries

Design opt-in experiments toward mapping operations into AuthZEN requests (COAZ),
requesting approval after an eligible denial (AARP / Access Request and Approval
Profile), and comparing candidate evaluations without using them to authorize
execution (the gem-local interpretation of Dry Run). The first COAZ delivery is
only a static envelope utility; input-dependent mapping is a later milestone.
The stable Authorization API 1.0 client remains usable on its own.

This design covers the PEP/requester side. It does not add a PDP, approval UI,
approval decision service, background worker, MCP server, or expression-language
runtime. It adds no runtime dependencies. A feature's standard-conformance claim
must be narrower than or equal to its tested, pinned specification coverage.

## Existing implementation constraints

| Evidence | Implication |
| --- | --- |
| `lib/action_policy/authzen/client.rb:78` returns the full evaluation response; `:84` extracts the boolean in `allowed?` | Existing response context can carry extension data, but a boolean helper cannot express approval or simulation semantics. |
| `lib/action_policy/authzen/client.rb:170` builds batch payloads and `:195` selects item fields | New extension fields need deliberate validation and serialization; generic pass-through is insufficient. |
| `lib/action_policy/authzen/client.rb:249` only accepts HTTP 200 for POST | Approval endpoint methods/status codes need their own operation contracts. Do not relax evaluation HTTP handling globally. |
| `lib/action_policy/authzen/client.rb:279` configures TLS, timeouts, and disables retries | Experimental HTTP should retain those properties. |
| `lib/action_policy/authzen/client.rb:455` validates only known core discovery endpoints | Preserving an unknown metadata field does not make its URL trusted or its feature supported. |
| `lib/action_policy/authzen/policy.rb:14` and `:46` delegate to the core client | Keep network workflow side effects out of policy rules and their caching. |
| `lib/action_policy/authzen.rb:1`, `action_policy-authzen.gemspec:13` | A separate require path can ship inside the existing gem without automatic activation or another package. |
| `test/support/pdp_server.rb:4`, `test/discovery_test.rb:87`, `test/tls_test.rb` | Reuse existing HTTP/TLS testing patterns; extend the test helper only where new response headers/statuses require it. |

## Decision

Choose composition in an explicitly loaded namespace:

```ruby
require "action_policy/authzen"
require "action_policy/authzen/experimental"

# Construction is not activation of a global mode.
# Each experimental operation is invoked explicitly by application code.
```

The ordinary require must not define or load `ActionPolicy::AuthZEN::Experimental`.
Loading experimental code must not monkey-patch `Client`, `Policy`, their method
signatures, discovery endpoint constants, or default behavior. No global
`experimental = true` or mutable per-client `dry_run` toggle.

Each feature owns its small contract and validation. Avoid a plugin registry,
generic workflow engine, or new universal result abstraction. Transport reuse is
allowed only through a narrowly scoped internal extraction with characterization
tests proving unchanged core wire behavior. New transport operations declare their
allowed status codes instead of broadening the core client's accepted responses.

Alternatives:

| Option | Benefit | Cost / decision |
| --- | --- | --- |
| Add switches and approval methods directly to `Client` | Small initial diff | Reject: unstable protocols and workflow side effects become part of the stable interface. |
| Explicit experimental namespace in this gem | Shared transport and install experience; clear opt-in | Chosen: requires careful require-path and regression tests. |
| Separate gems | Independent release cadence and dependency choices | Defer: unnecessary packaging burden while the public contracts are being tested. Revisit for a CEL runtime or MCP integration. |

## Common safety and compatibility contracts

1. Only an ordinary, fresh evaluation of the actual operation can authorize it.
   Approval, successful mapping, and a comparison report are not authorization.
2. Experimental methods perform no implicit approval submission, retry, polling,
   redirect, browser navigation, business operation, or obligation execution.
3. Inputs and parsed results are copied into owned JSON-compatible structures;
   reject conflicting string/symbol keys before normalization. Store immutable
   snapshots where a later method relies on earlier request/response identity.
4. Support is explicit and versioned in the gem's documentation/fixtures, not via
   an invented wire-version negotiation field. Discovery is evidence of advertised support,
   not evidence that a server implements it correctly. Do not infer support from a
   successful core evaluation. Missing prerequisites fail before a write request.
5. HTTPS, certificate/hostname verification, bounded timeouts, and zero automatic
   retries remain the default. Local HTTP requires the existing explicit opt-in.
6. Extension links and capability values are untrusted response data. Do not use
   core `trusted_origins` as an implicit credential grant to an approval service.
7. No request bodies, response bodies, approval links, tokens, subject properties,
   or operation arguments are logged by default. Errors identify the operation and
   validation problem without embedding sensitive values.

Ruby has no way to make an arbitrary object falsey. Every offer, receipt, mapping,
and comparison report is truthy, even when it represents denial or an error. Do
not return these objects from Action Policy rules or use them in an `if` as a
permission check. This design prevents accidental integration through the gem's
provided helpers; it cannot prevent application code from misusing a Ruby object.
Experimental result types expose no `allowed?`, `permit?`, `authorized?`, or
`decision` methods. Examples place workflow/observation in application services,
outside `Policy`, and use only explicit core booleans for authorization.

## COAZ experiment

Proposed API surface: `Experimental::COAZ::Mapping` performs pure mapping;
application code passes its validated output to the core `evaluate`/`evaluations`
methods. Mapping does not make an HTTP request or execute the source operation.

Initial scope is an explicitly documented static-envelope subset of the pinned COAZ Framework:
literal mapping values and the request envelope shapes supported by that subset.
Reject expressions and unrecognized mapping constructs before contacting a PDP.
Do not evaluate strings using Ruby `eval`, interpolate Ruby templates, or silently
interpret unsupported CEL as a literal. Any literal subset must use the draft's
actual literal syntax, with wire fixtures copied from the pinned source.

This first slice is useful as a deterministic envelope/validation foundation; it
does not claim complete COAZ support. Dynamic CEL evaluation and COAZ-MCP Binding
are separate milestones. Adding a dependency or claiming full Framework/MCP
conformance requires a subsequent design decision and the applicable tests.

Proposed method: `Mapping#render` returns a value with an explicit
`operation` (`:evaluation` or `:evaluations`) and validated `payload`. It exposes
no `allowed?` helper. Because this slice has no expressions it takes no `inputs:`
argument: it must not suggest that runtime identity is being mapped. The application supplies
the mapping from trusted configuration; remote requests cannot supply mapping
definitions or override trusted identity. Missing/wrongly typed mapped fields and invalid
SARC output raise `MappingError`; no partial batch is sent.

For future MCP support, identity comes from authenticated server context, never
from tool arguments. Mapping and execution must use the same immutable operation
snapshot, including tool name, arguments, server identity, and relevant tenant.
Authorization is repeated when any of those change. The initial experiment does
not provide an MCP interception or enforcement guarantee.

Pinned mapping contract:

- Exactly one envelope key: `evaluation` or `evaluations`; zero/multiple/unknown
  keys fail. The contained object follows the corresponding core request schema.
- Walk JSON mapping values recursively. A leading `$$` becomes one literal `$`;
  a leading single `$` is an unsupported expression and fails; interior `$` is
  ordinary text. Do not evaluate the unescaped output a second time.
- Entity custom fields live in `properties`; arbitrary siblings fail. `context`
  remains a JSON object. Batch override is whole-object replacement as in the
  core API, not a recursive merge. No automatic batch-to-single fallback.
- Output is an owned frozen JSON value. The caller explicitly converts the
  top-level payload to the keyword form expected by the core client; document
  the adapter example with `payload.transform_keys(&:to_sym)`. Entity keys remain
  strings. No generic `send(operation, ...)` of unvalidated input.
- This literal-only milestone has limited standalone utility: deterministic
  fixture/validation and preview, not dynamic application integration. Full COAZ
  is a separate dependency-and-binding decision, not a promised release criterion.

## Access request / approval experiment

Use descriptive Ruby names (`Experimental::AccessRequests`) rather than baking
the changing AARP/ARAP abbreviation into the public API.

The client exposes explicit requester operations: interpret an eligible denial,
create an access request, and fetch its current state. An approved state is a
workflow result, never a permission. The application subsequently re-evaluates
the current intended operation through the core client.

Proposed API shape (exact wire details must match the source contract below):

```ruby
decision = client.evaluate(**request)
offer = access_requests.offer_for(request: request, response: decision)
# nil means a valid ordinary denial with no supported approval offer.

# Application initiates submission outside its Action Policy rule.
receipt = access_requests.create(offer: offer, idempotency_key: submission_key)
state = access_requests.fetch(receipt: receipt)

# This builder is pure and rejects non-approved or expired results.
retry_request = access_requests.reevaluation_request(state: state, request: request)
# At execution time use a fresh evaluation, not a cached Action Policy instance.
permitted = client.allowed?(**retry_request)
```

`offer_for` requires `decision == false`. A malformed advertised offer raises
`InvalidResponse`; an absent offer produces `nil`. Unsupported mandatory features
raise `UnsupportedFeature`. Both cases leave the denial intact. Validated offers
and receipts retain immutable snapshots and service identity; bare arbitrary URLs
are not accepted by `create` or `fetch`.

Configure approval-service endpoints and credentials separately from PDP headers.
Allow only configured service origins AND endpoint paths, without credentials or
fragments in URLs. Configure an exact submission URL and an approved status URL
path namespace with segment boundaries, independently: the spec does not require
status URLs to be under the submission collection. Use the returned
`task.status_endpoint` verbatim after validation, never reconstruct it from
`task.id`. Reject dot segments, encoded slashes/backslashes/traversal, queries, and
noncanonical URL forms in this first subset. This deliberately excludes servers
using signed query URLs. Same-origin alone is insufficient: a response could target an
unrelated administrative path on the same service. Do not follow redirects.
Cross-origin services require their own explicit configuration and credentials;
they never inherit the PDP Authorization header.

The application owns UI consent, persistence, scheduling, expiration, and bounded
polling. The gem does one operation per method call. A timeout during creation has
an ambiguous outcome: raise a transport error, never retry automatically or claim
that no request was created. Accept a caller-owned `idempotency_key:` and send it
as `Idempotency-Key`, as recommended by the pinned profile; the application must
persist it with the exact submission and reuse it only for that submission.
Header values reject CR/LF. A key is not a guarantee of server deduplication.
HTTP errors and unknown states are not approval or permission.

### Pinned single-item requester contract

| Operation/data | Contract for the first experiment |
| --- | --- |
| Discovery | Recognize `access_request_endpoint`; `urn:openid:authzen:capability:access-request` is a SHOULD advertisement, so its absence alone is not rejection. Validate extension endpoints independently of the core metadata parser. Require an explicitly supplied, validated metadata snapshot and approval-service configuration; construction does no discovery HTTP. |
| Offer endpoint | Denial's `context.access_request.endpoint` takes precedence over metadata. If that endpoint is outside configured trust, reject instead of falling back to metadata. |
| Offer freshness/binding | Require RFC3339 `context.access_request.expires_at` and at least `binding_token` or `context.evaluation_id`. Reject an expired offer before submission using an injectable clock and no positive clock-skew grace. `binding_token` is authoritative when present and echoed byte-for-byte, never decoded. Service configuration declares shared-state or independent topology; independent requires a token, not an evaluation ID alone. |
| Submission | POST one original `subject`, `resource`, `action`, original request `context` if present, and a `denial` object. Copy denial expiry/token/template from `context.access_request`, plus evaluation ID/time/reason from response context where present. Do not send response context as original request context. |
| Optional inputs | First release omits `items`, callback, requested-access overrides, context augmentation, actor normalization, and arbitrary extra submission fields. Preserve original subject properties including actor data. If an offer requires schema/catalog augmentation (`request_schema_url` or `request_catalogs_url`), refuse submission with `UnsupportedFeature`; do not guess a form or fetch its URL. Display/form links are inert. This subset supports simple offers with no additional requested input. |
| Create response | Accept only 201/202 JSON objects with a valid `task`: string ID/status, HTTPS status endpoint, optional RFC3339 expiry. Handle synchronous approval in the create response without an obligatory fetch. Ignore `Location` as a navigation target; `task.status_endpoint` is authoritative. |
| Fetch | GET the validated authoritative status endpoint, accept 200 JSON. Preserve the original endpoint when a status response omits it (the draft's status examples omit it); if supplied, require it to match the original. Require matching task ID. Expose and honor a valid `Retry-After` (delta-seconds or HTTP-date) as an earliest-next-fetch time; reject premature fetch locally without sleeping. Do not auto-poll. |
| Task states | Recognize pending, approved, denied, expired, cancelled, failed. Preserve unknown states as not approved and unusable for re-evaluation. `partial` or any task `items` is unsupported in this single-item slice. Preserve unknown extension members without interpreting them. |
| Completion | Only approved + `result.mode == "reevaluate"` + valid approval object is eligible for request construction. Require approval string ID and RFC3339 `approved_until`; optional `approved_at` must be RFC3339. Preserve the entire approval object including the exact JSON value of `state`. Unknown completion modes remain inspectable but cannot be used. |
| Re-evaluation request | Pure builder, no network. Check eligibility and expiry at call time; copy the current request, reject an existing `context.approval`, and place the returned approval unchanged at `context.approval`. Bind the receipt to its service, original PDP identity, and original subject/tenant. Application must use that PDP and authenticated requester for the fresh check; never trust an arbitrary task ID from an end user. PDP validates approval scope/current policy/cryptographic proof. No cryptographic verification by this PEP. |
| Error handling | Preserve safe HTTP status and a recognized problem type for application recovery; do not embed response bodies in exception text. 404/410/409/429 are errors, never approval. Expose safe retry timing where provided. No automatic resubmission. |

An approval service's cryptographic verification of denial binding and a PDP's
verification of approval state remain server responsibilities. The PEP never
fetches `jwks_uri`. Copies and local receipt checks prevent accidental mixing;
they do not authenticate a response injected by trusted application code.

`task.expires_at` bounds status retrieval, while `approval.approved_until` bounds
approval reuse; neither implies the other. A non-expired approval can be revoked
and still requires current PDP evaluation. A builder-to-execution time gap is not
made atomic by this library. The application must check validity at the operation
boundary and bound any downstream credential lifetime by the earlier applicable
approval expiry, including a tighter expiry returned by the PDP.

Re-evaluation denials remain ordinary denials. The first slice returns their
context without executing `next_action`, retrying, or starting another workflow.
Full automatic profile processing, schema/catalog forms, bundles, callbacks,
cancellation, cross-PDP reuse, and durable receipt restoration are deferred.
This is a pinned requester subset, not full profile conformance.

## ShadowEvaluation experiment (Dry Run use case)

No official wire contract was located in the bounded source search. For this
design, interpret the user's Dry Run as a **gem-local shadow comparison**, with
the descriptive API name `Experimental::ShadowEvaluation`. This is a stated
product assumption, not an AuthZEN protocol claim. A zero-network preview or
vendor-specific Dry Run would be a different feature; no invented `dry_run`
request field, capability URN, or `DryRun#evaluate` is introduced.

```ruby
shadow = ActionPolicy::AuthZEN::Experimental::ShadowEvaluation.new(
  candidate_client: candidate_client
)
report = shadow.compare(primary_decision: primary_decision, request: request)
# Observe the report separately. Authorization uses primary_decision == true.
```

`primary_decision` must be exactly true or false, supplied from an already
completed authoritative check for the same immutable request snapshot. If the
primary failed, do not turn that error into an input or fall back to the candidate.
This API does not call the primary or execute the application operation.

`compare` makes exactly one ordinary core `evaluate` call to a separately
configured candidate client. It snapshots its input, never sets mutable flags on
either client, submits no access request, and executes no obligations. Batch and
search comparison are deferred. The report contains only `primary_outcome`
(`permit`/`deny`), `candidate_outcome` (`permit`/`deny`/`unavailable`), `comparison`
(`match`/`mismatch`/`unavailable`), and an optional safe error category/status. It
does not retain raw request/response context, secrets, or an enforceable decision.
No automatic logging or observer callback is invoked.

Candidate `ActionPolicy::AuthZEN::Error` failures become an unavailable report;
invalid local arguments and unrelated programming exceptions are not swallowed.
The application owns observation isolation, scheduling, sampling, and latency
budgets. This synchronous method can delay its caller by the candidate's network
timeouts; it cannot promise zero impact on application availability or latency.
Recommend calling it in an application-owned observational path that cannot
replace the already selected authoritative decision.

Only local business execution is excluded. The candidate receives a real request
and can log, meter, update server state, or otherwise have effects. Callers must
choose a suitable candidate service and data policy; this API provides no
server-side side-effect guarantee. A future actual Dry Run protocol would have
its own versioned adapter and integration evidence, not silently change this API.

## Verification and acceptance criteria

These are implementation gates, not claims that tests have run for this design.

| ID | Acceptance condition and evidence |
| --- | --- |
| E1 | In a fresh Ruby subprocess the normal require leaves `Experimental` undefined; opt-in require defines only the experimental API without changing stable public method ownership/signatures or adding Policy helpers. |
| E2 | All existing unit tests pass on supported Ruby 3.3, 3.4, and 4.0; core HTTP status, discovery, headers, and TLS contracts remain unchanged. |
| E3 | Constructors, mapping, offer parsing, and re-evaluation building issue zero requests; valid create/fetch issue exactly one request, including on timeout or redirect; invalid/pre-expiry-timing inputs issue zero. |
| E4 | An explicit misuse fixture demonstrates Ruby object truthiness; safe service examples authorize only core booleans. Experimental result types have no allowed?/permit?/authorized?/decision methods. This test documents misuse, not a nonexistent runtime truthiness guard. |
| C1 | Pinned literal mapping fixtures produce exact request envelopes; expressions, unknown constructs, conflicting keys, missing fields, and invalid batches fail before HTTP. |
| C2 | Mutating caller mappings after construction cannot change stored snapshots; failed mapping never yields a partially usable batch. `render(inputs:)` is rejected in the static-only API; escaped dollar fixtures decode exactly once. |
| A1 | Ordinary denial gives no offer; eligible denial gives an offer; malformed offer raises; an offer on permit cannot start a workflow. |
| A2 | Every supported lifecycle state has a fixture; pending/denied/expired/cancelled/failed/unknown state and approval alone never produce an authorization boolean. |
| A3 | Fixtures assert exact methods, paths, required fields, status codes, and identifiers for create/fetch against the pinned profile. |
| A4 | Different origin, wrong same-origin path, userinfo, fragments, encoded traversal, unexpected query, and redirect destinations receive no credentials and no follow-up request. |
| A5 | PDP and approval-service tokens are distinct in a two-server test; submission timeout produces exactly one attempted creation and a documented ambiguous outcome. |
| A6 | A fresh PDP denial after approval cannot execute the operation in the service example. Changed inputs are not authorized by the earlier response; current scope is evaluated by the PDP. Application state keeps subject/tenant and request identity together. |
| A7 | Expired denial, missing binding, independent service without token, required schema/catalog augmentation, mismatched task ID, unknown completion mode, and expired approval block the corresponding operation. Approval state preserves exact JSON structure and value; binding token preserves bytes. |
| A8 | Idempotency headers, synchronous approval, optional capability omission, authoritative endpoint precedence, Retry-After in both formats, and task-vs-approval expiry have positive/negative fixtures. A tighter PDP approval expiry is honored by the execution example. |
| D1 | Shadow makes exactly one candidate evaluation and zero primary evaluations; all four primary/candidate boolean combinations produce correct comparison and leave the independently enforced primary decision unchanged. |
| D2 | Candidate timeout/HTTP/invalid response produces unavailable, never fallback permission. No access request, obligation, callback, or application action is performed by comparison. Concurrent calls do not share request/context/flags. |
| D3 | No dry_run wire field is emitted; reports have only the documented safe fields and no raw context. Invalid primary nonbooleans fail before HTTP. Programming errors propagate, and examples isolate observation from enforcement. |
| O1 | Error/logging tests assert that fixture tokens, justifications, and sensitive operation arguments do not appear in messages. |

Use the existing Minitest/HTTP/TLS patterns rather than adding a new test framework.
Protocol fixtures prove client behavior; they do not prove a candidate PDP has no
side effects or implements approval persistence. Real interoperability claims require
an identified server/version and recorded integration evidence.

## Delivery plan

1. Pin official source revisions and complete feature wire-contract tables and
   scope claims in this document. Preserve unsupported portions explicitly.
2. Implement the require boundary and characterization tests, then extract only
   transport functionality actually required. Planned files:
   `lib/action_policy/authzen/experimental.rb`, feature files below
   `lib/action_policy/authzen/experimental/`, and, only if needed, an internal
   `lib/action_policy/authzen/http_transport.rb`.
3. Implement requester-side access request parsing and explicit create/fetch,
   with tests under `test/experimental_*_test.rb` and pinned fixtures under
   `test/fixtures/experimental/`. No automatic Policy helpers in this release.
4. Implement the COAZ literal subset and its negative fixture matrix. Keep CEL
   and MCP requirements visible as deferred rather than silently approximated.
5. Implement gem-local shadow comparison, labelled as the assumed Dry Run use
   case, with no protocol-conformance claim. Add per-feature experimental coverage to
   `docs/conformance.md` and opt-in examples to `README.md` when runtime code ships.
6. Run targeted tests, `bundle exec rake test`, Ruby syntax and gem build checks;
   run supported Ruby CI and existing PDP integration checks for any shared
   transport change. Add an experimental server integration only when a concrete
   compatible implementation is available. Report fixture-only gaps explicitly.

## Release policy and stop condition

All three features are independently opt-in and have independent coverage labels.
Pin each published experiment to a specification commit, not a moving “latest”.
Document breaking experimental API changes in release notes; do not imply stable
compatibility until separately promoted. Experimental support is not certification.

The original design task stopped at a reviewed design, a testable implementation
sequence, and unresolved protocol/dependency gates. The AARP requester subset has
since been implemented and is documented in the access-request guide. COAZ and
shadow evaluation remain unimplemented; no experiment has been published by this
task.

## Sources and review record

Source snapshot: OpenID AuthZEN commit
`6ed00bad5daa8f6eef6f2aef1f124442beeb8382`, retrieved 2026-09-23.

- [Official status index](https://openid.net/wg/authzen/specifications/): core API
  is final; COAZ and Access Request and Approval are Working Group Drafts.
- [Pinned COAZ Framework](https://github.com/openid/authzen/blob/6ed00bad5daa8f6eef6f2aef1f124442beeb8382/profiles/authzen-coaz-framework-1_0.md): Mapping, Literals and Expressions, Construction, and Trust-Anchored Fields sections.
- [Pinned Access Request and Approval Profile](https://github.com/openid/authzen/blob/6ed00bad5daa8f6eef6f2aef1f124442beeb8382/profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md): Discovery, Requestable Denial Context, Submission/Response, Task Status, Completion Semantics, and PEP Processing Rules.
- Dry Run evidence is bounded absence, not a claim that no proposal exists:
  research checked the snapshot's `api/`, `profiles/`, and README, plus official
  issue/PR searches for dry-run, dry_run, dry run, simulation, and simulate. No
  normative Dry Run wire contract was located. Revisit if a concrete source is supplied.

Independent review: `gpt-6-astra`, critic role, high reasoning, separate context.
First pass: **REVISE**. Second pass on the revised design: **ACCEPT**, with no
remaining blocker for the design-review stop condition. Acceptance is of the
design, not a claim that its implementation or interoperability is verified.

| Adversarial finding | Disposition |
| --- | --- |
| Literal-only COAZ cannot map runtime operation inputs | Removed `inputs:` and input-dependent claims; labelled the first slice as a static envelope utility. CEL/MCP remain a separate milestone. |
| Missing concrete approval wire semantics | Added the pinned requester contract, denial/approval preservation, expiry, Idempotency-Key, synchronous results, and status endpoint rules. |
| Approval/report objects can allow access through Ruby truthiness | Documented that Ruby cannot disable object truthiness; no experimental Policy helpers or permission-like result methods; explicit misuse fixture and safe service examples. |
| Authoritative URLs were not distinguished from trusted destinations | Separate service credentials and purpose-specific URL rules; validate and preserve the authoritative status URL rather than reconstructing it. |
| Dry Run implied an unverified protocol | Chose the explicitly stated gem-local shadow-comparison assumption, renamed the API, and documented ordinary HTTP, possible server effects, and latency limits. |

Both second-pass wording nits were applied: the shadow section uses its actual
API name, and static mapping validation refers to mapped fields rather than
runtime inputs. Retained scope choices: no dynamic COAZ/CEL, no full approval
profile, no server-side Dry Run guarantee, and no real experimental server
interop evidence yet. Revisit the shadow assumption if the user supplies another
Dry Run use case or a concrete proposal.

### AARP implementation review

The single-item requester implementation was developed by a separate
`gpt-5.6-terra` executor using failing tests before repairs. A separate
`gpt-6-astra` architect reviewed the implementation adversarially. Its initial
request for changes covered request binding, immutable issued handles, request
validation, response media types, timestamps, URL boundaries, and duplicate JSON
keys. Follow-up review also required keyword-compatible re-evaluation output.
These findings were fixed with regression tests; final verdict: **ACCEPT**, with
no remaining blocker in the reviewed subset.

Final local verification on Ruby 3.3.5: 103 tests, 422 assertions, no failures or
errors; experimental line coverage 96.21% and branch coverage 80.56%. Gem build
and Ruby syntax checks passed. This remains fixture-based client verification,
not approval-service interoperability or certification.
