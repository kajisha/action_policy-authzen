# action_policy-authzen

Use OpenID AuthZEN authorization services from Action Policy rules and scopes.
This Ruby gem is a **PEP-side client** for Authorization API 1.0: single and batch
evaluation, subject/resource/action search, pagination, and PDP discovery.
It is not a PDP server or an OpenID Certified implementation.

See [conformance and limitations](docs/conformance.md) and
[official scenario coverage](docs/official-scenarios.md).

## Installation

Requires Ruby 3.3 or later. This gem has not yet been published to RubyGems.
Until release, use a local checkout:

```ruby
gem "action_policy-authzen", path: "/path/to/action_policy-authzen"
```

For development:

```sh
bundle install
bundle exec rake test
```

## Action Policy integration

```ruby
require "action_policy/authzen"

class DocumentPolicy < ActionPolicy::Base
  include ActionPolicy::AuthZEN::Policy

  def show?
    authzen_allowed?(
      subject: {type: "user", id: user.id.to_s},
      action: "reader",
      resource: {type: "document", id: record.id.to_s}
    )
  end
end

client = ActionPolicy::AuthZEN::Client.new(
  endpoint: ENV.fetch("AUTHZEN_EVALUATION_URL"),
  headers: {"Authorization" => "Bearer #{ENV.fetch('AUTHZEN_TOKEN')}"},
  open_timeout: 2,
  read_timeout: 5
)

policy = DocumentPolicy.new(document, user: current_user, authzen_client: client)
policy.apply(:show?)
```

In a Rails controller, pass the client through Action Policy's authorization context:

```ruby
authorize! document, to: :show?, context: {authzen_client: client}
```

Map entity types, IDs, and actions explicitly. There is no automatic mapping from
`show?` to `reader`. With OpenFGA, `action.name` must match a model relation.
Entity `properties` and request `context` are supported; construct them from
trusted application data.

## Decisions and errors

`allowed?(subject:, action:, resource:, context: nil)` returns a boolean.
`evaluate(...)` returns a Hash with string keys, including optional decision
context. Applications must interpret obligations; `allowed?` does not execute them.

The client requires HTTP 200, JSON content, and boolean decisions. Failures raise:

| Exception | Meaning |
| --- | --- |
| `ActionPolicy::AuthZEN::HTTPError` | Non-200 response, including redirects; exposes `status` |
| `ActionPolicy::AuthZEN::InvalidResponse` | Invalid JSON, decision, context, search result, or metadata |
| `ActionPolicy::AuthZEN::TransportError` | Connection, TLS, or timeout failure |
| `ActionPolicy::AuthZEN::UnsupportedEndpoint` | Optional endpoint missing from discovered metadata |
| `ArgumentError` | Invalid request, URL, or timeout |

Exceptions propagate through policies. Never convert a transport failure into an
allow decision: deny access or report service unavailability. The client does not
follow redirects or retry requests. Error messages omit response bodies and
authentication headers.

HTTPS and certificate/hostname verification are enabled by default. Configure a
private CA with `ca_file: "/path/to/ca.pem"`. Use `allow_http: true` only for local
tests, and configure the authentication required by your production PDP.

The gem adds no cache. Action Policy's rule caching still applies; consider policy
instance lifetime and cache settings when permissions change.

## Discovery and endpoints

`endpoint:` specifies a single evaluation URL. Use `base_url:` for all APIs or
discover the PDP's advertised endpoints:

```ruby
client = ActionPolicy::AuthZEN::Client.new(base_url: "https://pdp.example.com/tenant")

client = ActionPolicy::AuthZEN::Client.discover(
  base_url: "https://pdp.example.com/tenant",
  headers: {"Authorization" => "Bearer #{ENV.fetch('AUTHZEN_TOKEN')}"}
)
client.metadata
```

Discovery requests `/.well-known/authzen-configuration/tenant`, checks exact PDP
identity and endpoint URLs, and installs the advertised endpoints. Missing optional
endpoints raise `UnsupportedEndpoint`. Without discovery, `base_url:` uses standard
paths. Override individual URLs with
`endpoints: {evaluations: "https://pdp.example.com/custom/batch"}`.

Cross-origin discovery endpoints require an explicit
`trusted_origins: ["https://other-pdp.example.com"]` allowlist before credentials
can be forwarded. Optional `signed_metadata` is ignored; only plain JSON metadata
is used, without any claim of signature verification.

## Batch evaluation

```ruby
result = client.evaluations(
  subject: {type: "user", id: "anne"},
  resource: {type: "document", id: "roadmap"},
  evaluations: [{action: "reader"}, {action: "writer"}],
  options: {evaluations_semantic: "execute_all"}
)
decisions = result.fetch("evaluations").map { |entry| entry.fetch("decision") }
```

Supported semantics are `execute_all`, `deny_on_first_deny`, and
`permit_on_first_permit`. Response cardinality, boolean types, and short-circuit
positions are validated. Individual context is preserved. Per-item values replace
top-level defaults as **whole objects**, not merged sub-fields.

Absent or empty `evaluations` requests a single evaluation using the defaults.
Depending on the PDP, the response contains a single `decision` or a one-element
`evaluations` array. Nonempty requests always require an `evaluations` response.

In policies, use `authzen_evaluations(...)`. Do not return its Hash as a boolean
rule result; explicitly aggregate individual decisions with `all?` or `any?` as
appropriate.

## Search and pagination

```ruby
client.search_subjects(subject: {type: "user"}, action: "reader",
  resource: {type: "document", id: "roadmap"})
client.search_actions(subject: {type: "user", id: "anne"},
  resource: {type: "document", id: "roadmap"})

client.each_resource(subject: {type: "user", id: "anne"}, action: "reader",
  resource: {type: "document"}, page: {limit: 100}).each do |resource|
  puts resource.fetch("id")
end
```

`search_subjects`, `search_resources`, and `search_actions` return one response
Hash. `each_subject`, `each_resource`, and `each_action` accept a block or return
an Enumerator. They preserve query conditions and follow opaque tokens, rejecting
token cycles and malformed responses. Results are not deduplicated; reauthorize
before acting because permissions may change after a search.

Policy helpers use the `authzen_` prefix and are private. For example:

```ruby
scope_for :array do |records|
  ids = authzen_each_resource(subject: {type: "user", id: user.id.to_s},
    action: "reader", resource: {type: "document"}).map { |entry| entry.fetch("id") }
  records.select { |record| ids.include?(record.id.to_s) }
end
```

Consider result size before collecting IDs in memory or constructing database scopes.

## Integration tests

Use isolated test services, never production PDPs. OpenFGA 1.21.0 runs with
`--experimentals=authzen`, in-memory storage, and a loopback HTTP port:

```sh
docker compose up -d
OPENFGA_URL=http://127.0.0.1:18080 bundle exec rake integration
docker compose down
```

Tests create and remove their own store, model, and tuples through OpenFGA's native
API, then verify AuthZEN decisions and native Check parity. Client evaluation URLs
include the store, for example
`http://127.0.0.1:18080/stores/STORE_ID/access/v1/evaluation`. Pass the model ID in
`headers: {"Openfga-Authorization-Model-Id" => model_id}` and enable `allow_http`
for this local setup. Experimental APIs may change; test versions are pinned.

Linux x86_64 runners download pinned official binaries, start a local PDP, run its
tests, and stop the process. They require installed gems, `curl`, `unzip`, and
`sha256sum`:

```sh
bash script/test-opa
bash script/test-topaz
bash script/test-opa official
```

OPA AuthZEN plugin 0.8.0 is a separate OPA extension. It covers all APIs,
short-circuit evaluation, and paginated searches. Topaz 0.33.20 ignores
short-circuit options; tests check that the client rejects those responses.
Its unpaginated search is permitted by the official scenario.

OPA uses `OPA_PORT` (default `18181`). Topaz uses `TOPAZ_URL` (default
`http://127.0.0.1:18383`) and `TOPAZ_GRPC` (default `127.0.0.1:19292`). Logs and
test data remain under `/tmp/action-policy-authzen-*`. Tests skip only when their
PDP URL is unset; unavailable configured services fail the tests.

The `official` runner uses a separate fixture based on the pinned OpenID AuthZEN
WG scenario. [Case IDs, source provenance, and exclusions](docs/official-scenarios.md)
are recorded explicitly. These are project-owned tests, not a run of the official
conformance suite or a certification. CI includes all three PDPs and the scenario runner.

## License

[MIT](LICENSE.txt), the same license as
[Action Policy](https://github.com/palkan/action_policy/blob/v0.7.7/LICENSE.txt).
Vendored Topaz test fixtures retain their Apache-2.0 license and attribution in
`test/fixtures/topaz/LICENSE` and `test/fixtures/topaz/PROVENANCE.md`.
