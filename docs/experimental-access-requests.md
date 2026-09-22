# Experimental access requests

The access-request API is an opt-in, single-item requester implementation of the
[AuthZEN Access Request and Approval Profile draft](https://github.com/openid/authzen/blob/6ed00bad5daa8f6eef6f2aef1f124442beeb8382/profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md),
pinned to commit `6ed00bad5daa8f6eef6f2aef1f124442beeb8382`. Its Ruby API can change
between releases. This is a subset of a draft, not full profile conformance or
certification.

Load it explicitly:

```ruby
require "action_policy/authzen"
require "action_policy/authzen/experimental"
```

The normal `require "action_policy/authzen"` does not load experimental features.
There is no global enable flag and no experimental helper added to Action Policy.

## Requester flow

An ordinary PDP evaluation remains authoritative. If it returns a requestable
denial, application service code may explicitly submit an access request. A
successful submission returns a task, which can complete immediately or be
retrieved later. An approved task supplies an approval reference for a fresh PDP
evaluation; approval alone never permits the operation.

Keep this workflow outside policy rules. Ruby considers every offer, task, and
result object truthy. Returning one from a policy method can accidentally allow
access. Use the core client's boolean authorization result for permission checks.

Configure a separate client for the approval service:

```ruby
pdp = ActionPolicy::AuthZEN::Client.discover(
  base_url: ENV.fetch("AUTHZEN_PDP_URL"),
  headers: {"Authorization" => "Bearer #{ENV.fetch('AUTHZEN_PDP_TOKEN')}"}
)

access_requests = ActionPolicy::AuthZEN::Experimental::AccessRequests.new(
  metadata: pdp.metadata,
  submission_url: ENV.fetch("AUTHZEN_ACCESS_REQUEST_URL"),
  status_url_prefix: ENV.fetch("AUTHZEN_TASK_STATUS_URL_PREFIX"),
  service_headers: {
    "Authorization" => "Bearer #{ENV.fetch('AUTHZEN_ACCESS_REQUEST_TOKEN')}"
  },
  topology: :independent
)
```

The URLs are deployment-owned configuration, not values accepted from an end
user. Use `topology: :shared_state` only when the approval service can resolve the
PDP's evaluation IDs. The independent topology requires an opaque binding token.

The application can interpret a denial without making another HTTP request:

```ruby
decision = pdp.evaluate(**request)
if decision.fetch("decision") == false
  offer = access_requests.offer_for(request: request, response: decision)
  # nil: ordinary denial; there is no supported requestable offer.
end
```

In a separate, application-initiated submission action, using that offer:

```ruby
receipt = access_requests.create(
  offer: offer,
  idempotency_key: submission_key # retain with this exact submission
)
```

An approved creation response needs no status fetch. For a pending task, the
application schedules `access_requests.fetch(receipt: receipt)` no earlier than
`receipt.earliest_next_fetch_at`, when present, and before task expiry. Use the
returned state for subsequent operations. The gem never schedules this itself.

After approval, build the re-evaluation input and perform a fresh authorization:

```ruby
retry_request = access_requests.reevaluation_request(
  state: state, # or the receipt, if creation completed synchronously
  request: current_request
)
permitted = pdp.allowed?(**retry_request)
# Only permitted == true can allow the actual operation.
```

The request builder rejects pending, unsupported, or expired approval. In this
initial subset, `current_request` must match the original subject, resource,
action, and complete context after JSON key normalization. This deliberately
rejects changed tenant, properties, operation parameters, and volatile context
values; a changed operation needs an ordinary fresh evaluation and, if needed,
a new access request. Broader approval-scope matching is not implemented locally.
Preserve the authenticated requester and use the same PDP for re-evaluation.
The returned request uses symbol keys at the top level so it can be passed
directly to `pdp.allowed?(**retry_request)`, including when the input came from JSON.

Offers and states are immutable handles belonging to the `AccessRequests`
instance that issued them. Keep that instance for the in-process workflow;
handles from another instance or hand-built objects are not accepted.

## Service trust

PDP metadata advertises the access-request endpoint. A requestable denial may
override it. Configure the permitted submission endpoint and status URL namespace
explicitly, and give the access-request client its own service credentials.
PDP headers are not a credential grant to another service.

Status retrieval uses the returned `task.status_endpoint` after validation, not a
URL derived from the task ID or the HTTP `Location` header. Redirects and URLs
outside the configured purpose/path are rejected. This initial subset excludes
query-bearing task URLs, including signed query links, and percent-encoded paths.
Configure a status namespace such as `https://approval.example/tasks/`; only one
task path segment below that namespace is supported. A missing trailing slash on
the configured namespace is normalized to a segment boundary.

The client carries a denial binding token unchanged to the access-request
service, and carries the approval object unchanged to the PDP for re-evaluation.
The receiving services verify these artifacts. The gem does not decode tokens,
fetch signing keys, or treat an approval ID as a bearer permission.

## Timing, errors, and persistence

The application initiates every request. There is no automatic polling, retry,
callback, or browser navigation. Respect retry timing and expiration, and avoid
reusing a cached Action Policy decision after approval. Current policy, revocation,
and operation context can still cause the fresh PDP evaluation to deny access.

HTTP failures raise `ActionPolicy::AuthZEN::Experimental::HTTPError`, a subclass
of the core `HTTPError`. It exposes `status`, a recognized `problem_type` when
available, and `retry_after` as an absolute `Time` when the service supplies it.
Unrecognized problem types are omitted. Response bodies and problem descriptions
are not included in these errors. Retry timing does not trigger another request.

A submission timeout has an ambiguous outcome: the service might already have
created the task. Persist a submission's idempotency key with its exact request if
the application needs to retry deliberately. Server support determines whether
the key prevents duplicates; the gem does not retry automatically.

Task expiry limits task retrieval. Approval expiry limits use of the approval;
these are different clocks. Recheck at the execution boundary and honor any
shorter validity returned by the PDP. Request construction and business execution
are not atomic.

The first release supports in-process handles. Durable restoration across process
restarts is not part of this API. Applications requiring long-lived persistent
approval workflows should account for that limitation before adoption.

## Supported subset

- Single-item offers without required form/schema/catalog augmentation.
- Explicit creation, one-shot status retrieval, and re-evaluation request building.
- Shared-state denial references and opaque binding-token transport.
- Pending and terminal task states, including immediate completion.
- Opaque approval-state preservation and current-expiry checks.

Bundles, forms/catalogs, callbacks, cancellation, broader-scope matching,
automatic follow-up actions, and approval UI are outside this initial subset.
Unknown states and completion modes never become usable approval references.
COAZ and shadow evaluation are not implemented by this feature.

See the [design and adversarial review record](experimental-features-design.md)
for the planned boundaries and acceptance criteria.
