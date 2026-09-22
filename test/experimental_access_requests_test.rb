require_relative "test_helper"
require "open3"
require "rbconfig"
require "socket"
require "timeout"

class ExperimentalAccessRequestsTest < Minitest::Test
  REQUEST = {
    subject: {type: "user", id: "alice@example.com", properties: {act: {sub: "agent-7", iss: "agents.example"}}},
    action: "can_read",
    resource: {type: "document", id: "q4-plan"},
    context: {business_justification: "Needed for customer renewal review"}
  }.freeze

  DENIAL = {
    "decision" => false,
    "context" => {
      "evaluation_id" => "eval_01HX4Y2P8BQ4Y3F0V0K9D6Z7M1",
      "evaluated_at" => "2026-04-30T20:15:00Z",
      "reason" => "approval_required",
      "access_request" => {
        "expires_at" => "2026-04-30T20:25:00Z",
        "binding_token" => "opaque-binding-token",
        "template" => "manager_approval"
      }
    }
  }.freeze

  def setup
    @now = Time.utc(2026, 4, 30, 20, 16, 0)
  end

  def test_core_require_does_not_load_experimental_namespace
    stdout, stderr, status = Open3.capture3(
      RbConfig.ruby,
      "-Ilib",
      "-e",
      "require 'action_policy/authzen'; exit(ActionPolicy::AuthZEN.const_defined?(:Experimental, false) ? 1 : 0)"
    )

    assert status.success?, "expected ordinary require to avoid experimental namespace; stdout=#{stdout.inspect} stderr=#{stderr.inspect}"
  end

  def test_explicit_require_loads_access_request_experiment
    require "action_policy/authzen/experimental"

    assert ActionPolicy::AuthZEN.const_defined?(:Experimental, false)
    assert ActionPolicy::AuthZEN::Experimental.const_defined?(:AccessRequests, false)
  end

  def test_offer_for_interprets_requestable_denial_without_authorizing_it
    require "action_policy/authzen/experimental"

    access_requests = build_access_requests
    offer = access_requests.offer_for(request: REQUEST, response: DENIAL)

    assert_equal "https://ars.example/access/v1/requests", offer.endpoint
    assert_equal Time.utc(2026, 4, 30, 20, 25, 0), offer.expires_at
    assert_equal "opaque-binding-token", offer.binding_token
    assert_equal "eval_01HX4Y2P8BQ4Y3F0V0K9D6Z7M1", offer.evaluation_id
    refute_respond_to offer, :allowed?
    refute_respond_to offer, :permit?
    refute_respond_to offer, :authorized?
    refute_respond_to offer, :decision

    assert_raises(FrozenError) { offer.request_snapshot["subject"]["id"] = "mallory" }
    assert_equal "alice@example.com", REQUEST.fetch(:subject).fetch(:id)
  end

  def test_offer_for_returns_nil_for_plain_denial_and_rejects_malformed_offers
    require "action_policy/authzen/experimental"

    access_requests = build_access_requests
    assert_nil access_requests.offer_for(request: REQUEST, response: {"decision" => false})
    assert_raises(ArgumentError) { access_requests.offer_for(request: REQUEST, response: {"decision" => true}) }
    assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
      access_requests.offer_for(request: REQUEST, response: {"decision" => false, "context" => {"access_request" => {}}})
    end
  end

  def test_offer_for_rejects_untrusted_or_expired_offer_before_submission
    require "action_policy/authzen/experimental"

    access_requests = build_access_requests
    expired = denied_with("access_request" => DENIAL.dig("context", "access_request").merge("expires_at" => "2026-04-30T20:15:59Z"))
    assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { access_requests.offer_for(request: REQUEST, response: expired) }

    untrusted = denied_with("access_request" => DENIAL.dig("context", "access_request").merge("endpoint" => "https://ars.example/admin/requests"))
    assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { access_requests.offer_for(request: REQUEST, response: untrusted) }
  end

  def test_independent_topology_requires_binding_token
    require "action_policy/authzen/experimental"

    access_requests = build_access_requests(topology: :independent)
    response = denied_with("access_request" => {"expires_at" => "2026-04-30T20:25:00Z"})

    assert_raises(ActionPolicy::AuthZEN::UnsupportedFeature) do
      access_requests.offer_for(request: REQUEST, response: response)
    end
  end

  def test_create_posts_single_item_request_with_separate_credentials_and_idempotency_key
    require "action_policy/authzen/experimental"

    with_access_request_server(
      {status: 202, body: pending_body}
    ) do |base_url, requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/",
        service_headers: {"Authorization" => "Bearer ars-token", "X-Service" => "approval"}
      )
      offer = access_requests.offer_for(request: REQUEST, response: DENIAL)
      receipt = access_requests.create(offer: offer, idempotency_key: "submit-123")

      assert_equal "arq_01HX4Y3AJZ7Y56W2F9H8Q8C1V4", receipt.task_id
      assert_equal "pending", receipt.status
      refute receipt.approved?

      request = requests.pop(true)
      assert_equal "POST /access/v1/requests HTTP/1.1\r\n", request.fetch(:line)
      assert_equal "Bearer ars-token", request.dig(:headers, "authorization")
      assert_equal "approval", request.dig(:headers, "x-service")
      assert_equal "submit-123", request.dig(:headers, "idempotency-key")
      assert_equal "application/json", request.dig(:headers, "content-type")
      refute_equal "Bearer pdp-token", request.dig(:headers, "authorization")
      assert_equal "alice@example.com", request.dig(:body, "subject", "id")
      assert_equal "can_read", request.dig(:body, "action", "name")
      assert_equal "document", request.dig(:body, "resource", "type")
      assert_equal({"business_justification" => "Needed for customer renewal review"}, request.dig(:body, "context"))
      assert_equal "eval_01HX4Y2P8BQ4Y3F0V0K9D6Z7M1", request.dig(:body, "denial", "evaluation_id")
      assert_equal "opaque-binding-token", request.dig(:body, "denial", "binding_token")
      assert_equal "manager_approval", request.dig(:body, "denial", "template")
      refute request.dig(:body, "denial").key?("access_request")
    end
  end

  def test_create_rejects_crlf_idempotency_and_unsupported_schema_without_network
    require "action_policy/authzen/experimental"

    access_requests = build_access_requests
    offer = access_requests.offer_for(request: REQUEST, response: DENIAL)
    assert_raises(ArgumentError) { access_requests.create(offer: offer, idempotency_key: "abc\r\nInjected: yes") }

    schema_denial = denied_with("access_request" => DENIAL.dig("context", "access_request").merge("request_schema_url" => "https://ars.example/schema"))
    schema_offer = access_requests.offer_for(request: REQUEST, response: schema_denial)
    assert_raises(ActionPolicy::AuthZEN::UnsupportedFeature) do
      access_requests.create(offer: schema_offer, idempotency_key: "submit-123")
    end
  end

  def test_fetch_preserves_authoritative_status_endpoint_and_retry_after
    require "action_policy/authzen/experimental"

    with_access_request_server(
      {status: 202, body: pending_body, headers: {"Retry-After" => "120"}},
      {status: 200, body: approved_body}
    ) do |base_url, requests|
      now = @now
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/",
        service_headers: {"Authorization" => "Bearer ars-token"},
        clock: -> { now }
      )
      offer = access_requests.offer_for(request: REQUEST, response: DENIAL)
      receipt = access_requests.create(offer: offer, idempotency_key: "submit-123")

      assert_equal @now + 120, receipt.earliest_next_fetch_at
      assert_raises(ActionPolicy::AuthZEN::UnsupportedFeature) { access_requests.fetch(receipt: receipt) }

      now += 121
      state = access_requests.fetch(receipt: receipt)

      assert state.approved?
      assert_equal "apr_01HX4Y8E2NE3Y2X7P0K4JE6WVH", state.approval.fetch("id")
      assert_equal "opaque-approval-state", state.approval.fetch("state")
      assert_equal ["POST /access/v1/requests HTTP/1.1\r\n", "GET /access/v1/requests/arq_01HX4Y3AJZ7Y56W2F9H8Q8C1V4 HTTP/1.1\r\n"], drain_requests(requests).map { |request| request.fetch(:line) }
    end
  end

  def test_fetch_rejects_changed_task_id_status_endpoint_and_bulk_items
    require "action_policy/authzen/experimental"

    with_access_request_server(
      {status: 202, body: pending_body},
      {status: 200, body: pending_body(task: {"id" => "other-task"})}
    ) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )
      receipt = access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")

      assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { access_requests.fetch(receipt: receipt) }
    end

    with_access_request_server(
      {status: 202, body: pending_body},
      {status: 200, body: pending_body(task: {"items" => []})}
    ) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )
      receipt = access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")

      assert_raises(ActionPolicy::AuthZEN::UnsupportedFeature) { access_requests.fetch(receipt: receipt) }
    end
  end

  def test_reevaluation_request_is_pure_and_requires_approved_unexpired_reevaluate_result
    require "action_policy/authzen/experimental"

    with_access_request_server({status: 201, body: approved_body}) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )
      state = access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")
      retry_request = access_requests.reevaluation_request(state: state, request: REQUEST)

      assert_equal REQUEST.fetch(:subject), retry_request.fetch(:subject)
      assert_equal "can_read", retry_request.fetch(:action)
      assert_equal "apr_01HX4Y8E2NE3Y2X7P0K4JE6WVH", retry_request.dig(:context, "approval", "id")
      assert_equal "opaque-approval-state", retry_request.dig(:context, "approval", "state")
      assert_raises(FrozenError) { retry_request.fetch(:context).fetch("approval")["id"] = "changed" }
      refute REQUEST.fetch(:context).key?(:approval)

      assert_raises(ArgumentError) { access_requests.reevaluation_request(state: state, request: REQUEST.merge(context: {approval: {"id" => "existing"}})) }
    end

    with_access_request_server({status: 202, body: pending_body}) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )
      pending = access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")

      assert_raises(ActionPolicy::AuthZEN::UnsupportedFeature) { access_requests.reevaluation_request(state: pending, request: REQUEST) }
    end
  end

  def test_reevaluation_request_from_string_key_input_is_usable_with_core_client
    require "action_policy/authzen/experimental"

    original_request = JSON.parse(JSON.generate(REQUEST))
    with_access_request_server({status: 201, body: approved_body}) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )
      state = access_requests.create(offer: access_requests.offer_for(request: original_request, response: DENIAL), idempotency_key: "submit-123")
      retry_request = access_requests.reevaluation_request(state: state, request: original_request)

      assert_equal [:subject, :action, :resource, :context], retry_request.keys
      assert_equal "can_read", retry_request.fetch(:action)
      assert_equal({"business_justification" => "Needed for customer renewal review"}, retry_request.fetch(:context).reject { |key, _| key == "approval" })
      assert_equal "apr_01HX4Y8E2NE3Y2X7P0K4JE6WVH", retry_request.dig(:context, "approval", "id")
      refute retry_request.key?("context")

      with_evaluation_server(body: {decision: true}) do |client, requests|
        assert_equal true, client.allowed?(**retry_request)
        request = requests.pop(true)
        assert_equal "alice@example.com", request.dig(:body, "subject", "id")
        assert_equal "can_read", request.dig(:body, "action", "name")
        assert_equal "apr_01HX4Y8E2NE3Y2X7P0K4JE6WVH", request.dig(:body, "context", "approval", "id")
      end

      assert_equal JSON.parse(JSON.generate(REQUEST)), original_request
    end
  end

  def test_invalid_json_error_does_not_expose_response_body_through_cause
    require "action_policy/authzen/experimental"

    with_access_request_server({status: 202, raw_body: '{"secret_token":"do-not-leak"'}) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )
      error = assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
        access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")
      end

      assert_nil error.cause
      refute_includes error.full_message, "secret_token"
      refute_includes error.full_message, "do-not-leak"
    end
  end

  def test_fetch_without_status_endpoint_or_expiry_preserves_receipt_values
    require "action_policy/authzen/experimental"

    with_access_request_server(
      {status: 202, body: pending_body},
      {status: 200, body: approved_body(task: {"status_endpoint" => nil, "expires_at" => nil})}
    ) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )
      receipt = access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")
      state = access_requests.fetch(receipt: receipt)

      assert_equal receipt.status_endpoint, state.status_endpoint
      assert_equal receipt.task_expires_at, state.task_expires_at
      assert state.approved?
    end
  end

  def test_approval_state_preserves_false_nil_and_nested_json_values
    require "action_policy/authzen/experimental"

    [false, nil, ["nested", {"ok" => true}, nil]].each_with_index do |approval_state, index|
      with_access_request_server({status: 201, body: approved_body(approval: {"state" => approval_state})}) do |base_url, _requests|
        access_requests = build_access_requests(
          metadata: metadata_for(base_url),
          submission_url: "#{base_url}/access/v1/requests",
          status_url_prefix: "#{base_url}/access/v1/requests/"
        )
        state = access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-#{index}")
        retry_request = access_requests.reevaluation_request(state: state, request: REQUEST)

        assert retry_request.dig(:context, "approval").key?("state")
        actual_state = retry_request.dig(:context, "approval", "state")
        approval_state.nil? ? assert_nil(actual_state) : assert_equal(approval_state, actual_state)
      end
    end
  end

  def test_unknown_status_and_completion_mode_are_never_usable_for_reevaluation
    require "action_policy/authzen/experimental"

    [
      pending_body(task: {"status" => "waiting"}),
      approved_body(result: {"mode" => "token_issue", "approval" => {"id" => "apr", "approved_until" => "2026-05-01T00:42:00Z"}})
    ].each_with_index do |body, index|
      with_access_request_server({status: 201, body: body}) do |base_url, _requests|
        access_requests = build_access_requests(
          metadata: metadata_for(base_url),
          submission_url: "#{base_url}/access/v1/requests",
          status_url_prefix: "#{base_url}/access/v1/requests/"
        )
        state = access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-#{index}")

        refute state.approved?
        assert_raises(ActionPolicy::AuthZEN::UnsupportedFeature) { access_requests.reevaluation_request(state: state, request: REQUEST) }
      end
    end
  end

  def test_untrusted_task_status_url_is_rejected_before_credentialed_get
    require "action_policy/authzen/experimental"

    with_access_request_server(
      {status: 202, body: pending_body(task: {"status_endpoint" => "https://user:pass@ars.example/access/v1/requests/task"})}
    ) do |base_url, requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )

      assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
        access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")
      end
      assert_equal ["POST /access/v1/requests HTTP/1.1\r\n"], drain_requests(requests).map { |request| request.fetch(:line) }
    end
  end

  def test_conflicting_symbol_and_string_keys_are_rejected_before_network
    require "action_policy/authzen/experimental"

    access_requests = build_access_requests
    request = REQUEST.merge(subject: {"type" => "user", type: "user", id: "alice@example.com"})

    assert_raises(ArgumentError) { access_requests.offer_for(request: request, response: DENIAL) }
  end

  def test_reevaluation_rejects_changed_original_request_binding
    require "action_policy/authzen/experimental"

    with_access_request_server({status: 201, body: approved_body}) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )
      state = access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")

      [
        REQUEST.merge(subject: {type: "user", id: "mallory@example.com"}),
        REQUEST.merge(resource: {type: "document", id: "other-plan"}),
        REQUEST.merge(action: "can_write"),
        REQUEST.merge(context: {business_justification: "Different purpose"}),
        REQUEST.reject { |key, _| key == :context }
      ].each do |changed_request|
        assert_raises(ActionPolicy::AuthZEN::UnsupportedFeature) do
          access_requests.reevaluation_request(state: state, request: changed_request)
        end
      end
    end
  end

  def test_forged_or_cross_client_handles_are_rejected_before_http
    require "action_policy/authzen/experimental"

    with_access_request_server({status: 202, body: pending_body}) do |base_url, requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )
      other_access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )

      offer = access_requests.offer_for(request: REQUEST, response: DENIAL)
      forged_offer = ActionPolicy::AuthZEN::Experimental::AccessRequests::Offer.new(
        endpoint: "#{base_url}/access/v1/requests",
        expires_at: @now + 60,
        binding_token: "opaque-binding-token",
        evaluation_id: "eval-forged",
        request_snapshot: {"subject" => {"type" => "user", "id" => "alice@example.com"}, "resource" => {"type" => "document", "id" => "q4-plan"}, "action" => "can_read"},
        response_snapshot: {},
        access_request: {"expires_at" => "2026-04-30T20:25:00Z"}
      )
      assert_raises(ArgumentError) { access_requests.create(offer: forged_offer, idempotency_key: "submit-forged") }
      assert_raises(ArgumentError) { other_access_requests.create(offer: offer, idempotency_key: "submit-cross") }

      receipt = access_requests.create(offer: offer, idempotency_key: "submit-123")
      assert_raises(ArgumentError) { other_access_requests.fetch(receipt: receipt) }

      assert_equal ["POST /access/v1/requests HTTP/1.1\r\n"], drain_requests(requests).map { |request| request.fetch(:line) }
    end
  end

  def test_copied_handles_are_rejected_even_when_public_fields_match
    require "action_policy/authzen/experimental"

    with_access_request_server({status: 201, body: approved_body}) do |base_url, requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )
      offer = access_requests.offer_for(request: REQUEST, response: DENIAL)
      copied_offer = ActionPolicy::AuthZEN::Experimental::AccessRequests::Offer.new(**offer.to_h)
      assert_raises(ArgumentError) { access_requests.create(offer: copied_offer, idempotency_key: "copied-offer") }

      state = access_requests.create(offer: offer, idempotency_key: "submit-123")
      copied_state = ActionPolicy::AuthZEN::Experimental::AccessRequests::State.new(**state.to_h.merge(
        status: "approved",
        approval: {
          "id" => "apr-forged",
          "approved_until" => "2026-05-01T00:42:00Z",
          "state" => "forged"
        }
      ))
      assert_raises(ArgumentError) { access_requests.reevaluation_request(state: copied_state, request: REQUEST) }

      state_dup = state.dup
      assert_raises(ArgumentError) { access_requests.fetch(receipt: state_dup) }

      assert_equal ["POST /access/v1/requests HTTP/1.1\r\n"], drain_requests(requests).map { |request| request.fetch(:line) }
    end
  end

  def test_public_handles_are_deeply_immutable
    require "action_policy/authzen/experimental"

    with_access_request_server({status: 201, body: approved_body(approval: {"state" => {"nested" => ["opaque"]}})}) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )
      state = access_requests.create(
        offer: access_requests.offer_for(request: REQUEST, response: DENIAL),
        idempotency_key: "submit-123"
      )

      assert state.task_id.frozen?
      assert state.status_endpoint.frozen?
      assert state.task_expires_at.frozen?
      assert_raises(FrozenError) { state.approval.fetch("state").fetch("nested") << "changed" }
    end
  end

  def test_offer_for_validates_original_request_shape_and_metadata_identity
    require "action_policy/authzen/experimental"

    [
      REQUEST.merge(subject: {type: "user"}),
      REQUEST.merge(subject: {type: "user", id: 1}),
      REQUEST.merge(resource: {type: "document", id: "q4-plan", properties: []}),
      REQUEST.merge(action: {name: nil}),
      REQUEST.merge(context: [])
    ].each do |bad_request|
      assert_raises(ArgumentError) { build_access_requests.offer_for(request: bad_request, response: DENIAL) }
    end

    assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
      build_access_requests(metadata: {"access_request_endpoint" => "https://ars.example/access/v1/requests"})
    end
  end

  def test_create_and_fetch_success_require_json_content_type
    require "action_policy/authzen/experimental"

    with_access_request_server({status: 202, body: pending_body, content_type: "text/plain"}) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )

      assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
        access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")
      end
    end

    with_access_request_server(
      {status: 202, body: pending_body},
      {status: 200, body: pending_body, content_type: "text/plain"}
    ) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )
      receipt = access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")

      assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { access_requests.fetch(receipt: receipt) }
    end
  end

  def test_rfc3339_timestamps_require_timezone_offsets
    require "action_policy/authzen/experimental"

    access_requests = build_access_requests
    ["2026-04-30T20:25:00", "2026-04-30T20:25:00+0000"].each do |timestamp|
      denial = denied_with("access_request" => DENIAL.dig("context", "access_request").merge("expires_at" => timestamp))
      assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { access_requests.offer_for(request: REQUEST, response: denial) }
    end
  end

  def test_status_url_prefix_requires_segment_boundary_and_rejects_percent_encoding
    require "action_policy/authzen/experimental"

    with_access_request_server(
      {status: 202, body: pending_body(task: {"status_endpoint" => "https://ars.example/access/v1/tasksabc"})}
    ) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "https://ars.example/access/v1/tasks"
      )

      assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
        access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")
      end
    end

    with_access_request_server(
      {status: 202, body: pending_body(task: {"status_endpoint" => "https://ars.example/access/v1/requests/%2e%2e"})}
    ) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "https://ars.example/access/v1/requests/"
      )

      assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
        access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")
      end
    end
  end

  def test_duplicate_response_keys_are_rejected_and_sanitized
    require "action_policy/authzen/experimental"

    with_access_request_server(lambda { |base_url|
      {
        status: 202,
        raw_body: '{"task":{"id":"task-one","id":"task-two","status":"pending","status_endpoint":"' \
          "#{base_url}/access/v1/requests/task-one" \
          '","expires_at":"2026-04-30T23:00:00Z"}}'
      }
    }) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )
      error = assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
        access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")
      end

      assert_nil error.cause
      refute_includes error.full_message, "task-one"
      refute_includes error.full_message, "task-two"
    end
  end

  def test_malformed_json_and_escaped_duplicate_keys_are_rejected_without_hanging
    require "action_policy/authzen/experimental"

    ["[", "{"].each_with_index do |raw_body, index|
      with_access_request_server({status: 202, raw_body: raw_body}) do |base_url, _requests|
        access_requests = build_access_requests(
          metadata: metadata_for(base_url),
          submission_url: "#{base_url}/access/v1/requests",
          status_url_prefix: "#{base_url}/access/v1/requests/"
        )

        assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
          Timeout.timeout(1) do
            access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "malformed-#{index}")
          end
        end
      end
    end

    with_access_request_server(lambda { |base_url|
      {
        status: 202,
        raw_body: '{"task":{"id":"task-one","status":"pending","status_endpoint":"' \
          "#{base_url}/access/v1/requests/task-one" \
          '","expires_at":"2026-04-30T23:00:00Z"},"t\u0061sk":{"id":"task-two","status":"pending","status_endpoint":"' \
          "#{base_url}/access/v1/requests/task-two" \
          '","expires_at":"2026-04-30T23:00:00Z"}}'
      }
    }) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )

      assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
        access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "escaped-duplicate")
      end
    end
  end

  def test_http_errors_preserve_problem_type_and_retry_after_without_body_leak
    require "action_policy/authzen/experimental"

    with_access_request_server({
      status: 429,
      content_type: "application/problem+json",
      headers: {"Retry-After" => "60"},
      body: {
        "type" => "urn:openid:authzen:access-request:error:duplicate_request",
        "detail" => "secret denial binding"
      }
    }) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )
      error = assert_raises(ActionPolicy::AuthZEN::HTTPError) do
        access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")
      end

      assert_equal 429, error.status
      assert_equal "urn:openid:authzen:access-request:error:duplicate_request", error.problem_type
      assert_equal @now + 60, error.retry_after
      refute_includes error.full_message, "secret denial binding"
    end
  end

  def test_malformed_present_context_and_approved_completion_are_rejected
    require "action_policy/authzen/experimental"

    access_requests = build_access_requests
    assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
      access_requests.offer_for(request: REQUEST, response: {"decision" => false, "context" => "not-an-object"})
    end

    [
      approved_body(result: nil).tap { |body| body.delete("result") },
      approved_body(result: {"mode" => "reevaluate"}),
      approved_body(result: {"mode" => "reevaluate", "approval" => {"approved_until" => "2026-05-01T00:42:00Z"}})
    ].each_with_index do |body, index|
      with_access_request_server({status: 201, body: body}) do |base_url, _requests|
        access_requests = build_access_requests(
          metadata: metadata_for(base_url),
          submission_url: "#{base_url}/access/v1/requests",
          status_url_prefix: "#{base_url}/access/v1/requests/"
        )

        assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
          access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-#{index}")
        end
      end
    end
  end

  def test_known_terminal_state_cannot_transition_on_later_fetch
    require "action_policy/authzen/experimental"

    with_access_request_server(
      {status: 201, body: approved_body},
      {status: 200, body: approved_body},
      {status: 200, body: pending_body(task: {"status" => "denied"})}
    ) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )
      approved = access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")

      unchanged = access_requests.fetch(receipt: approved)
      assert_equal "approved", unchanged.status
      assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { access_requests.fetch(receipt: unchanged) }
    end
  end

  def test_constructor_rejects_unsafe_configuration
    require "action_policy/authzen/experimental"

    assert_raises(ArgumentError) { build_access_requests(topology: :federated) }
    assert_raises(ArgumentError) { build_access_requests(service_headers: {"Good" => "bad\nvalue"}) }
    assert_raises(ArgumentError) { build_access_requests(service_headers: {Authorization: "Bearer token"}) }
    assert_raises(ArgumentError) { build_access_requests(read_timeout: 0) }
    assert_raises(ArgumentError) do
      ActionPolicy::AuthZEN::Experimental::AccessRequests.new(
        metadata: {
          "policy_decision_point" => "https://pdp.example",
          "access_evaluation_endpoint" => "https://pdp.example/access/v1/evaluation",
          "access_request_endpoint" => "http://ars.example/access/v1/requests"
        },
        submission_url: "http://ars.example/access/v1/requests",
        status_url_prefix: "http://ars.example/access/v1/requests/"
      )
    end
  end

  def test_create_and_fetch_reject_expired_local_handles_before_http
    require "action_policy/authzen/experimental"

    with_access_request_server({status: 202, body: pending_body(task: {"expires_at" => "2026-04-30T20:16:30Z"})}) do |base_url, requests|
      now = @now
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/",
        clock: -> { now }
      )
      offer = access_requests.offer_for(request: REQUEST, response: DENIAL)
      now = Time.utc(2026, 4, 30, 20, 26, 0)
      assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { access_requests.create(offer: offer, idempotency_key: "expired-offer") }

      now = @now
      receipt = access_requests.create(offer: offer, idempotency_key: "submit-123")
      now = Time.utc(2026, 4, 30, 20, 16, 31)
      assert_raises(ActionPolicy::AuthZEN::UnsupportedFeature) { access_requests.fetch(receipt: receipt) }

      assert_equal ["POST /access/v1/requests HTTP/1.1\r\n"], drain_requests(requests).map { |request| request.fetch(:line) }
    end
  end

  def test_retry_after_accepts_http_date_and_rejects_invalid_values
    require "action_policy/authzen/experimental"

    retry_time = Time.utc(2026, 4, 30, 20, 20, 0)
    with_access_request_server({status: 202, body: pending_body, headers: {"Retry-After" => retry_time.httpdate}}) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )
      receipt = access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")

      assert_equal retry_time, receipt.earliest_next_fetch_at
    end

    with_access_request_server({status: 202, body: pending_body, headers: {"Retry-After" => "soon"}}) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )

      assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
        access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")
      end
    end
  end

  def test_http_error_metadata_is_safe_when_problem_body_is_absent_or_unrecognized
    require "action_policy/authzen/experimental"

    [
      {content_type: "application/json", body: {"detail" => "secret"}},
      {content_type: "application/problem+json", body: {"type" => "https://example.test/problem", "detail" => "secret"}},
      {content_type: "application/problem+json", body: {"type" => "urn:openid:authzen:access-request:error:secret_internal_policy", "detail" => "secret"}}
    ].each_with_index do |reply, index|
      with_access_request_server({status: 409, content_type: reply.fetch(:content_type), body: reply.fetch(:body)}) do |base_url, _requests|
        access_requests = build_access_requests(
          metadata: metadata_for(base_url),
          submission_url: "#{base_url}/access/v1/requests",
          status_url_prefix: "#{base_url}/access/v1/requests/"
        )
        error = assert_raises(ActionPolicy::AuthZEN::HTTPError) do
          access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-#{index}")
        end

        assert_equal 409, error.status
        assert_nil error.problem_type
        assert_nil error.retry_after
        refute_includes error.full_message, "secret"
      end
    end
  end

  def test_experimental_transport_sets_timeouts_and_disables_automatic_retries
    require "action_policy/authzen/experimental"

    http = Minitest::Mock.new
    http.expect(:use_ssl=, nil, [false])
    http.expect(:open_timeout=, nil, [3])
    http.expect(:read_timeout=, nil, [7])
    http.expect(:write_timeout=, nil, [7])
    http.expect(:max_retries=, nil, [0])
    response = Struct.new(:code, :body, :headers) do
      def [](key)
        headers[key.downcase]
      end
    end.new("202", JSON.generate(pending_body(task: {
      "status_endpoint" => "http://ars.example/access/v1/requests/arq_01HX4Y3AJZ7Y56W2F9H8Q8C1V4"
    })), {"content-type" => "application/json"})
    http.expect(:start, response) do |&block|
      connection = Minitest::Mock.new
      connection.expect(:request, response) { |request| request.is_a?(Net::HTTP::Post) }
      block.call(connection)
      connection.verify
      true
    end

    access_requests = build_access_requests(
      submission_url: "http://ars.example/access/v1/requests",
      status_url_prefix: "http://ars.example/access/v1/requests/",
      metadata: {
        "policy_decision_point" => "https://pdp.example",
        "access_evaluation_endpoint" => "https://pdp.example/access/v1/evaluation",
        "access_request_endpoint" => "http://ars.example/access/v1/requests"
      },
      open_timeout: 3,
      read_timeout: 7
    )
    offer = access_requests.offer_for(request: REQUEST, response: DENIAL)

    Net::HTTP.stub(:new, http) do
      assert_equal "pending", access_requests.create(offer: offer, idempotency_key: "submit-123").status
    end
    http.verify
  end

  def test_response_roots_and_approval_timestamps_are_strictly_validated
    require "action_policy/authzen/experimental"

    with_access_request_server({status: 202, raw_body: "[]"}) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )

      assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
        access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")
      end
    end

    with_access_request_server({status: 201, body: approved_body(approval: {"approved_at" => "2026-04-30T20:42:00"})}) do |base_url, _requests|
      access_requests = build_access_requests(
        metadata: metadata_for(base_url),
        submission_url: "#{base_url}/access/v1/requests",
        status_url_prefix: "#{base_url}/access/v1/requests/"
      )

      assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
        access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-123")
      end
    end

    ["2030-02-30T12:00:00Z", "2030-01-01T24:00:00Z"].each do |invalid_time|
      with_access_request_server({status: 201, body: approved_body(approval: {"approved_until" => invalid_time})}) do |base_url, _requests|
        access_requests = build_access_requests(
          metadata: metadata_for(base_url),
          submission_url: "#{base_url}/access/v1/requests",
          status_url_prefix: "#{base_url}/access/v1/requests/"
        )

        assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
          access_requests.create(offer: access_requests.offer_for(request: REQUEST, response: DENIAL), idempotency_key: "submit-#{invalid_time}")
        end
      end
    end
  end

  private

  def build_access_requests(metadata: {
      "policy_decision_point" => "https://pdp.example",
      "access_evaluation_endpoint" => "https://pdp.example/access/v1/evaluation",
      "access_request_endpoint" => "https://ars.example/access/v1/requests"
    },
    submission_url: "https://ars.example/access/v1/requests",
    status_url_prefix: "https://ars.example/access/v1/requests/",
    service_headers: {},
    topology: :shared_state,
    open_timeout: 2,
    read_timeout: 5,
    clock: -> { @now })
    ActionPolicy::AuthZEN::Experimental::AccessRequests.new(
      metadata: metadata,
      submission_url: submission_url,
      status_url_prefix: status_url_prefix,
      service_headers: service_headers,
      topology: topology,
      open_timeout: open_timeout,
      read_timeout: read_timeout,
      clock: clock,
      allow_http: submission_url.start_with?("http://")
    )
  end

  def metadata_for(base_url)
    {
      "policy_decision_point" => "https://pdp.example",
      "access_evaluation_endpoint" => "https://pdp.example/access/v1/evaluation",
      "access_request_endpoint" => "#{base_url}/access/v1/requests"
    }
  end

  def denied_with(context)
    DENIAL.merge("context" => DENIAL.fetch("context").merge(context))
  end

  def pending_body(task: {})
    {
      "task" => {
        "id" => "arq_01HX4Y3AJZ7Y56W2F9H8Q8C1V4",
        "status" => "pending",
        "status_endpoint" => "https://ars.example/access/v1/requests/arq_01HX4Y3AJZ7Y56W2F9H8Q8C1V4",
        "expires_at" => "2026-04-30T23:00:00Z"
      }.merge(task)
    }
  end

  def approved_body(task: {}, result: nil, approval: {})
    approval_body = {
      "id" => "apr_01HX4Y8E2NE3Y2X7P0K4JE6WVH",
      "approved_at" => "2026-04-30T20:42:00Z",
      "approved_until" => "2026-05-01T00:42:00Z",
      "state" => "opaque-approval-state"
    }.merge(approval)
    {
      "task" => {
        "id" => "arq_01HX4Y3AJZ7Y56W2F9H8Q8C1V4",
        "status" => "approved",
        "status_endpoint" => "https://ars.example/access/v1/requests/arq_01HX4Y3AJZ7Y56W2F9H8Q8C1V4"
      }.merge(task).compact,
      "result" => result || {
        "mode" => "reevaluate",
        "approval" => approval_body
      }
    }
  end

  def with_evaluation_server(body:, status: 200)
    server = TCPServer.new("127.0.0.1", 0)
    requests = Queue.new
    thread = Thread.new do
      socket = server.accept
      line = socket.gets
      headers = {}
      while (header = socket.gets) && header != "\r\n"
        key, value = header.split(":", 2)
        headers[key.downcase] = value.strip
      end
      raw_body = socket.read(headers.fetch("content-length", "0").to_i)
      requests << {line: line, headers: headers, body: JSON.parse(raw_body)}
      payload = JSON.generate(body)
      socket.write("HTTP/1.1 #{status} Test\r\nContent-Type: application/json\r\nContent-Length: #{payload.bytesize}\r\nConnection: close\r\n\r\n#{payload}")
      socket.close
    ensure
      socket&.close
    end
    endpoint = "http://127.0.0.1:#{server.addr[1]}/access/v1/evaluation"
    yield ActionPolicy::AuthZEN::Client.new(endpoint: endpoint, allow_http: true), requests
  ensure
    thread&.kill
    thread&.join
    server&.close
  end

  def with_access_request_server(*responses)
    server = TCPServer.new("127.0.0.1", 0)
    base_url = "http://127.0.0.1:#{server.addr[1]}"
    requests = Queue.new
    thread = Thread.new do
      socket = nil
      responses.each do |reply|
        reply = reply.call(base_url) if reply.respond_to?(:call)
        socket = server.accept
        line = socket.gets
        headers = {}
        while (header = socket.gets) && header != "\r\n"
          key, value = header.split(":", 2)
          headers[key.downcase] = value.strip
        end
        body = socket.read(headers.fetch("content-length", "0").to_i)
        requests << {line: line, headers: headers, body: body.empty? ? nil : JSON.parse(body)}
        response_headers = {"Content-Type" => reply.fetch(:content_type, "application/json")}.merge(reply.fetch(:headers, {}))
        payload = reply.key?(:raw_body) ? reply.fetch(:raw_body) : JSON.generate(rewrite_urls(reply.fetch(:body), base_url))
        response_headers["Content-Length"] = payload.bytesize.to_s
        response_headers["Connection"] = "close"
        socket.write("HTTP/1.1 #{reply.fetch(:status)} Test\r\n")
        response_headers.each { |key, value| socket.write("#{key}: #{value}\r\n") }
        socket.write("\r\n#{payload}")
        socket.close
      end
    ensure
      socket&.close
    end
    yield base_url, requests
  ensure
    thread&.kill
    thread&.join
    server&.close
  end

  def rewrite_urls(value, base_url)
    case value
    when Hash
      value.transform_values { |child| rewrite_urls(child, base_url) }
    when Array
      value.map { |child| rewrite_urls(child, base_url) }
    when "https://ars.example/access/v1/requests"
      "#{base_url}/access/v1/requests"
    when "https://ars.example/access/v1/requests/arq_01HX4Y3AJZ7Y56W2F9H8Q8C1V4"
      "#{base_url}/access/v1/requests/arq_01HX4Y3AJZ7Y56W2F9H8Q8C1V4"
    else
      value
    end
  end

  def drain_requests(requests)
    drained = []
    loop do
      drained << requests.pop(true)
    rescue ThreadError
      return drained
    end
  end
end
