require_relative "test_helper"
require "open3"
require "rbconfig"
require "socket"

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

  private

  def build_access_requests(metadata: {"access_request_endpoint" => "https://ars.example/access/v1/requests"},
    submission_url: "https://ars.example/access/v1/requests",
    status_url_prefix: "https://ars.example/access/v1/requests/",
    service_headers: {},
    topology: :shared_state,
    clock: -> { @now })
    ActionPolicy::AuthZEN::Experimental::AccessRequests.new(
      metadata: metadata,
      submission_url: submission_url,
      status_url_prefix: status_url_prefix,
      service_headers: service_headers,
      topology: topology,
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

  def approved_body
    {
      "task" => {
        "id" => "arq_01HX4Y3AJZ7Y56W2F9H8Q8C1V4",
        "status" => "approved"
      },
      "result" => {
        "mode" => "reevaluate",
        "approval" => {
          "id" => "apr_01HX4Y8E2NE3Y2X7P0K4JE6WVH",
          "approved_at" => "2026-04-30T20:42:00Z",
          "approved_until" => "2026-05-01T00:42:00Z",
          "state" => "opaque-approval-state"
        }
      }
    }
  end

  def with_access_request_server(*responses)
    server = TCPServer.new("127.0.0.1", 0)
    base_url = "http://127.0.0.1:#{server.addr[1]}"
    requests = Queue.new
    thread = Thread.new do
      socket = nil
      responses.each do |reply|
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
        payload = JSON.generate(rewrite_urls(reply.fetch(:body), base_url))
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
