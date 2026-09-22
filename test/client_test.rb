require_relative "test_helper"
require "socket"

class ClientTest < Minitest::Test
  REQUEST = {
    subject: {type: "user", id: "anne"},
    action: "reader",
    resource: {type: "document", id: "roadmap"}
  }.freeze

  def with_server(body:, status: 200, delay: 0, headers: {}, read_timeout: 2)
    server = TCPServer.new("127.0.0.1", 0)
    requests = Queue.new
    thread = Thread.new do
      socket = server.accept
      request_line = socket.gets
      request_headers = {}
      while (line = socket.gets) && line != "\r\n"
        key, value = line.split(":", 2)
        request_headers[key.downcase] = value.strip
      end
      request_body = socket.read(request_headers.fetch("content-length").to_i)
      requests << [request_line, request_headers, JSON.parse(request_body)]
      sleep delay if delay.positive?
      socket.write("HTTP/1.1 #{status} Test\r\nContent-Type: application/json\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
    ensure
      socket&.close
    end
    endpoint = "http://127.0.0.1:#{server.addr[1]}/stores/test/access/v1/evaluation"
    yield ActionPolicy::AuthZEN::Client.new(endpoint: endpoint, headers: headers, read_timeout: read_timeout, allow_http: true), requests
  ensure
    thread&.kill
    thread&.join
    server&.close
  end

  def test_serializes_authzen_request_and_preserves_endpoint_and_headers
    with_server(body: '{"decision":true,"context":{"reason":"member"}}',
      headers: {"Authorization" => "Bearer test-token", "Openfga-Authorization-Model-Id" => "model"}) do |client, requests|
      result = client.evaluate(**REQUEST, context: {tenant: "acme"},
        action: {name: "reader", properties: {mode: "preview"}})
      assert_equal({"decision" => true, "context" => {"reason" => "member"}}, result)
      request_line, headers, payload = requests.pop
      assert_equal "POST /stores/test/access/v1/evaluation HTTP/1.1\r\n", request_line
      assert_equal "application/json", headers["content-type"]
      assert_equal "application/json", headers["accept"]
      assert_equal "Bearer test-token", headers["authorization"]
      assert_equal "model", headers["openfga-authorization-model-id"]
      refute_empty headers["x-request-id"]
      assert_equal({"type" => "user", "id" => "anne"}, payload["subject"])
      assert_equal({"type" => "document", "id" => "roadmap"}, payload["resource"])
      assert_equal({"name" => "reader", "properties" => {"mode" => "preview"}}, payload["action"])
      assert_equal({"tenant" => "acme"}, payload["context"])
    end
  end

  def test_boolean_decisions_and_absent_context
    [true, false].each do |decision|
      with_server(body: JSON.generate(decision: decision)) do |client, requests|
        assert_equal decision, client.allowed?(**REQUEST)
        refute requests.pop.last.key?("context")
      end
    end
  end

  def test_protocol_strings_are_not_restricted_to_openfga_identifiers
    with_server(body: '{"decision":true,"future_field":{"value":1}}') do |client, requests|
      assert client.allowed?(subject: {type: "", id: ""}, action: "", resource: {type: "", id: ""})
      assert_equal "", requests.pop.last["subject"]["id"]
    end
  end

  def test_rejects_non_boolean_or_missing_decisions
    ["true", 1, nil, [], {}].each do |decision|
      with_server(body: JSON.generate(decision: decision)) do |client, _requests|
        assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { client.allowed?(**REQUEST) }
      end
    end
    ["{}", "[]", "null", "invalid", '{"decision":true,"context":null}'].each do |body|
      with_server(body: body) do |client, _requests|
        assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { client.allowed?(**REQUEST) }
      end
    end
  end

  def test_http_errors_and_redirects_never_authorize
    [201, 204, 302, 400, 401, 403, 429, 500, 503].each do |status|
      with_server(body: '{"decision":true}', status: status) do |client, _requests|
        error = assert_raises(ActionPolicy::AuthZEN::HTTPError) { client.allowed?(**REQUEST) }
        assert_equal status, error.status
      end
    end
  end

  def test_read_timeout_is_a_transport_error
    with_server(body: '{"decision":true}', delay: 1, read_timeout: 0.1) do |client, _requests|
      error = assert_raises(ActionPolicy::AuthZEN::TransportError) { client.allowed?(**REQUEST) }
      assert_kind_of Net::ReadTimeout, error.cause
    end
  end

  def test_connection_failure_is_a_transport_error
    failure = ->(*) { raise Errno::ECONNREFUSED }
    Net::HTTP.stub(:new, failure) do
      client = ActionPolicy::AuthZEN::Client.new(endpoint: "http://localhost/access/v1/evaluation", allow_http: true)
      assert_raises(ActionPolicy::AuthZEN::TransportError) { client.allowed?(**REQUEST) }
    end
  end

  def test_invalid_input_is_rejected_before_network_access
    client = ActionPolicy::AuthZEN::Client.new(endpoint: "http://localhost/access/v1/evaluation", allow_http: true)
    [
      {subject: {type: "user"}}, {subject: {type: "user", id: 1}},
      {resource: {type: nil, id: "roadmap"}}, {resource: nil},
      {action: {name: nil}}, {action: {name: "reader", properties: []}}, {context: []}
    ].each do |override|
      assert_raises(ArgumentError) { client.evaluate(**REQUEST.merge(override)) }
    end
  end

  def test_rejects_invalid_endpoints_and_unbounded_timeouts
    ["/relative", "ftp://example.com", "https://user:password@example.com", "https://example.com/#fragment", "http://"].each do |endpoint|
      assert_raises(ArgumentError) { ActionPolicy::AuthZEN::Client.new(endpoint: endpoint) }
    end
    [0, -1, nil, Float::INFINITY].each do |timeout|
      assert_raises(ArgumentError) do
        ActionPolicy::AuthZEN::Client.new(endpoint: "https://example.com", read_timeout: timeout)
      end
    end
  end
end
