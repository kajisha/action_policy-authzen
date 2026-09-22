require_relative "test_helper"
require_relative "support/pdp_server"

class DiscoveryTest < Minitest::Test
  include PDPServer

  def metadata(base_url)
    {
      policy_decision_point: base_url,
      access_evaluation_endpoint: "#{base_url}/custom/check",
      access_evaluations_endpoint: "#{base_url}/custom/batch",
      search_subject_endpoint: "#{base_url}/custom/subjects",
      search_resource_endpoint: "#{base_url}/custom/resources",
      search_action_endpoint: "#{base_url}/custom/actions",
      capabilities: ["urn:example:capability"],
      future_extension: {enabled: true}
    }
  end

  def test_configuration_inserts_well_known_before_tenant_path
    with_pdp([->(base_url, _) { {body: metadata(base_url)} }], base_path: "/tenant") do |client, requests, base_url|
      result = client.configuration
      assert_equal base_url, result["policy_decision_point"]
      assert_equal "GET /.well-known/authzen-configuration/tenant HTTP/1.1\r\n", requests.first[:line]
      assert_equal ["urn:example:capability"], result["capabilities"]
    end
  end

  def test_discovered_client_uses_advertised_nonstandard_urls
    responses = [->(base_url, _) { {body: metadata(base_url)} },
      {body: {decision: true}}, {body: {evaluations: [{decision: false}]}},
      {body: {results: []}}, {body: {results: []}}, {body: {results: []}}]
    with_pdp(responses) do |_client, requests, base_url|
      client = ActionPolicy::AuthZEN::Client.discover(base_url: base_url, allow_http: true)
      request = {subject: {type: "user", id: "anne"}, action: "reader", resource: {type: "document", id: "one"}}
      assert client.allowed?(**request)
      refute client.evaluations(evaluations: [request])["evaluations"].first["decision"]
      client.search_subjects(**request.merge(subject: {type: "user"}))
      client.search_resources(**request.merge(resource: {type: "document"}))
      client.search_actions(**request.reject { |key, _value| key == :action })
      assert_equal %w[/custom/check /custom/batch /custom/subjects /custom/resources /custom/actions],
        requests.drop(1).map { |entry| entry[:line].split[1] }
      assert_equal base_url, client.metadata["policy_decision_point"]
    end
  end

  def test_discovery_supports_explicit_openfga_style_metadata_url
    with_pdp([->(base_url, _) { {body: metadata(base_url)} }], base_path: "/stores/test") do |_client, requests, base_url|
      origin = base_url.delete_suffix("/stores/test")
      discovered = ActionPolicy::AuthZEN::Client.discover(base_url: base_url, allow_http: true,
        metadata_url: "#{origin}/.well-known/authzen-configuration/test")
      assert_equal base_url, discovered.metadata["policy_decision_point"]
      assert_includes requests.first[:line], "/.well-known/authzen-configuration/test "
    end
  end

  def test_mismatched_identifier_is_rejected
    with_pdp([->(base_url, _) { {body: metadata(base_url).merge(policy_decision_point: "#{base_url}/other")} }]) do |client, _requests|
      assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { client.configuration }
    end
  end

  def test_absent_optional_endpoints_are_not_invented_after_discovery
    with_pdp([->(base_url, _) { {body: {policy_decision_point: base_url, access_evaluation_endpoint: "#{base_url}/check"}} }]) do |_client, _requests, base_url|
      client = ActionPolicy::AuthZEN::Client.discover(base_url: base_url, allow_http: true)
      assert_raises(ActionPolicy::AuthZEN::UnsupportedEndpoint) do
        client.search_actions(subject: {type: "user", id: "anne"}, resource: {type: "document", id: "one"})
      end
    end
  end

  def test_malformed_metadata_is_rejected
    [
      ->(base_url) { {policy_decision_point: base_url} },
      ->(base_url) { metadata(base_url).merge(access_evaluation_endpoint: "/relative") },
      ->(base_url) { metadata(base_url).merge(access_evaluation_endpoint: "https://example.com/invalid path") },
      ->(base_url) { metadata(base_url).merge(search_action_endpoint: "https://user:secret@example.com/") },
      ->(base_url) { metadata(base_url).merge(capabilities: "not an array") },
      ->(base_url) { metadata(base_url).merge(capabilities: [3]) }
    ].each do |build|
      with_pdp([->(base_url, _) { {body: build.call(base_url)} }]) do |client, _requests|
        assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { client.configuration }
      end
    end
  end

  def test_cross_origin_discovery_does_not_forward_credentials_implicitly
    with_pdp([->(base_url, _) { {body: metadata(base_url).merge(access_evaluation_endpoint: "https://other.example/check")} }],
      headers: {"Authorization" => "Bearer secret"}) do |client, _requests|
      assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { client.configuration }
    end
  end

  def test_explicitly_trusted_origin_is_accepted
    with_pdp([->(base_url, _) { {body: metadata(base_url).merge(access_evaluation_endpoint: "https://other.example/check")} }],
      trusted_origins: ["https://other.example"]) do |client, _requests|
      assert_equal "https://other.example/check", client.configuration["access_evaluation_endpoint"]
    end
  end

  def test_unsupported_signed_metadata_and_unknown_fields_do_not_override_plain_values
    with_pdp([->(base_url, _) { {body: metadata(base_url).merge(signed_metadata: "unsupported.jwt.signature")} }]) do |client, _requests, base_url|
      assert_equal base_url, client.configuration["policy_decision_point"]
    end
  end

  def test_legacy_single_endpoint_is_not_rewritten
    client = ActionPolicy::AuthZEN::Client.new(endpoint: "https://example.com/arbitrary")
    assert_raises(ArgumentError) do
      client.search_actions(subject: {type: "user", id: "anne"}, resource: {type: "document", id: "one"})
    end
  end

  def test_discovery_rejects_non_json_content_type
    with_pdp([->(base_url, _) { {body: metadata(base_url), content_type: "text/html"} }]) do |client, _requests|
      assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { client.configuration }
    end
  end

  def test_discovery_does_not_accept_explicit_endpoint_overrides
    assert_raises(ArgumentError) do
      ActionPolicy::AuthZEN::Client.discover(base_url: "https://example.com", endpoint: "https://other.example/check")
    end
  end

  def test_trusted_origin_is_forwarded_by_discover
    with_pdp([->(base_url, _) { {body: metadata(base_url).merge(access_evaluation_endpoint: "https://other.example/check")} }]) do |_client, _requests, base_url|
      client = ActionPolicy::AuthZEN::Client.discover(base_url: base_url, allow_http: true, trusted_origins: ["https://other.example"])
      assert_equal "https://other.example/check", client.metadata["access_evaluation_endpoint"]
    end
  end

  def test_configuration_applies_advertised_urls_to_existing_client
    with_pdp([->(base_url, _) { {body: metadata(base_url)} }, {body: {results: []}}]) do |client, requests|
      client.configuration
      client.search_actions(subject: {type: "user", id: "anne"}, resource: {type: "document", id: "one"})
      assert_includes requests.last[:line], "/custom/actions "
    end
  end
end
