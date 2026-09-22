require_relative "test_helper"
require_relative "support/pdp_server"

class OfficialScenarioTest < Minitest::Test
  include PDPServer

  REQUEST = {subject: {type: "user", id: "alice"}, action: {name: "read"},
    resource: {type: "record", id: "record-1"}}.freeze

  def test_c_2_4_1_missing_fields_are_rejected_before_transport
    client = ActionPolicy::AuthZEN::Client.new(base_url: "https://invalid.example")
    REQUEST.each_key do |field|
      assert_raises(ArgumentError) { client.evaluate(**REQUEST.reject { |key, _value| key == field }) }
    end
  end

  def test_c_2_4_2_missing_subfields_are_rejected_before_transport
    client = ActionPolicy::AuthZEN::Client.new(base_url: "https://invalid.example")
    {subject: %i[type id], action: [:name], resource: %i[type id]}.each do |entity, fields|
      fields.each do |field|
        value = REQUEST.fetch(entity).reject { |key, _value| key == field }
        assert_raises(ArgumentError) { client.evaluate(**REQUEST.merge(entity => value)) }
      end
    end
  end

  def test_c_2_4_6_invalid_field_types_are_rejected_before_transport
    client = ActionPolicy::AuthZEN::Client.new(base_url: "https://invalid.example")
    [{subject: "alice"}, {action: {name: 123}}].each do |override|
      assert_raises(ArgumentError) { client.evaluate(**REQUEST.merge(override)) }
    end
  end

  def test_c_2_3_1_and_c_2_3_2_decision_and_context_shapes
    [{}, {decision: "true"}, {decision: true, context: []}].each do |body|
      with_pdp([{body: body}]) do |client, _requests|
        assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { client.evaluate(**REQUEST) }
      end
    end
    with_pdp([{body: {decision: false, context: {reason: "denied"}, future: true}}]) do |client, _requests|
      result = client.evaluate(**REQUEST)
      refute result.fetch("decision")
      assert_equal({"reason" => "denied"}, result.fetch("context"))
    end
  end

  def test_c_2_5_1_and_c_5_send_explicit_request_id_and_json
    with_pdp([{body: {decision: true}}], headers: {"X-Request-ID" => "official-scenario"}) do |client, requests|
      assert client.allowed?(**REQUEST)
      assert_equal "official-scenario", requests.first.fetch(:headers).fetch("x-request-id")
      assert_equal "application/json", requests.first.fetch(:headers).fetch("content-type")
      assert_equal JSON.parse(JSON.generate(REQUEST)), requests.first.fetch(:body)
    end
  end

  def test_c_3_3_1_to_c_3_3_4_batch_shape_and_individual_decisions
    [[], [{decision: true}], [{decision: true}, {}], [{decision: true}, {decision: "false"}]].each do |items|
      with_pdp([{body: {decision: true, evaluations: items}}]) do |client, _requests|
        assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
          client.evaluations(**REQUEST, evaluations: [{}, {}])
        end
      end
    end
    with_pdp([{body: {decision: true, evaluations: [{decision: false}, {decision: true}]}}]) do |client, _requests|
      result = client.evaluations(**REQUEST, evaluations: [{}, {}])
      assert_equal [false, true], result.fetch("evaluations").map { |entry| entry.fetch("decision") }
    end
  end

  def test_c_3_4_1_individual_errors_do_not_mask_denials
    body = {evaluations: [{decision: true}, {decision: false, context: {error: "invalid evaluation"}}]}
    with_pdp([{body: body}]) do |client, _requests|
      result = client.evaluations(**REQUEST, evaluations: [{}, {}], options: {evaluations_semantic: "execute_all"})
      assert_equal [true, false], result.fetch("evaluations").map { |entry| entry.fetch("decision") }
      assert_equal "invalid evaluation", result.fetch("evaluations").last.dig("context", "error")
    end
  end

  def test_c_4_5_4_accepts_unpaginated_results_even_with_limit
    [{results: [{type: "user", id: "alice"}, {type: "user", id: "bob"}]},
     {results: [{type: "user", id: "alice"}, {type: "user", id: "bob"}], page: {next_token: ""}}].each do |body|
      with_pdp([{body: body}]) do |client, requests|
        results = client.each_subject(**REQUEST.merge(subject: {type: "user"}), page: {limit: 1}).to_a
        assert_equal %w[alice bob], results.map { |entry| entry.fetch("id") }
        assert_equal 1, requests.length
      end
    end
  end

  def test_c_4_7_1_and_c_4_7_2_missing_search_inputs_are_rejected
    client = ActionPolicy::AuthZEN::Client.new(base_url: "https://invalid.example")
    requests = [
      [:search_subjects, {subject: {type: "user"}, resource: REQUEST[:resource]}],
      [:search_resources, {action: REQUEST[:action], resource: {type: "record"}}],
      [:search_actions, {subject: REQUEST[:subject]}],
      [:search_subjects, REQUEST.merge(subject: {type: "user"}, resource: {type: "record"})],
      [:search_resources, REQUEST.merge(subject: {type: "user"}, resource: {type: "record"})],
      [:search_actions, {subject: {type: "user"}, resource: REQUEST[:resource]}]
    ]
    requests.each do |method, request|
      assert_raises(ArgumentError) { client.public_send(method, **request) }
    end
  end

  def test_c_6_6_discovery_404_is_not_success_and_default_paths_can_be_selected_explicitly
    with_pdp([{status: 404, body: {}}, {body: {decision: true}}]) do |client, requests|
      error = assert_raises(ActionPolicy::AuthZEN::HTTPError) { client.configuration }
      assert_equal 404, error.status
      assert client.allowed?(**REQUEST)
      assert_equal "POST /access/v1/evaluation HTTP/1.1\r\n", requests.last.fetch(:line)
    end
  end

  def test_c_6_2_metadata_requires_json_object_and_success_status
    [{body: []}, {body: nil}, {body: {}}, {body: {}, status: 201}].each do |response|
      with_pdp([response]) do |client, _requests|
        error_class = response[:status] ? ActionPolicy::AuthZEN::HTTPError : ActionPolicy::AuthZEN::InvalidResponse
        assert_raises(error_class) { client.configuration }
      end
    end
  end

  def test_c_6_3_and_c_6_5_reject_identifier_queries_and_fragments
    ["?tenant=one", "#fragment"].each do |suffix|
      with_pdp([->(base_url, _request) {
        {body: {policy_decision_point: "#{base_url}#{suffix}", access_evaluation_endpoint: "#{base_url}/check"}}
      }]) do |client, _requests|
        assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { client.configuration }
      end
    end
  end
end
