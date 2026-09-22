require_relative "test_helper"
require_relative "support/pdp_server"

class EvaluationsTest < Minitest::Test
  include PDPServer

  DEFAULTS = {
    subject: {type: "user", id: "anne"}, action: "reader",
    resource: {type: "document", id: "roadmap"}
  }.freeze

  def test_defaults_and_whole_entity_overrides_remain_distinct
    response = {"evaluations" => [{"decision" => true}, {"decision" => false, "context" => {"error" => "denied"}}]}
    with_pdp([{body: response}], base_path: "/tenant") do |client, requests|
      result = client.evaluations(**DEFAULTS, context: {tenant: "default"},
        evaluations: [{}, {subject: {type: "user", id: "bob"}, context: {purpose: "preview"}}])
      assert_equal response, result
      assert_equal "POST /tenant/access/v1/evaluations HTTP/1.1\r\n", requests.first[:line]
      payload = requests.first[:body]
      assert_equal({"tenant" => "default"}, payload["context"])
      assert_equal({"purpose" => "preview"}, payload["evaluations"][1]["context"])
      assert_equal "bob", payload["evaluations"][1]["subject"]["id"]
    end
  end

  def test_complete_independent_items_need_no_defaults
    with_pdp([{body: {evaluations: [{decision: true}]}}]) do |client, _requests|
      assert client.evaluations(evaluations: [DEFAULTS]).fetch("evaluations").first.fetch("decision")
    end
  end

  def test_absent_and_empty_evaluations_support_single_response
    [nil, []].each do |items|
      [{decision: true}, {evaluations: [{decision: true}]}].each do |body|
        with_pdp([{body: body}]) do |client, _requests|
          result = client.evaluations(**DEFAULTS, evaluations: items)
          assert_equal JSON.parse(JSON.generate(body)), result
        end
      end
    end
  end

  def test_all_semantics_accept_valid_results
    {
      "execute_all" => [true, false, true],
      "deny_on_first_deny" => [true, false],
      "permit_on_first_permit" => [true]
    }.each do |semantic, decisions|
      with_pdp([{body: {evaluations: decisions.map { |decision| {decision: decision} }}}]) do |client, requests|
        result = client.evaluations(**DEFAULTS, evaluations: [{}, {}, {}], options: {evaluations_semantic: semantic})
        assert_equal decisions, result["evaluations"].map { |entry| entry["decision"] }
        assert_equal semantic, requests.first[:body]["options"]["evaluations_semantic"]
      end
    end
  end

  def test_exhausted_short_circuit_semantics_return_every_result
    {"deny_on_first_deny" => true, "permit_on_first_permit" => false}.each do |semantic, decision|
      with_pdp([{body: {evaluations: [{decision: decision}, {decision: decision}]}}]) do |client, _requests|
        assert_equal 2, client.evaluations(**DEFAULTS, evaluations: [{}, {}],
          options: {evaluations_semantic: semantic})["evaluations"].length
      end
    end
  end

  def test_truncated_or_excess_results_cannot_authorize
    [[], [{decision: true}], [{decision: true}] * 3].each do |items|
      with_pdp([{body: {evaluations: items}}]) do |client, _requests|
        assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
          client.evaluations(**DEFAULTS, evaluations: [{}, {}])
        end
      end
    end
  end

  def test_invalid_short_circuit_sequences_are_rejected
    {"deny_on_first_deny" => [[true], [false, true]],
     "permit_on_first_permit" => [[false], [true, false]]}.each do |semantic, sequences|
      sequences.each do |decisions|
        with_pdp([{body: {evaluations: decisions.map { |decision| {decision: decision} }}}]) do |client, _requests|
          assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
            client.evaluations(**DEFAULTS, evaluations: [{}, {}], options: {evaluations_semantic: semantic})
          end
        end
      end
    end
  end

  def test_invalid_decision_shapes_and_top_level_decision_do_not_mask_errors
    [{decision: true}, {evaluations: [{decision: "true"}]},
     {evaluations: [true]}, {evaluations: [{decision: true, context: []}]}].each do |body|
      with_pdp([{body: body}]) do |client, _requests|
        assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { client.evaluations(evaluations: [DEFAULTS]) }
      end
    end
  end

  def test_invalid_inputs_fail_before_http
    client = ActionPolicy::AuthZEN::Client.new(base_url: "https://example.com")
    [
      {evaluations: [{}]}, {evaluations: "bad"}, {evaluations: [nil]},
      DEFAULTS.merge(evaluations: [{subject: {id: "bob"}}]),
      DEFAULTS.merge(options: {evaluations_semantic: "other"}), DEFAULTS.merge(options: [])
    ].each do |request|
      assert_raises(ArgumentError) { client.evaluations(**request) }
    end
  end

  def test_optional_batch_containers_reject_non_objects_and_non_arrays
    client = ActionPolicy::AuthZEN::Client.new(base_url: "https://example.com")
    [false, 0, "", {}].each do |evaluations|
      assert_raises(ArgumentError) { client.evaluations(**DEFAULTS, evaluations: evaluations) }
    end
    [false, 0, "", []].each do |value|
      [:context, :options].each do |field|
        assert_raises(ArgumentError) { client.evaluations(**DEFAULTS, field => value) }
      end
      assert_raises(ArgumentError) { client.evaluations(**DEFAULTS, evaluations: [{context: value}]) }
    end
  end

  def test_http_error_is_not_a_batch_decision
    with_pdp([{status: 503, body: {evaluations: [{decision: true}]}}]) do |client, _requests|
      assert_raises(ActionPolicy::AuthZEN::HTTPError) { client.evaluations(evaluations: [DEFAULTS]) }
    end
  end

  def test_top_level_decision_and_unknown_fields_cannot_override_individual_denials
    body = {decision: true, future: "ignored", evaluations: [{decision: false, context: {error: {status: 500}}}]}
    with_pdp([{body: body}]) do |client, _requests|
      result = client.evaluations(evaluations: [DEFAULTS])
      refute result["evaluations"].first["decision"]
      assert_equal 500, result["evaluations"].first.dig("context", "error", "status")
    end
  end
end
