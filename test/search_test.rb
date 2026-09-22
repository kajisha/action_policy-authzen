require_relative "test_helper"
require_relative "support/pdp_server"

class SearchTest < Minitest::Test
  include PDPServer

  RESOURCE_QUERY = {subject: {type: "user", id: "anne"}, action: "reader", resource: {type: "document"}}.freeze

  def test_each_search_uses_its_own_schema_and_path
    requests_by_method = {
      search_subjects: {subject: {type: "user"}, action: "reader", resource: {type: "document", id: "roadmap"}},
      search_resources: RESOURCE_QUERY,
      search_actions: {subject: {type: "user", id: "anne"}, resource: {type: "document", id: "roadmap"}}
    }
    requests_by_method.each do |method, query|
      entity = method == :search_actions ? {name: "reader"} : {type: method == :search_subjects ? "user" : "document", id: "one"}
      with_pdp([{body: {results: [entity], context: {explanation: "allowed"}}}], base_path: "/tenant") do |client, requests|
        result = client.public_send(method, **query, context: {tenant: "acme"}, page: {limit: 0})
        assert_equal [JSON.parse(JSON.generate(entity))], result["results"]
        assert_equal({"explanation" => "allowed"}, result["context"])
        assert_includes requests.first[:line], "/tenant/access/v1/search/#{method.to_s.delete_prefix('search_').delete_suffix('s')} "
        refute requests.first[:body].key?("action") if method == :search_actions
        assert_equal 0, requests.first[:body]["page"]["limit"]
      end
    end
  end

  def test_pagination_preserves_query_and_page_options_without_mutation
    query = RESOURCE_QUERY.merge(context: {time: "fixed"}, page: {limit: 1, properties: {sort: "id"}})
    before = Marshal.load(Marshal.dump(query))
    responses = [
      {body: {results: [{type: "document", id: "one"}], page: {next_token: "opaque+/=", count: 1, total: 2}}},
      {body: {results: [{type: "document", id: "two"}], page: {next_token: "", count: 1}}}
    ]
    with_pdp(responses) do |client, requests|
      enumerator = client.each_resource(**query)
      assert_kind_of Enumerator, enumerator
      assert_equal %w[one two], enumerator.map { |entity| entity["id"] }
      assert_equal before, query
      first, second = requests.map { |request| request[:body] }
      assert_equal "opaque+/=", second["page"].delete("token")
      assert_equal first, second
    end
  end

  def test_subject_and_action_iterators
    [[:each_subject, {subject: {type: "user"}, action: "reader", resource: {type: "document", id: "one"}}, {type: "user", id: "anne"}],
     [:each_action, {subject: {type: "user", id: "anne"}, resource: {type: "document", id: "one"}}, {name: "reader"}]].each do |method, query, entity|
      with_pdp([{body: {results: [entity]}}]) do |client, _requests|
        assert_equal [JSON.parse(JSON.generate(entity))], client.public_send(method, **query).to_a
      end
    end
  end

  def test_caller_mutation_during_iteration_cannot_change_later_requests
    query = Marshal.load(Marshal.dump(RESOURCE_QUERY))
    query[:page] = {"limit" => 1}
    responses = [
      {body: {results: [{type: "document", id: "one"}], page: {next_token: "next"}}},
      {body: {results: [], page: {next_token: ""}}}
    ]
    with_pdp(responses) do |client, requests|
      client.each_resource(**query) do |_entity|
        query[:subject][:id] = "bob"
        query[:page]["limit"] = 99
      end
      assert_equal "anne", requests.last[:body]["subject"]["id"]
      assert_equal({"limit" => 1, "token" => "next"}, requests.last[:body]["page"])
    end
  end

  def test_empty_page_with_token_continues_and_repeated_token_fails
    responses = [
      {body: {results: [], page: {next_token: "same"}}},
      {body: {results: [], page: {next_token: "same"}}}
    ]
    with_pdp(responses) do |client, requests|
      assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { client.each_resource(**RESOURCE_QUERY).to_a }
      assert_equal 2, requests.size
    end
  end

  def test_missing_page_means_complete_empty_result
    with_pdp([{body: {results: []}}]) do |client, requests|
      assert_empty client.each_resource(**RESOURCE_QUERY).to_a
      assert_equal 1, requests.length
    end
  end

  def test_invalid_search_responses_are_rejected
    [
      {}, {results: nil}, {results: [true]}, {results: [{name: "wrong entity"}]},
      {results: [{type: "other", id: "one"}]},
      {results: [], page: {}}, {results: [], page: {next_token: nil}},
      {results: [], page: {next_token: "", count: -1}},
      {results: [], page: {next_token: "", total: 1.5}}, {results: [], context: []}
    ].each do |body|
      with_pdp([{body: body}]) do |client, _requests|
        assert_raises(ActionPolicy::AuthZEN::InvalidResponse) { client.search_resources(**RESOURCE_QUERY) }
      end
    end
  end

  def test_invalid_page_parameters_fail_before_http
    client = ActionPolicy::AuthZEN::Client.new(base_url: "https://example.com")
    [[], {limit: -1}, {limit: "1"}, {token: 3}, {properties: []}, {unregistered_extension: 1}].each do |page|
      assert_raises(ArgumentError) { client.search_resources(**RESOURCE_QUERY, page: page) }
    end
  end

  def test_search_http_errors_propagate
    with_pdp([{status: 500, body: {results: []}}]) do |client, _requests|
      assert_raises(ActionPolicy::AuthZEN::HTTPError) { client.each_resource(**RESOURCE_QUERY).to_a }
    end
  end
end
