require_relative "../test_helper"

require "json"

class OfficialScenarioIntegrationTest < Minitest::Test
  CASES_PATH = File.expand_path("../fixtures/official_scenario/cases.json", __dir__)
  CASES = JSON.parse(File.read(CASES_PATH)).freeze

  def setup
    skip "set OFFICIAL_PDP_URL to run official AuthZEN scenario integration tests" unless ENV["OFFICIAL_PDP_URL"]

    @client = ActionPolicy::AuthZEN::Client.discover(
      base_url: ENV.fetch("OFFICIAL_PDP_URL").sub(%r{/+\z}, ""),
      allow_http: true,
      open_timeout: 2,
      read_timeout: 5
    )
  end

  CASES.fetch("evaluation").each do |example|
    define_method("test_#{example.fetch('id')}_evaluation") do
      assert_decision example
    end
  end

  define_method("test_c-2-6_repeat_calls_are_idempotent") do
    example = CASES.fetch("repeat")
    decisions = Array.new(example.fetch("count")) do
      @client.evaluate(**symbolize(example.fetch("request"))).fetch("decision")
    end

    assert_equal [example.fetch("decision")] * example.fetch("count"), decisions
  end

  CASES.fetch("batch").each do |example|
    define_method("test_#{example.fetch('id')}_batch") do
      response = @client.evaluations(**symbolize(example.fetch("request")))
      if example.key?("decision")
        assert_equal example.fetch("decision"), response.fetch("decision")
      else
        evaluations = response.fetch("evaluations")
        assert_equal example["count"], evaluations.length if example.key?("count")
        assert_equal example["decisions"], evaluations.map { |entry| entry.fetch("decision") } if example.key?("decisions")
        evaluations.each { |entry| assert_includes [true, false], entry.fetch("decision") }
      end
    end
  end

  CASES.fetch("search").each do |example|
    define_method("test_#{example.fetch('id')}_search") do
      response = @client.public_send(example.fetch("method"), **symbolize(example.fetch("request")))
      results = response.fetch("results")
      assert_kind_of Array, results

      if example["empty"]
        assert_empty results
      elsif example.key?("names")
        names = results.map { |entry| entry.fetch("name") }
        example.fetch("names").each { |name| assert_includes names, name }
      elsif example.key?("ids")
        ids = results.map { |entry| entry.fetch("id") }
        example.fetch("ids").each { |id| assert_includes ids, id }
      end

      assert_same_results(example, results)
      assert_valid_page(response) if response.key?("page")
    end
  end

  define_method("test_c-4-5-2_and_c-4-5-3_pagination_token_response_format") do
    first = @client.search_subjects(
      subject: {"type" => "user"},
      action: {"name" => "read"},
      resource: {"type" => "record", "id" => "record-1"},
      page: {"limit" => 1}
    )
    assert_valid_page(first) if first.key?("page")
    token = first.dig("page", "next_token")
    assert_kind_of String, token
    refute_empty token

    follow_up = @client.search_subjects(
      subject: {"type" => "user"},
      action: {"name" => "read"},
      resource: {"type" => "record", "id" => "record-1"},
      page: {"limit" => 1, "token" => token}
    )
    assert_kind_of Array, follow_up.fetch("results")
    assert_valid_page(follow_up)
    assert_equal "", follow_up.fetch("page").fetch("next_token")
    assert_equal %w[alice bob], (first.fetch("results") + follow_up.fetch("results")).map { |entry| entry.fetch("id") }.sort
  end

  define_method("test_c-4-6-1_and_c-4-6-2_empty_results_for_all_searches") do
    queries = {
      search_subjects: {subject: {type: "user"}, action: {name: "read"}, resource: {type: "record", id: "record-1"}},
      search_resources: {subject: {type: "user", id: "alice"}, action: {name: "read"}, resource: {type: "record"}},
      search_actions: {subject: {type: "user", id: "alice"}, resource: {type: "record", id: "record-1"}}
    }
    queries.each do |method, query|
      input = method == :search_subjects ? :resource : :subject
      [{id: "nonexistent"}, {type: "spaceship"}].each do |override|
        request = query.merge(input => query.fetch(input).merge(override))
        assert_empty @client.public_send(method, **request).fetch("results"), "#{method}: #{override}"
      end
    end
  end

  define_method("test_c-1-4_rule_5_archived_property_overrides_active_identifier") do
    refute @client.allowed?(subject: {type: "user", id: "alice"}, action: "write",
      resource: {type: "record", id: "record-1", properties: {status: "archived"}})
  end

  private

  def assert_decision(example)
    assert_equal example.fetch("decision"), @client.evaluate(**symbolize(example.fetch("request"))).fetch("decision")
  end

  def assert_same_results(example, results)
    return unless example["same_as"]

    baseline = CASES.fetch("search").find { |entry| entry.fetch("id") == example.fetch("same_as") }
    baseline_results = @client.public_send(baseline.fetch("method"), **symbolize(baseline.fetch("request"))).fetch("results")
    assert_equal comparable_results(baseline_results), comparable_results(results)
  end

  def comparable_results(results)
    results.map { |entry| entry.sort.to_h }.sort_by { |entry| entry["id"] || entry["name"] }
  end

  def assert_valid_page(response)
    page = response.fetch("page")
    assert_kind_of Hash, page
    assert_kind_of String, page.fetch("next_token")
  end

  def symbolize(value)
    case value
    when Array
      value.map { |entry| symbolize(entry) }
    when Hash
      value.each_with_object({}) { |(key, entry), result| result[key.to_sym] = symbolize(entry) }
    else
      value
    end
  end
end
