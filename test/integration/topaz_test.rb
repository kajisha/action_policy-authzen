require_relative "../test_helper"

require "json"
require "net/http"
require "uri"

class TopazIntegrationTest < Minitest::Test
  SUBJECT_RICK = {"type" => "user", "id" => "rick@the-citadel.com"}.freeze
  SUBJECT_JERRY = {"type" => "user", "id" => "jerry@the-smiths.com"}.freeze
  SUBJECT_BETH = {"type" => "user", "id" => "beth@the-smiths.com"}.freeze
  RESOURCE_JERRY = {"type" => "user", "id" => "jerry@the-smiths.com"}.freeze
  ACTION_MANAGEMENT = "in_management_chain"

  def setup
    skip "set TOPAZ_URL to run Topaz integration tests" unless ENV["TOPAZ_URL"]

    @base_url = ENV.fetch("TOPAZ_URL").sub(%r{/+\z}, "")
  end

  def test_discovery_metadata_has_strict_identity_and_all_endpoints
    client = discovered_client

    assert_equal @base_url, client.metadata.fetch("policy_decision_point")
    assert_equal "#{@base_url}/access/v1/evaluation", client.metadata.fetch("access_evaluation_endpoint")
    assert_equal "#{@base_url}/access/v1/evaluations", client.metadata.fetch("access_evaluations_endpoint")
    assert_equal "#{@base_url}/access/v1/search/subject", client.metadata.fetch("search_subject_endpoint")
    assert_equal "#{@base_url}/access/v1/search/resource", client.metadata.fetch("search_resource_endpoint")
    assert_equal "#{@base_url}/access/v1/search/action", client.metadata.fetch("search_action_endpoint")
  end

  def test_single_evaluation_returns_known_allow_and_deny
    client = authzen_client

    assert client.allowed?(subject: SUBJECT_RICK, action: ACTION_MANAGEMENT, resource: RESOURCE_JERRY)
    refute client.allowed?(subject: SUBJECT_JERRY, action: ACTION_MANAGEMENT, resource: RESOURCE_JERRY)
  end

  def test_batch_three_evaluations_accept_default_and_independent_items
    result = authzen_client.evaluations(
      subject: SUBJECT_RICK,
      action: ACTION_MANAGEMENT,
      resource: RESOURCE_JERRY,
      evaluations: [
        {},
        {subject: SUBJECT_JERRY},
        {subject: SUBJECT_BETH}
      ],
      options: {evaluations_semantic: "execute_all"}
    )

    assert_equal [true, false, true], result.fetch("evaluations").map { |entry| entry.fetch("decision") }
  end

  def test_topaz_compatibility_gap_deny_on_first_deny_returns_execute_all_and_is_rejected
    client = authzen_client

    assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
      client.evaluations(
        subject: SUBJECT_RICK,
        action: ACTION_MANAGEMENT,
        resource: RESOURCE_JERRY,
        evaluations: mixed_batch,
        options: {evaluations_semantic: "deny_on_first_deny"}
      )
    end
  end

  def test_topaz_compatibility_gap_permit_on_first_permit_returns_execute_all_and_is_rejected
    client = authzen_client

    assert_raises(ActionPolicy::AuthZEN::InvalidResponse) do
      client.evaluations(
        subject: SUBJECT_RICK,
        action: ACTION_MANAGEMENT,
        resource: RESOURCE_JERRY,
        evaluations: mixed_batch,
        options: {evaluations_semantic: "permit_on_first_permit"}
      )
    end
  end

  def test_all_three_searches_return_entities_that_evaluate_to_allow
    client = authzen_client

    subjects = client.each_subject(subject: {"type" => "user"}, action: ACTION_MANAGEMENT, resource: RESOURCE_JERRY).to_a
    assert_equal ["beth@the-smiths.com", "rick@the-citadel.com"], subjects.map { |entry| entry.fetch("id") }.sort
    subjects.each { |entry| assert client.allowed?(subject: entry, action: ACTION_MANAGEMENT, resource: RESOURCE_JERRY) }

    resources = client.each_resource(subject: SUBJECT_RICK, action: ACTION_MANAGEMENT, resource: {"type" => "user"}).to_a
    assert_includes resources.map { |entry| entry.fetch("id") }, RESOURCE_JERRY.fetch("id")
    resources.each { |entry| assert client.allowed?(subject: SUBJECT_RICK, action: ACTION_MANAGEMENT, resource: entry) }

    actions = client.each_action(subject: SUBJECT_RICK, resource: RESOURCE_JERRY).to_a
    assert_includes actions.map { |entry| entry.fetch("name") }, ACTION_MANAGEMENT
    actions.each { |entry| assert client.allowed?(subject: SUBJECT_RICK, action: entry, resource: RESOURCE_JERRY) }
  end

  def test_topaz_optional_unpaginated_search_returns_all_results_despite_limit
    client = authzen_client
    first = client.search_subjects(
      subject: {"type" => "user"},
      action: ACTION_MANAGEMENT,
      resource: RESOURCE_JERRY,
      page: {limit: 1}
    )

    assert_equal ["beth@the-smiths.com", "rick@the-citadel.com"],
      first.fetch("results").map { |entry| entry.fetch("id") }.sort
    assert_equal "", first.fetch("page").fetch("next_token")
  end

  private

  def mixed_batch
    [
      {},
      {subject: SUBJECT_JERRY},
      {subject: SUBJECT_BETH}
    ]
  end

  def discovered_client
    ActionPolicy::AuthZEN::Client.discover(base_url: @base_url, allow_http: true, open_timeout: 2, read_timeout: 5)
  end

  def authzen_client
    ActionPolicy::AuthZEN::Client.new(base_url: @base_url, allow_http: true, open_timeout: 2, read_timeout: 5)
  end
end
