require_relative "../test_helper"

class OPAIntegrationTest < Minitest::Test
  SUBJECT = {type: "user", id: "alice"}.freeze
  RESOURCE = {type: "document", id: "one"}.freeze

  def setup
    skip "set OPA_URL to run OPA integration tests" unless ENV["OPA_URL"]
    @client = ActionPolicy::AuthZEN::Client.discover(base_url: ENV.fetch("OPA_URL"), allow_http: true)
  end

  def test_discovery_and_action_policy_allow_and_deny
    assert_equal ENV.fetch("OPA_URL"), @client.metadata.fetch("policy_decision_point")
    %w[access_evaluation_endpoint access_evaluations_endpoint search_subject_endpoint search_resource_endpoint search_action_endpoint].each do |endpoint|
      assert @client.metadata.fetch(endpoint).start_with?(ENV.fetch("OPA_URL"))
    end
    policy_class = Class.new(ActionPolicy::Base) do
      include ActionPolicy::AuthZEN::Policy
      def show?
        authzen_allowed?(subject: {type: "user", id: user}, action: "read", resource: record)
      end
    end
    assert policy_class.new(RESOURCE, user: "alice", authzen_client: @client).apply(:show?)
    refute policy_class.new(RESOURCE, user: "mallory", authzen_client: @client).apply(:show?)
  end

  def test_all_batch_semantics_with_mixed_decisions
    {"execute_all" => [true, false, true], "deny_on_first_deny" => [true, false],
     "permit_on_first_permit" => [true]}.each do |semantic, expected|
      result = @client.evaluations(subject: SUBJECT, resource: RESOURCE, action: "read",
        evaluations: [{}, {action: "delete"}, {}], options: {evaluations_semantic: semantic})
      assert_equal expected, result.fetch("evaluations").map { |entry| entry.fetch("decision") }
    end
  end

  def test_all_searches_paginate_and_results_reauthorize
    queries = {
      subject: {subject: {type: "user"}, action: "read", resource: RESOURCE},
      resource: {subject: SUBJECT, action: "read", resource: {type: "document"}},
      action: {subject: SUBJECT, resource: RESOURCE}
    }
    expected = {subject: %w[alice bob], resource: %w[one two], action: %w[read view]}
    queries.each do |kind, query|
      method = {subject: :search_subjects, resource: :search_resources, action: :search_actions}.fetch(kind)
      first = @client.public_send(method, **query, page: {limit: 1})
      assert_equal 1, first.fetch("results").length
      token = first.fetch("page").fetch("next_token")
      refute_empty token
      second = @client.public_send(method, **query, page: {limit: 1, token: token})
      assert_equal 1, second.fetch("results").length
      assert_equal "", second.fetch("page").fetch("next_token")
      results = @client.public_send("each_#{kind}", **query, page: {limit: 1}).to_a
      field = kind == :action ? "name" : "id"
      assert_equal expected.fetch(kind), results.map { |entry| entry.fetch(field) }.sort
      results.each do |entry|
        assert @client.allowed?(**{subject: SUBJECT, action: "read", resource: RESOURCE}.merge(kind => entry))
      end
    end
  end
end
