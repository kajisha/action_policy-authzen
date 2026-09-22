require_relative "test_helper"

class AuthZENTestPolicy < ActionPolicy::Base
  include ActionPolicy::AuthZEN::Policy

  def show?
    authzen_allowed?(subject: {type: "user", id: user}, action: "reader",
      resource: {type: "document", id: record}, context: {tenant: "acme"})
  end
end

class PolicyTest < Minitest::Test
  def test_policy_passes_explicit_mapping_and_uses_decision
    [true, false].each do |decision|
      client = Minitest::Mock.new
      client.expect(:nil?, false)
      client.expect(:allowed?, decision, [], subject: {type: "user", id: "anne"},
        action: "reader", resource: {type: "document", id: "roadmap"}, context: {tenant: "acme"})
      policy = AuthZENTestPolicy.new("roadmap", user: "anne", authzen_client: client)
      assert_equal decision, policy.apply(:show?)
      client.verify
    end
  end

  def test_missing_client_fails_explicitly
    assert_raises(ActionPolicy::AuthorizationContextMissing) do
      AuthZENTestPolicy.new("roadmap", user: "anne")
    end
  end

  def test_transport_error_propagates_and_is_not_cached_as_an_allow
    client = Struct.new(:unavailable) do
      def allowed?(**)
        raise ActionPolicy::AuthZEN::TransportError, "unavailable" if unavailable
        false
      end
    end.new(true)
    policy = AuthZENTestPolicy.new("roadmap", user: "anne", authzen_client: client)
    assert_raises(ActionPolicy::AuthZEN::TransportError) { policy.apply(:show?) }
    client.unavailable = false
    refute policy.apply(:show?)
  end

  def test_does_not_modify_unrelated_policies
    refute ActionPolicy::Base.authorization_targets.key?(:authzen_client)
  end

  def test_batch_response_is_not_mistaken_for_a_boolean_policy_decision
    client = Object.new
    def client.evaluations(**request)
      {"evaluations" => request.fetch(:evaluations).map { |entry| {"decision" => entry.fetch(:action) == "reader"} }}
    end
    policy_class = Class.new(ActionPolicy::Base) do
      include ActionPolicy::AuthZEN::Policy

      def manage?
        authzen_evaluations(subject: {type: "user", id: user}, resource: {type: "document", id: record},
          evaluations: [{action: "reader"}, {action: "writer"}]).fetch("evaluations").all? { |entry| entry.fetch("decision") }
      end
    end
    refute policy_class.new("roadmap", user: "anne", authzen_client: client).apply(:manage?)
  end

  def test_search_iterator_can_define_an_action_policy_scope
    client = Object.new
    def client.each_resource(**)
      [{"type" => "document", "id" => "roadmap"}].each
    end
    policy_class = Class.new(ActionPolicy::Base) do
      include ActionPolicy::AuthZEN::Policy

      scope_for :array do |records|
        ids = authzen_each_resource(subject: {type: "user", id: user}, action: "reader",
          resource: {type: "document"}).map { |entry| entry.fetch("id") }
        records.select { |record| ids.include?(record.fetch(:id)) }
      end
    end
    policy = policy_class.new(user: "anne", authzen_client: client)
    assert_equal [{id: "roadmap"}], policy.apply_scope([{id: "roadmap"}, {id: "secret"}], type: :array)
  end
end
