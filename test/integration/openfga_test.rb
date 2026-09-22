require_relative "../test_helper"

require "json"
require "net/http"
require "securerandom"
require "uri"

class OpenFGAIntegrationTest < Minitest::Test
  class Application
    include ActionPolicy::Behaviour
  end

  class DocumentPolicy < ActionPolicy::Base
    include ActionPolicy::AuthZEN::Policy

    def read?
      authzen_allowed?(
        subject: {"type" => "user", "id" => user},
        action: "reader",
        resource: {"type" => "document", "id" => record.fetch(:id)}
      )
    end

    def write?
      authzen_allowed?(
        subject: {"type" => "user", "id" => user},
        action: {"name" => "writer"},
        resource: {"type" => "document", "id" => record.fetch(:id)}
      )
    end
  end

  def setup
    skip "set OPENFGA_URL to run OpenFGA integration tests" unless ENV["OPENFGA_URL"]

    @base_url = ENV.fetch("OPENFGA_URL").sub(%r{/+\z}, "")
    @store_id = nil
    create_store
    write_authorization_model
    write_tuples
  end

  def teardown
    delete_store if @store_id
  end

  def test_action_policy_apply_allow_and_deny_match_native_check
    client = authzen_client
    policy = DocumentPolicy.new({id: "roadmap"}, user: "anne", authzen_client: client)

    assert_equal native_check(user: "user:anne", relation: "reader", object: "document:roadmap"), client.allowed?(
      subject: {"type" => "user", "id" => "anne"},
      action: "reader",
      resource: {"type" => "document", "id" => "roadmap"}
    )
    assert_equal native_check(user: "user:anne", relation: "writer", object: "document:roadmap"), client.allowed?(
      subject: {"type" => "user", "id" => "anne"},
      action: {"name" => "writer"},
      resource: {"type" => "document", "id" => "roadmap"}
    )
    assert_equal true, policy.apply(:read?)
    assert_equal false, policy.apply(:write?)

    application = Application.new
    record = {id: "roadmap"}
    context = {user: "anne", authzen_client: client}
    assert_equal record, application.authorize!(record, to: :read?, with: DocumentPolicy, context: context)
    assert_raises(ActionPolicy::Unauthorized) do
      application.authorize!(record, to: :write?, with: DocumentPolicy, context: context)
    end
    assert_raises(ActionPolicy::Unauthorized) do
      application.authorize!(record, to: :read?, with: DocumentPolicy,
        context: context.merge(user: "bob"))
    end
    refute DocumentPolicy.new({id: "other"}, **context).apply(:read?)
  end

  def test_explicit_context_and_properties_are_forwarded_to_conditions
    subject = {"type" => "user", "id" => "anne", "properties" => {"region" => "emea"}}
    action = {"name" => "reader", "properties" => {"scope" => "internal"}}
    resource = {"type" => "document", "id" => "briefing", "properties" => {"region" => "emea"}}
    context = {"request_purpose" => "preview"}

    native_allowed = native_check(
      user: "user:anne",
      relation: "reader",
      object: "document:briefing",
      context: {
        "subject_region" => "emea",
        "action_scope" => "internal",
        "resource_region" => "emea",
        "request_purpose" => "preview"
      }
    )

    assert_equal true, native_allowed
    assert_equal native_allowed, authzen_client.allowed?(
      subject: subject,
      action: action,
      resource: resource,
      context: context
    )
    assert_equal false, authzen_client.allowed?(
      subject: subject,
      action: action,
      resource: resource.merge("properties" => {"region" => "apac"}),
      context: context
    )
  end

  def test_discovery_and_all_batch_semantics
    client = ActionPolicy::AuthZEN::Client.discover(
      allow_http: true,
      base_url: "#{@base_url}/stores/#{@store_id}",
      metadata_url: "#{@base_url}/.well-known/authzen-configuration/#{@store_id}",
      headers: {"Openfga-Authorization-Model-Id" => @model_id}
    )
    request = {subject: {type: "user", id: "anne"}, resource: {type: "document", id: "roadmap"}}
    {"execute_all" => [true, false, true], "deny_on_first_deny" => [true, false],
     "permit_on_first_permit" => [true]}.each do |semantic, decisions|
      result = client.evaluations(**request,
        evaluations: [{action: "reader"}, {action: "writer"}, {action: "reader"}],
        options: {evaluations_semantic: semantic})
      assert_equal decisions, result.fetch("evaluations").map { |entry| entry.fetch("decision") }
    end
    assert client.allowed?(**request, action: "reader")
    assert_equal "#{@base_url}/stores/#{@store_id}", client.metadata.fetch("policy_decision_point")
  end

  def test_all_three_searches_return_entities_that_evaluate_to_allow
    client = authzen_client
    subject = {type: "user", id: "anne"}
    resource = {type: "document", id: "roadmap"}
    subjects = client.each_subject(subject: {type: "user"}, action: "reader", resource: resource).to_a
    assert_equal ["anne"], subjects.map { |entry| entry.fetch("id") }
    subjects.each { |entry| assert client.allowed?(subject: entry, action: "reader", resource: resource) }

    actions = client.each_action(subject: subject, resource: resource).to_a
    assert_equal ["reader"], actions.map { |entry| entry.fetch("name") }
    actions.each { |entry| assert client.allowed?(subject: subject, action: entry, resource: resource) }

    context = {subject_region: "emea", action_scope: "internal", resource_region: "emea", request_purpose: "preview"}
    resources = client.each_resource(subject: subject, action: "reader", resource: {type: "document"}, context: context).to_a
    assert_equal %w[briefing roadmap], resources.map { |entry| entry.fetch("id") }.sort
    resources.each { |entry| assert client.allowed?(subject: subject, action: "reader", resource: entry, context: context) }
  end

  private

  def create_store
    response = post_json("/stores", {"name" => "action-policy-authzen-#{SecureRandom.hex(8)}"})
    @store_id = response.fetch("id")
  end

  def write_authorization_model
    response = post_json("/stores/#{@store_id}/authorization-models", authorization_model)
    @model_id = response.fetch("authorization_model_id")
  end

  def write_tuples
    post_json("/stores/#{@store_id}/write", {
      "authorization_model_id" => @model_id,
      "writes" => {
        "tuple_keys" => [
          {"user" => "user:anne", "relation" => "reader", "object" => "document:roadmap"},
          {
            "user" => "user:anne",
            "relation" => "reader",
            "object" => "document:briefing",
            "condition" => {
              "name" => "region_scope_match",
              "context" => {"required_scope" => "internal"}
            }
          }
        ]
      }
    })
  end

  def delete_store
    request_json(Net::HTTP::Delete, "/stores/#{@store_id}", nil)
  ensure
    @store_id = nil
  end

  def authzen_client
    ActionPolicy::AuthZEN::Client.new(
      allow_http: true,
      base_url: "#{@base_url}/stores/#{@store_id}",
      headers: {"Openfga-Authorization-Model-Id" => @model_id},
      open_timeout: 2,
      read_timeout: 5
    )
  end

  def native_check(user:, relation:, object:, context: nil)
    payload = {
      "authorization_model_id" => @model_id,
      "tuple_key" => {"user" => user, "relation" => relation, "object" => object}
    }
    payload["context"] = context if context

    post_json("/stores/#{@store_id}/check", payload).fetch("allowed")
  end

  def post_json(path, payload)
    request_json(Net::HTTP::Post, path, payload)
  end

  def request_json(verb, path, payload)
    uri = URI("#{@base_url}#{path}")
    request = verb.new(uri)
    request["Accept"] = "application/json"
    request["Content-Type"] = "application/json"
    request.body = JSON.generate(payload) if payload

    response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https", open_timeout: 2, read_timeout: 5) do |http|
      http.request(request)
    end
    return nil if response.code == "204"

    body = response.body.nil? || response.body.empty? ? {} : JSON.parse(response.body)
    unless response.is_a?(Net::HTTPSuccess)
      flunk "OpenFGA #{verb::METHOD} #{path} returned HTTP #{response.code}: #{body.inspect}"
    end
    body
  end

  def authorization_model
    {
      "schema_version" => "1.1",
      "type_definitions" => [
        {"type" => "user"},
        {
          "type" => "document",
          "relations" => {
            "reader" => {"this" => {}},
            "writer" => {"this" => {}}
          },
          "metadata" => {
            "relations" => {
              "reader" => {
                "directly_related_user_types" => [
                  {"type" => "user"},
                  {"type" => "user", "condition" => "region_scope_match"}
                ]
              },
              "writer" => {
                "directly_related_user_types" => [
                  {"type" => "user"}
                ]
              }
            }
          }
        }
      ],
      "conditions" => {
        "region_scope_match" => {
          "name" => "region_scope_match",
          "expression" => "subject_region == resource_region && action_scope == required_scope && request_purpose == \"preview\"",
          "parameters" => {
            "subject_region" => {"type_name" => "TYPE_NAME_STRING"},
            "resource_region" => {"type_name" => "TYPE_NAME_STRING"},
            "action_scope" => {"type_name" => "TYPE_NAME_STRING"},
            "required_scope" => {"type_name" => "TYPE_NAME_STRING"},
            "request_purpose" => {"type_name" => "TYPE_NAME_STRING"}
          }
        }
      }
    }
  end
end
