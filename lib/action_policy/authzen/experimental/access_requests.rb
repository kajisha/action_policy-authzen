require "json"
require "net/http"
require "date"
require "time"
require "uri"

module ActionPolicy
  module AuthZEN
    module Experimental
      class AccessRequests
        STATES = %w[pending approved denied expired cancelled failed partial].freeze
        TERMINAL_STATES = %w[approved denied expired cancelled failed partial].freeze
        PROBLEM_TYPES = %w[
          urn:openid:authzen:access-request:error:not_requestable
          urn:openid:authzen:access-request:error:expired_denial
          urn:openid:authzen:access-request:error:invalid_denial_binding
          urn:openid:authzen:access-request:error:duplicate_request
          urn:openid:authzen:access-request:error:unknown_task
          urn:openid:authzen:access-request:error:task_expired
          urn:openid:authzen:access-request:error:invalid_task_state
        ].freeze

        Offer = Struct.new(
          :owner,
          :pdp_identifier,
          :service_identity,
          :endpoint,
          :expires_at,
          :binding_token,
          :evaluation_id,
          :request_snapshot,
          :response_snapshot,
          :access_request,
          keyword_init: true
        ) do
          def initialize(**values)
            super
            each_pair { |_key, value| AccessRequests.deep_freeze_value(value) }
            freeze
          end
        end

        State = Struct.new(
          :owner,
          :pdp_identifier,
          :service_identity,
          :task_id,
          :status,
          :status_endpoint,
          :task_expires_at,
          :result,
          :approval,
          :earliest_next_fetch_at,
          :offer,
          keyword_init: true
        ) do
          def initialize(**values)
            super
            each_pair { |_key, value| AccessRequests.deep_freeze_value(value) }
            freeze
          end

          def approved?
            status == "approved" && approval.is_a?(Hash)
          end
        end

        def initialize(metadata:, submission_url:, status_url_prefix:, service_headers: {},
          topology: :shared_state, clock: -> { Time.now.utc }, open_timeout: 2,
          read_timeout: 5, ca_file: nil, allow_http: false)
          @allow_http = allow_http == true
          @metadata = deep_copy_json(metadata, "metadata")
          @pdp_identifier = validate_metadata_identity(@metadata)
          @submission_url = parse_endpoint(submission_url, "submission_url", exact: true)
          @status_url_prefix = parse_endpoint(status_url_prefix, "status_url_prefix", exact: false)
          @status_prefix = @status_url_prefix.to_s.end_with?("/") ? @status_url_prefix.to_s : "#{@status_url_prefix}/"
          @service_headers = normalize_headers(service_headers)
          @service_identity = "#{@submission_url}|#{@status_prefix}".freeze
          @owner_token = Object.new.freeze
          @issued_offers = ObjectSpace::WeakMap.new
          @issued_states = ObjectSpace::WeakMap.new
          @topology = topology.to_sym
          unless %i[shared_state independent].include?(@topology)
            raise ArgumentError, "topology must be :shared_state or :independent"
          end
          @clock = clock
          @open_timeout = positive_timeout(open_timeout)
          @read_timeout = positive_timeout(read_timeout)
          @ca_file = ca_file
        end

        def self.deep_freeze_value(value)
          case value
          when Hash
            value.each_value { |child| deep_freeze_value(child) }
          when Array
            value.each { |child| deep_freeze_value(child) }
          end
          value.freeze
        end

        def offer_for(request:, response:)
          request_snapshot = normalize_request(request)
          response_snapshot = deep_copy_json(response, "response")
          raise ArgumentError, "response decision must be false" unless response_snapshot["decision"] == false

          context = response_snapshot["context"]
          raise InvalidResponse, "response context must be an object" if response_snapshot.key?("context") && !context.is_a?(Hash)
          return nil unless context&.key?("access_request")

          access_request = object(context["access_request"], "context.access_request")
          unsupported_form = access_request["request_schema_url"] || access_request["request_catalogs_url"]
          validate_offer_endpoint(access_request["endpoint"]) if access_request.key?("endpoint")
          expires_at = parse_rfc3339(access_request["expires_at"], "context.access_request.expires_at")
          raise InvalidResponse, "access request offer has expired" unless expires_at > now

          binding_token = access_request["binding_token"]
          raise InvalidResponse, "context.access_request.binding_token must be a string" if access_request.key?("binding_token") && !binding_token.is_a?(String)
          evaluation_id = context["evaluation_id"]
          raise InvalidResponse, "context.evaluation_id must be a string" if context.key?("evaluation_id") && !evaluation_id.is_a?(String)
          raise InvalidResponse, "context.access_request requires binding_token or context.evaluation_id" unless binding_token || evaluation_id
          if @topology == :independent && !binding_token
            raise UnsupportedFeature, "independent access-request topology requires binding_token"
          end

          if unsupported_form
            raise InvalidResponse, "request_schema_url must be a string" if access_request.key?("request_schema_url") && !access_request["request_schema_url"].is_a?(String)
            raise InvalidResponse, "request_catalogs_url must be a string" if access_request.key?("request_catalogs_url") && !access_request["request_catalogs_url"].is_a?(String)
          end

          endpoint = access_request["endpoint"] || metadata_endpoint
          validate_submission_url(parse_endpoint(endpoint, "access request endpoint", exact: true))

          offer = Offer.new(
            owner: @owner_token,
            pdp_identifier: @pdp_identifier,
            service_identity: @service_identity,
            endpoint: endpoint,
            expires_at: expires_at,
            binding_token: binding_token,
            evaluation_id: evaluation_id,
            request_snapshot: deep_freeze(request_snapshot),
            response_snapshot: deep_freeze(response_snapshot),
            access_request: deep_freeze(access_request)
          )
          @issued_offers[offer] = true
          offer
        end

        def create(offer:, idempotency_key:)
          validate_offer(offer)
          raise InvalidResponse, "access request offer has expired" unless offer.expires_at > now
          validate_idempotency_key(idempotency_key)
          if offer.access_request["request_schema_url"] || offer.access_request["request_catalogs_url"]
            raise UnsupportedFeature, "access request forms and catalogs are unsupported"
          end

          body = submission_body(offer)
          response = request_json(:post, @submission_url, body, {"Idempotency-Key" => idempotency_key})
          unless %w[201 202].include?(response.code)
            raise_http_error(response)
          end
          validate_json_content_type(response, "access request response")

          state_from_response(parse_json_object(response.body, "Invalid access request response"), response["retry-after"], offer)
        end

        def fetch(receipt: nil, state: nil)
          receipt ||= state
          validate_state(receipt)
          if receipt.earliest_next_fetch_at && receipt.earliest_next_fetch_at > now
            raise UnsupportedFeature, "access request status fetch is premature"
          end
          if receipt.task_expires_at && receipt.task_expires_at <= now
            raise UnsupportedFeature, "access request task has expired"
          end

          uri = parse_response_endpoint(receipt.status_endpoint, "task.status_endpoint", exact: true)
          validate_status_url(uri)
          response = request_json(:get, uri)
          raise_http_error(response) unless response.code == "200"
          validate_json_content_type(response, "access request status response")

          state_from_response(parse_json_object(response.body, "Invalid access request status response"), response["retry-after"], receipt.offer || receipt, previous: receipt)
        end

        def reevaluation_request(state:, request:)
          validate_state(state)
          unless state.approved?
            raise UnsupportedFeature, "access request state is not approved for re-evaluation"
          end
          approval = state.approval
          approved_until = parse_rfc3339(approval["approved_until"], "result.approval.approved_until")
          raise UnsupportedFeature, "access request approval has expired" unless approved_until > now

          snapshot = deep_copy_preserving_keys(request, "request")
          existing_context = snapshot[:context] || snapshot["context"]
          if existing_context.is_a?(Hash) && (existing_context.key?(:approval) || existing_context.key?("approval"))
            raise ArgumentError, "request context already contains approval"
          end

          normalized_current = normalize_request(request)
          unless state.offer.is_a?(Offer) && normalized_current == state.offer.request_snapshot
            raise UnsupportedFeature, "re-evaluation request must exactly match the approved access request"
          end

          context = existing_context ? deep_copy_preserving_keys(existing_context, "request.context") : {}
          context["approval"] = deep_copy_json(approval, "result.approval")
          retry_request = {
            subject: top_level_request_value(snapshot, :subject),
            action: top_level_request_value(snapshot, :action),
            resource: top_level_request_value(snapshot, :resource),
            context: context
          }
          deep_freeze(retry_request)
        end

        private

        def top_level_request_value(snapshot, key)
          snapshot.key?(key) ? snapshot.fetch(key) : snapshot.fetch(key.to_s)
        end

        def metadata_endpoint
          endpoint = @metadata["access_request_endpoint"]
          raise InvalidResponse, "metadata requires access_request_endpoint" unless endpoint.is_a?(String)

          endpoint
        end

        def validate_metadata_identity(metadata)
          pdp = metadata["policy_decision_point"]
          raise InvalidResponse, "metadata requires policy_decision_point" unless pdp.is_a?(String)
          parse_endpoint(pdp, "policy_decision_point metadata", exact: false)
          evaluation = metadata["access_evaluation_endpoint"]
          raise InvalidResponse, "metadata requires access_evaluation_endpoint" unless evaluation.is_a?(String)
          parse_endpoint(evaluation, "access_evaluation_endpoint metadata", exact: true)
          pdp.freeze
        end

        def submission_body(offer)
          context = offer.request_snapshot["context"]
          access_request = offer.access_request
          denial = {
            "expires_at" => access_request.fetch("expires_at")
          }
          denial["evaluation_id"] = offer.evaluation_id if offer.evaluation_id
          denial["evaluated_at"] = offer.response_snapshot.dig("context", "evaluated_at") if offer.response_snapshot.dig("context", "evaluated_at")
          denial["reason"] = offer.response_snapshot.dig("context", "reason") if offer.response_snapshot.dig("context", "reason")
          denial["binding_token"] = offer.binding_token if offer.binding_token
          denial["template"] = access_request["template"] if access_request["template"]

          body = {
            "subject" => offer.request_snapshot.fetch("subject"),
            "resource" => offer.request_snapshot.fetch("resource"),
            "action" => action_object(offer.request_snapshot.fetch("action")),
            "denial" => denial
          }
          body["context"] = context if context
          body
        end

        def action_object(action)
          action.is_a?(String) ? {"name" => action} : action
        end

        def state_from_response(body, retry_after, offer_or_state, previous: nil)
          task = object(body["task"], "task")
          raise UnsupportedFeature, "bulk access request tasks are unsupported" if task.key?("items")

          task_id = string_field(task, "id", "task.id")
          status = string_field(task, "status", "task.status")
          status_endpoint = task["status_endpoint"] || previous&.status_endpoint
          status_endpoint = string_field({"status_endpoint" => status_endpoint}, "status_endpoint", "task.status_endpoint")
          validate_status_url(parse_response_endpoint(status_endpoint, "task.status_endpoint", exact: true))
          if previous
            raise InvalidResponse, "access request status task.id mismatch" unless task_id == previous.task_id
            raise InvalidResponse, "access request status_endpoint changed" unless status_endpoint == previous.status_endpoint
            if TERMINAL_STATES.include?(previous.status) && previous.status != status
              raise InvalidResponse, "access request terminal task status changed"
            end
          end

          task_expires_at = task.key?("expires_at") ? parse_rfc3339(task["expires_at"], "task.expires_at") : previous&.task_expires_at
          result = body["result"] ? object(body["result"], "result") : nil
          approval = approval_from(status, result)
          earliest = parse_retry_after(retry_after)

          state = State.new(
            owner: @owner_token,
            pdp_identifier: @pdp_identifier,
            service_identity: @service_identity,
            task_id: task_id,
            status: status,
            status_endpoint: status_endpoint,
            task_expires_at: task_expires_at,
            result: deep_freeze(result),
            approval: deep_freeze(approval),
            earliest_next_fetch_at: earliest,
            offer: previous&.offer || offer_or_state
          )
          @issued_states[state] = true
          state
        end

        def approval_from(status, result)
          return nil unless status == "approved"
          raise InvalidResponse, "approved access request task requires result" unless result
          mode = string_field(result, "mode", "result.mode")
          return nil unless mode == "reevaluate"

          approval = object(result["approval"], "result.approval")
          string_field(approval, "id", "result.approval.id")
          parse_rfc3339(approval["approved_until"], "result.approval.approved_until")
          parse_rfc3339(approval["approved_at"], "result.approval.approved_at") if approval.key?("approved_at")
          approval
        end

        def request_json(method, uri, body = nil, extra_headers = {})
          request = if method == :post
            Net::HTTP::Post.new(uri, @service_headers.merge(extra_headers))
          else
            Net::HTTP::Get.new(uri, @service_headers.merge(extra_headers))
          end
          request["Accept"] = "application/json"
          if body
            request["Content-Type"] = "application/json"
            request.body = JSON.generate(body)
          end

          perform(uri, request)
        end

        def perform(uri, request)
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = uri.scheme == "https"
          http.ca_file = @ca_file if @ca_file
          http.open_timeout = @open_timeout
          http.read_timeout = @read_timeout
          http.write_timeout = @read_timeout
          http.max_retries = 0
          http.start { |connection| connection.request(request) }
        rescue Timeout::Error, SocketError, SystemCallError, IOError, OpenSSL::SSL::SSLError, Net::ProtocolError => error
          raise TransportError, "AuthZEN access request failed (#{error.class})", cause: error
        end

        def raise_http_error(response)
          raise HTTPError.new(response.code.to_i,
            problem_type: problem_type(response),
            retry_after: parse_retry_after(response["retry-after"]))
        end

        def parse_json_object(body, message)
          result = JSON.parse(body, object_class: duplicate_rejecting_hash_class, allow_duplicate_key: false)
          raise InvalidResponse, "#{message}: root must be an object" unless result.is_a?(Hash)

          result
        rescue JSON::ParserError, TypeError, DuplicateJSONKey
          raise InvalidResponse, message, cause: nil
        end

        def duplicate_rejecting_hash_class
          Class.new(Hash) do
            def []=(key, value)
              raise ActionPolicy::AuthZEN::Experimental::DuplicateJSONKey if key?(key)
              super
            end
          end
        end

        def parse_retry_after(value)
          return nil if value.nil? || value.empty?
          return now + Integer(value, 10) if value.match?(/\A[0-9]+\z/)

          Time.httpdate(value)
        rescue ArgumentError
          raise InvalidResponse, "Retry-After must be delta-seconds or HTTP-date"
        end

        def parse_rfc3339(value, label)
          raise InvalidResponse, "#{label} must be a string" unless value.is_a?(String)
          match = value.match(/\A(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})\z/)
          unless match
            raise InvalidResponse, "#{label} must be an RFC3339 timestamp"
          end
          year, month, day, hour, minute, second = match.captures.map(&:to_i)
          unless Date.valid_date?(year, month, day) && hour <= 23 && minute <= 59 && second <= 59
            raise InvalidResponse, "#{label} must be an RFC3339 timestamp"
          end

          Time.iso8601(value)
        rescue ArgumentError
          raise InvalidResponse, "#{label} must be an RFC3339 timestamp"
        end

        def positive_timeout(value)
          unless value.is_a?(Numeric) && value.positive? && value.finite?
            raise ArgumentError, "timeouts must be positive finite numbers"
          end
          value
        end

        def object(value, label)
          raise InvalidResponse, "#{label} must be an object" unless value.is_a?(Hash)

          value
        end

        def string_field(hash, key, label)
          value = hash[key]
          raise InvalidResponse, "#{label} must be a string" unless value.is_a?(String)

          value
        end

        def validate_offer(offer)
          raise ArgumentError, "offer is required" unless offer.is_a?(Offer)
          raise ArgumentError, "offer was not created by this access request client" unless @issued_offers[offer]
          unless offer.owner.equal?(@owner_token) && offer.pdp_identifier == @pdp_identifier && offer.service_identity == @service_identity
            raise ArgumentError, "offer was not created by this access request client"
          end
          raise ArgumentError, "offer endpoint does not match configured submission_url" unless offer.endpoint == @submission_url.to_s
        end

        def validate_state(state)
          raise ArgumentError, "state is required" unless state.is_a?(State)
          raise ArgumentError, "state was not created by this access request client" unless @issued_states[state]
          unless state.owner.equal?(@owner_token) && state.pdp_identifier == @pdp_identifier && state.service_identity == @service_identity
            raise ArgumentError, "state was not created by this access request client"
          end
          raise ArgumentError, "state is missing original offer provenance" unless state.offer.is_a?(Offer)
        end

        def validate_offer_endpoint(endpoint)
          validate_submission_url(parse_response_endpoint(endpoint, "context.access_request.endpoint", exact: true))
        end

        def validate_submission_url(uri)
          unless uri == @submission_url
            raise InvalidResponse, "access request endpoint is outside configured trust"
          end
        end

        def validate_status_url(uri)
          text = uri.to_s
          unless text.start_with?(@status_prefix) && text.length > @status_prefix.length
            raise InvalidResponse, "task.status_endpoint is outside configured trust"
          end
          remainder = text[@status_prefix.length..]
          if remainder.include?("/") || remainder.empty?
            raise InvalidResponse, "task.status_endpoint must remain within the configured path namespace"
          end
        end

        def parse_endpoint(value, label, exact:)
          raise ArgumentError, "#{label} must be a URL string" unless value.is_a?(String)
          uri = URI.parse(value)
          unless uri.is_a?(URI::HTTP) && uri.host && !uri.host.empty? && !uri.userinfo && !uri.fragment
            raise ArgumentError, "#{label} must be an absolute HTTP(S) URL without credentials or fragment"
          end
          if uri.scheme != "https" && !@allow_http
            raise ArgumentError, "#{label} requires HTTPS; allow_http: true is for local testing"
          end
          raise ArgumentError, "#{label} must not contain a query" if uri.query
          validate_canonical_path(uri, label)
          if exact && uri.path.to_s.end_with?("/")
            raise ArgumentError, "#{label} must be an exact endpoint URL"
          end

          uri
        rescue URI::InvalidURIError
          raise ArgumentError, "#{label} must be an absolute HTTP(S) URL"
        end

        def parse_response_endpoint(value, label, exact:)
          parse_endpoint(value, label, exact: exact)
        rescue ArgumentError => error
          raise InvalidResponse, error.message
        end

        def validate_canonical_path(uri, label)
          path = uri.path.to_s
          if path.include?("%") || path.split("/").include?("..") || path.split("/").include?(".") ||
              path.include?("\\")
            raise ArgumentError, "#{label} must not contain traversal or percent encoding"
          end
        end

        def validate_json_content_type(response, label)
          content_type = response["content-type"].to_s.split(";", 2).first.to_s.strip.downcase
          raise InvalidResponse, "#{label} Content-Type must be application/json" unless content_type == "application/json"
        end

        def problem_type(response)
          content_type = response["content-type"].to_s.split(";", 2).first.to_s.strip.downcase
          return nil unless content_type == "application/problem+json"

          problem = parse_json_object(response.body, "Invalid access request problem response")
          type = problem["type"]
          return nil unless PROBLEM_TYPES.include?(type)

          type
        rescue InvalidResponse
          nil
        end

        def normalize_headers(headers)
          raise ArgumentError, "service_headers must be an object" unless headers.is_a?(Hash)

          headers.each_with_object({}) do |(key, value), normalized|
            raise ArgumentError, "service header names must be strings" unless key.is_a?(String)
            raise ArgumentError, "service header values must be strings" unless value.is_a?(String)
            if key.match?(/[\r\n]/) || value.match?(/[\r\n]/)
              raise ArgumentError, "service headers must not contain CR/LF"
            end
            normalized[key] = value
          end.freeze
        end

        def validate_idempotency_key(value)
          raise ArgumentError, "idempotency_key must be a string" unless value.is_a?(String) && !value.empty?
          raise ArgumentError, "idempotency_key must not contain CR/LF" if value.match?(/[\r\n]/)
        end

        def deep_copy_json(value, label)
          reject_conflicting_keys(value, label)
          JSON.parse(JSON.generate(value))
        rescue JSON::GeneratorError, TypeError => error
          raise ArgumentError, "#{label} must be JSON-compatible", cause: error
        end

        def deep_copy_preserving_keys(value, label)
          reject_conflicting_keys(value, label)
          copy_json_value(value, label)
        end

        def normalize_request(value)
          request = deep_copy_json(value, "request")
          subject = entity_object(request["subject"], %w[type id], "subject")
          resource = entity_object(request["resource"], %w[type id], "resource")
          action = action_value(request["action"])
          context = request["context"]
          raise ArgumentError, "context must be an object" if request.key?("context") && !context.is_a?(Hash)

          normalized = {"subject" => subject, "resource" => resource, "action" => action}
          normalized["context"] = context if request.key?("context")
          deep_freeze(normalized)
        end

        def entity_object(value, required, label)
          raise ArgumentError, "#{label} must be an object" unless value.is_a?(Hash)
          required.each do |key|
            raise ArgumentError, "#{label}.#{key} must be a string" unless value[key].is_a?(String)
          end
          if value.key?("properties") && !value["properties"].is_a?(Hash)
            raise ArgumentError, "#{label}.properties must be an object"
          end
          value
        end

        def action_value(value)
          action = value.is_a?(String) ? {"name" => value} : value
          raise ArgumentError, "action must be a string or object" unless action.is_a?(Hash)
          raise ArgumentError, "action.name must be a string" unless action["name"].is_a?(String)
          if action.key?("properties") && !action["properties"].is_a?(Hash)
            raise ArgumentError, "action.properties must be an object"
          end
          action
        end

        def copy_json_value(value, label)
          case value
          when Hash
            value.each_with_object({}) { |(key, child), copy| copy[key] = copy_json_value(child, "#{label}.#{key}") }
          when Array
            value.each_with_index.map { |child, index| copy_json_value(child, "#{label}[#{index}]") }
          when String
            value.dup
          when Numeric, true, false, nil
            value
          else
            raise ArgumentError, "#{label} must be JSON-compatible"
          end
        end

        def reject_conflicting_keys(value, label)
          case value
          when Hash
            seen = {}
            value.each do |key, child|
              string_key = key.to_s
              raise ArgumentError, "#{label} contains conflicting keys for #{string_key}" if seen.key?(string_key)
              seen[string_key] = true
              reject_conflicting_keys(child, "#{label}.#{string_key}")
            end
          when Array
            value.each_with_index { |child, index| reject_conflicting_keys(child, "#{label}[#{index}]") }
          end
        end

        def deep_freeze(value)
          case value
          when Hash
            value.each_value { |child| deep_freeze(child) }
          when Array
            value.each { |child| deep_freeze(child) }
          end
          value.freeze
        end

        def now
          time = @clock.call
          time.respond_to?(:utc) ? time.utc : time
        end
      end
    end
  end
end
