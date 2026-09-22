require "json"
require "net/http"
require "securerandom"
require "uri"

module ActionPolicy
  module AuthZEN
    class Error < StandardError; end
    class TransportError < Error; end
    class InvalidResponse < Error; end
    class UnsupportedEndpoint < Error; end

    class HTTPError < Error
      attr_reader :status

      def initialize(status)
        @status = status
        super("AuthZEN request returned HTTP #{status}")
      end
    end

    class Client
      DEFAULT_PATHS = {
        evaluation: "/access/v1/evaluation",
        evaluations: "/access/v1/evaluations",
        search_subject: "/access/v1/search/subject",
        search_resource: "/access/v1/search/resource",
        search_action: "/access/v1/search/action"
      }.freeze

      METADATA_ENDPOINTS = {
        evaluation: "access_evaluation_endpoint",
        evaluations: "access_evaluations_endpoint",
        search_subject: "search_subject_endpoint",
        search_resource: "search_resource_endpoint",
        search_action: "search_action_endpoint"
      }.freeze

      EVALUATION_SEMANTICS = %w[execute_all deny_on_first_deny permit_on_first_permit].freeze

      attr_reader :metadata

      def self.discover(base_url:, metadata_url: nil, trusted_origins: [], **options)
        unless (options.keys & %i[endpoint endpoints metadata discovered]).empty?
          raise ArgumentError, "discovery endpoints must come from PDP metadata"
        end
        new(base_url: base_url, metadata_url: metadata_url, trusted_origins: trusted_origins, **options).tap(&:configuration)
      end

      def initialize(endpoint: nil, base_url: nil, endpoints: {}, metadata_url: nil,
        headers: {}, open_timeout: 2, read_timeout: 5, ca_file: nil, trusted_origins: [], allow_http: false)
        raise ArgumentError, "base_url or endpoint is required" if endpoint.nil? && base_url.nil?

        @allow_http = allow_http == true
        @base_url = base_url.nil? ? nil : parse_base_url(base_url, "base_url")
        @pdp_identifier = base_url&.dup&.freeze
        @metadata_url = metadata_url.nil? ? nil : parse_endpoint(metadata_url, "metadata_url")
        @endpoints = {}
        @endpoints[:evaluation] = parse_endpoint(endpoint, "endpoint") unless endpoint.nil?
        endpoints.each do |operation, value|
          key = operation.to_sym
          raise ArgumentError, "unknown AuthZEN endpoint #{operation.inspect}" unless DEFAULT_PATHS.key?(key)

          @endpoints[key] = parse_endpoint(value, "endpoints[#{operation.inspect}]")
        end

        @headers = headers.dup.freeze
        @open_timeout = positive_timeout(open_timeout)
        @read_timeout = positive_timeout(read_timeout)
        @ca_file = ca_file
        @metadata = nil
        @trusted_origins = trusted_origins.map { |origin| normalize_origin(origin) }.freeze
        @discovered = false
      rescue URI::InvalidURIError
        raise ArgumentError, "AuthZEN URLs must be absolute HTTP(S) URLs"
      end

      def evaluate(subject:, action:, resource:, context: nil)
        result = post(:evaluation, evaluation_payload(subject: subject, action: action, resource: resource, context: context))
        validate_decision(result, "AuthZEN response")
        result
      end

      def allowed?(**request)
        evaluate(**request).fetch("decision")
      end

      def evaluations(evaluations: nil, subject: nil, action: nil, resource: nil, context: nil, options: nil)
        payload = evaluations_payload(evaluations: evaluations, subject: subject, action: action,
          resource: resource, context: context, options: options)
        result = post(:evaluations, payload)
        single_request = evaluations.nil? || evaluations.empty?
        count = single_request ? 1 : evaluations.length
        semantic = payload.dig("options", "evaluations_semantic") || "execute_all"
        validate_evaluations_response(result, count, semantic, single_request: single_request)
        result
      end

      def search_subjects(subject:, action:, resource:, context: nil, page: nil)
        search(:search_subject, :subject, subject: subject, action: action, resource: resource,
          context: context, page: page)
      end

      def search_resources(subject:, action:, resource:, context: nil, page: nil)
        search(:search_resource, :resource, subject: subject, action: action, resource: resource,
          context: context, page: page)
      end

      def search_actions(subject:, resource:, context: nil, page: nil)
        search(:search_action, :action, subject: subject, resource: resource, context: context, page: page)
      end

      def each_subject(**request)
        return enum_for(:each_subject, **request) unless block_given?

        each_search(:search_subjects, request) { |entity| yield entity }
      end

      def each_resource(**request)
        return enum_for(:each_resource, **request) unless block_given?

        each_search(:search_resources, request) { |entity| yield entity }
      end

      def each_action(**request)
        return enum_for(:each_action, **request) unless block_given?

        each_search(:search_actions, request) { |entity| yield entity }
      end

      def configuration
        base = base_url
        raise ArgumentError, "configuration discovery requires base_url" if base.nil?

        response = get(metadata_uri(base))
        raise HTTPError, response.code.to_i unless response.code == "200"
        validate_json_content_type(response, "AuthZEN metadata response")

        metadata = parse_json_object(response.body, "Invalid AuthZEN metadata JSON response")
        validate_metadata(metadata, base)
        endpoints = METADATA_ENDPOINTS.each_with_object({}) do |(operation, key), configured|
          configured[operation] = parse_endpoint(metadata.fetch(key), key) if metadata.key?(key)
        end
        @endpoints = endpoints
        @discovered = true
        @metadata = metadata
      end

      private

      attr_reader :base_url

      def positive_timeout(value)
        unless value.is_a?(Numeric) && value.positive? && value.finite?
          raise ArgumentError, "timeouts must be positive finite numbers"
        end
        value
      end

      def evaluation_payload(subject:, action:, resource:, context:)
        payload = {
          "subject" => object(subject, %w[type id], "subject"),
          "action" => object(action_value(action), %w[name], "action"),
          "resource" => object(resource, %w[type id], "resource")
        }
        payload["context"] = hash_object(context, "context") unless context.nil?
        payload
      end

      def evaluations_payload(evaluations:, subject:, action:, resource:, context:, options:)
        payload = {}
        payload["subject"] = object(subject, %w[type id], "subject") unless subject.nil?
        payload["action"] = object(action_value(action), %w[name], "action") unless action.nil?
        payload["resource"] = object(resource, %w[type id], "resource") unless resource.nil?
        payload["context"] = hash_object(context, "context") unless context.nil?
        payload["options"] = hash_object(options, "options") unless options.nil?

        semantic = payload.dig("options", "evaluations_semantic") || "execute_all"
        unless EVALUATION_SEMANTICS.include?(semantic)
          raise ArgumentError, "options.evaluations_semantic must be execute_all, deny_on_first_deny, or permit_on_first_permit"
        end

        unless evaluations.nil? || evaluations.is_a?(Array)
          raise ArgumentError, "evaluations must be an array"
        end

        if evaluations.nil? || evaluations.empty?
          %w[subject action resource].each do |key|
            raise ArgumentError, "#{key} is required when evaluations is absent or empty" unless payload.key?(key)
          end
          payload["evaluations"] = [] unless evaluations.nil?
          return payload
        end

        payload["evaluations"] = evaluations.each_with_index.map do |evaluation, index|
          normalized = hash_object(evaluation, "evaluations[#{index}]")
          item = {}
          item["subject"] = object(normalized["subject"], %w[type id], "evaluations[#{index}].subject") if normalized.key?("subject")
          item["action"] = object(action_value(normalized["action"]), %w[name], "evaluations[#{index}].action") if normalized.key?("action")
          item["resource"] = object(normalized["resource"], %w[type id], "evaluations[#{index}].resource") if normalized.key?("resource")
          item["context"] = hash_object(normalized["context"], "evaluations[#{index}].context") if normalized.key?("context")

          effective = payload.merge(item)
          %w[subject action resource].each do |key|
            raise ArgumentError, "evaluations[#{index}].#{key} or top-level #{key} is required" unless effective.key?(key)
          end
          item
        end
        payload
      end

      def action_value(value)
        value.is_a?(String) ? {"name" => value} : value
      end

      def object(value, required, label)
        normalized = hash_object(value, label)
        required.each do |key|
          unless normalized[key].is_a?(String)
            raise ArgumentError, "#{label}.#{key} must be a string"
          end
        end
        if normalized.key?("properties") && !normalized["properties"].is_a?(Hash)
          raise ArgumentError, "#{label}.properties must be an object"
        end
        normalized
      end

      def hash_object(value, label)
        raise ArgumentError, "#{label} must be an object" unless value.is_a?(Hash)

        value.transform_keys(&:to_s)
      end

      def page_object(value)
        page = hash_object(value, "page")
        unless (page.keys - %w[token limit properties]).empty?
          raise ArgumentError, "unsupported page extension; use page.properties for implementation-specific attributes"
        end
        raise ArgumentError, "page.token must be a string" if page.key?("token") && !page["token"].is_a?(String)
        unless !page.key?("limit") || (page["limit"].is_a?(Integer) && page["limit"] >= 0)
          raise ArgumentError, "page.limit must be a non-negative integer"
        end
        raise ArgumentError, "page.properties must be an object" if page.key?("properties") && !page["properties"].is_a?(Hash)

        page
      end

      def post(operation, payload)
        uri = endpoint_for(operation)
        request = Net::HTTP::Post.new(uri, @headers)
        request["Content-Type"] = "application/json"
        request["Accept"] = "application/json"
        request["X-Request-ID"] ||= SecureRandom.uuid
        request.body = JSON.generate(payload)
        response = perform(uri, request)
        raise HTTPError, response.code.to_i unless response.code == "200"
        validate_json_content_type(response, "AuthZEN response")

        parse_json_object(response.body, "Invalid AuthZEN JSON response")
      end

      def get(uri)
        request = Net::HTTP::Get.new(uri, @headers)
        request["Accept"] = "application/json"
        request["X-Request-ID"] ||= SecureRandom.uuid
        perform(uri, request)
      end

      def parse_json_object(body, message)
        result = JSON.parse(body)
        raise InvalidResponse, "#{message}: root must be an object" unless result.is_a?(Hash)

        result
      rescue JSON::ParserError, TypeError => error
        raise InvalidResponse, message, cause: error
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
        raise TransportError, "AuthZEN request failed (#{error.class})", cause: error
      end

      def endpoint_for(operation)
        return @endpoints.fetch(operation) if @endpoints.key?(operation)
        if @discovered
          metadata_key = METADATA_ENDPOINTS.fetch(operation)
          raise UnsupportedEndpoint, "AuthZEN #{operation} endpoint is unsupported by discovered metadata (missing #{metadata_key})"
        end
        raise ArgumentError, "#{operation} endpoint requires base_url or explicit endpoints[:#{operation}]" if @base_url.nil?

        append_path(@base_url, DEFAULT_PATHS.fetch(operation))
      end

      def parse_endpoint(value, label)
        raise ArgumentError, "#{label} must be a URL string" unless value.is_a?(String)
        uri = URI.parse(value)
        unless uri.is_a?(URI::HTTP) && uri.host && !uri.host.empty? && !uri.userinfo && !uri.fragment
          raise ArgumentError, "#{label} must be an absolute HTTP(S) URL without credentials or fragment"
        end
        if uri.scheme != "https" && !@allow_http
          raise ArgumentError, "#{label} requires HTTPS; allow_http: true is for local testing"
        end

        uri
      end

      def parse_base_url(value, label)
        uri = parse_endpoint(value, label)
        raise ArgumentError, "#{label} must not contain a query" if uri.query

        uri
      end

      def append_path(uri, path)
        copy = uri.dup
        prefix = copy.path.to_s.sub(%r{/+\z}, "")
        copy.path = "#{prefix}#{path}"
        copy.query = nil
        copy
      end

      def metadata_uri(base)
        return @metadata_url if @metadata_url

        copy = base.dup
        path = copy.path.to_s
        copy.path = "/.well-known/authzen-configuration#{path}"
        copy.query = nil
        copy
      end

      def validate_decision(result, label)
        unless result.is_a?(Hash) && [true, false].include?(result["decision"])
          raise InvalidResponse, "#{label} must contain a boolean decision"
        end
        if result.key?("context") && !result["context"].is_a?(Hash)
          raise InvalidResponse, "#{label} context must be an object"
        end
      end

      def validate_evaluations_response(result, expected_count, semantic, single_request:)
        if single_request && !result.key?("evaluations")
          validate_decision(result, "AuthZEN evaluations response")
          return
        end

        evaluations = result["evaluations"]
        raise InvalidResponse, "AuthZEN evaluations response must contain evaluations array" unless evaluations.is_a?(Array)
        evaluations.each_with_index { |decision, index| validate_decision(decision, "AuthZEN evaluations[#{index}]") }
        validate_evaluations_cardinality(evaluations, expected_count, semantic)
      end

      def validate_evaluations_cardinality(evaluations, expected_count, semantic)
        actual_count = evaluations.length
        case semantic
        when "execute_all"
          raise InvalidResponse, "AuthZEN evaluations response must contain #{expected_count} results" unless actual_count == expected_count
        when "deny_on_first_deny"
          validate_short_circuit(evaluations, expected_count, false, semantic)
        when "permit_on_first_permit"
          validate_short_circuit(evaluations, expected_count, true, semantic)
        end
      end

      def validate_short_circuit(evaluations, expected_count, stop_decision, semantic)
        raise InvalidResponse, "AuthZEN evaluations response must not be empty" if evaluations.empty?
        raise InvalidResponse, "AuthZEN evaluations response has too many results" if evaluations.length > expected_count
        evaluations[0...-1].each do |decision|
          if decision["decision"] == stop_decision
            raise InvalidResponse, "AuthZEN #{semantic} response short-circuited after an invalid decision"
          end
        end
        unless evaluations.length == expected_count || evaluations.last["decision"] == stop_decision
          raise InvalidResponse, "AuthZEN #{semantic} response must stop on #{stop_decision}"
        end
      end

      def search(operation, result_kind, **request)
        payload = search_payload(operation, **request)
        result = post(operation, payload)
        expected_type = payload.dig(result_kind.to_s, "type") unless result_kind == :action
        validate_search_response(result, result_kind, expected_type)
        result
      end

      def search_payload(operation, subject: nil, action: nil, resource: nil, context: nil, page: nil)
        payload = {
          "subject" => object(subject, operation == :search_subject ? %w[type] : %w[type id], "subject"),
          "resource" => object(resource, operation == :search_resource ? %w[type] : %w[type id], "resource")
        }
        payload["action"] = object(action_value(action), %w[name], "action") unless operation == :search_action
        payload["context"] = hash_object(context, "context") unless context.nil?
        payload["page"] = page_object(page) unless page.nil?
        payload
      end

      def validate_search_response(result, result_kind, expected_type)
        results = result["results"]
        raise InvalidResponse, "AuthZEN search response must contain results array" unless results.is_a?(Array)

        results.each_with_index do |entity, index|
          object(entity, result_kind == :action ? %w[name] : %w[type id], "results[#{index}]")
          if expected_type && entity["type"] != expected_type
            raise InvalidResponse, "AuthZEN search returned a different entity type"
          end
        end
        raise InvalidResponse, "AuthZEN search response context must be an object" if result.key?("context") && !result["context"].is_a?(Hash)
        validate_response_page(result["page"]) if result.key?("page")
      rescue ArgumentError => error
        raise InvalidResponse, error.message
      end

      def validate_response_page(page)
        raise InvalidResponse, "AuthZEN search response page must be an object" unless page.is_a?(Hash)
        raise InvalidResponse, "AuthZEN search response page.next_token must be a string" unless page["next_token"].is_a?(String)
        if page.key?("properties") && !page["properties"].is_a?(Hash)
          raise InvalidResponse, "AuthZEN search response page.properties must be an object"
        end
        %w[count total].each do |key|
          next unless page.key?(key)
          raise InvalidResponse, "AuthZEN search response page.#{key} must be a non-negative integer" unless page[key].is_a?(Integer) && page[key] >= 0
        end
      end

      def each_search(method_name, request)
        snapshot = deep_copy(request)
        seen_tokens = {}
        loop do
          response = public_send(method_name, **snapshot)
          response.fetch("results").each { |entity| yield entity }
          next_token = response.fetch("page", {})["next_token"]
          break if next_token.nil? || next_token.empty?
          raise InvalidResponse, "AuthZEN pagination repeated next_token" if seen_tokens[next_token]

          seen_tokens[next_token] = true
          page = snapshot[:page] || snapshot["page"] || {}
          page = deep_copy(page).merge(token: next_token)
          snapshot = snapshot.merge(page: page)
        end
      end

      def deep_copy(value)
        Marshal.load(Marshal.dump(value))
      end

      def validate_metadata(metadata, base)
        pdp = metadata["policy_decision_point"]
        unless pdp.is_a?(String) && pdp == @pdp_identifier
          raise InvalidResponse, "AuthZEN metadata policy_decision_point must exactly match #{@pdp_identifier}"
        end

        parse_base_url(pdp, "policy_decision_point metadata")
        evaluation = metadata["access_evaluation_endpoint"]
        raise InvalidResponse, "AuthZEN metadata requires access_evaluation_endpoint" unless evaluation.is_a?(String)

        METADATA_ENDPOINTS.each_value do |key|
          next unless metadata.key?(key)
          raise InvalidResponse, "AuthZEN metadata #{key} must be a string" unless metadata[key].is_a?(String)
          uri = parse_endpoint(metadata[key], "#{key} metadata")
          unless same_origin?(uri, base) || @trusted_origins.include?(origin(uri))
            raise InvalidResponse, "AuthZEN metadata endpoint #{key} is not on a trusted origin"
          end
        end

        if metadata.key?("capabilities")
          unless metadata["capabilities"].is_a?(Array) && metadata["capabilities"].all? { |capability| capability.is_a?(String) }
            raise InvalidResponse, "AuthZEN metadata capabilities must be an array of strings"
          end
        end
      rescue ArgumentError, URI::InvalidURIError => error
        raise InvalidResponse, error.message
      end

      def validate_json_content_type(response, label)
        content_type = response["content-type"].to_s.split(";", 2).first.to_s.strip.downcase
        raise InvalidResponse, "#{label} Content-Type must be application/json" unless content_type == "application/json"
      end

      def same_origin?(left, right)
        origin(left) == origin(right)
      end

      def normalize_origin(value)
        origin(parse_endpoint(value, "trusted_origins"))
      end

      def origin(uri)
        "#{uri.scheme}://#{uri.host}:#{uri.port}"
      end
    end
  end
end
