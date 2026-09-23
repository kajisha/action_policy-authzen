require_relative "client"

module ActionPolicy
  module AuthZEN
    class UnsupportedFeature < Error; end
    module Experimental
      class HTTPError < ActionPolicy::AuthZEN::HTTPError
        attr_reader :problem_type, :retry_after

        def initialize(status, problem_type: nil, retry_after: nil)
          @problem_type = problem_type
          @retry_after = retry_after
          super(status)
        end
      end

      class DuplicateJSONKey < Error; end
    end
  end
end

require_relative "experimental/access_requests"
