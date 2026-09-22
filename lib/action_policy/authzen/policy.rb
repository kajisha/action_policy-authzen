module ActionPolicy
  module AuthZEN
    module Policy
      def self.included(base)
        base.authorize :authzen_client
      end

      private

      def authzen_configuration
        authzen_client.configuration
      end

      def authzen_evaluate(**request)
        authzen_client.evaluate(**request)
      end

      def authzen_evaluations(**request)
        authzen_client.evaluations(**request)
      end

      def authzen_search_subjects(**request)
        authzen_client.search_subjects(**request)
      end

      def authzen_search_resources(**request)
        authzen_client.search_resources(**request)
      end

      def authzen_search_actions(**request)
        authzen_client.search_actions(**request)
      end

      def authzen_each_subject(**request, &block)
        authzen_client.each_subject(**request, &block)
      end

      def authzen_each_resource(**request, &block)
        authzen_client.each_resource(**request, &block)
      end

      def authzen_each_action(**request, &block)
        authzen_client.each_action(**request, &block)
      end

      def authzen_allowed?(subject:, action:, resource:, context: nil)
        authzen_client.allowed?(subject: subject, action: action, resource: resource, context: context)
      end
    end
  end
end
