# frozen_string_literal: true

module CA
  module SSH
    # Responsible for validating SSH certificate signing requests
    class Validator
      def initialize(inputs) 
        @inputs = inputs
      end

      def call
        verify_public_key
        verify_principals
      end

      protected

      def verify_public_key
        raise ArgumentError, "Request is missing public key for signing" unless @inputs.params[:public_key].present?
      end

      def verify_principals
        raise ArgumentError, "Signing parameter 'principals' is missing." unless @inputs.params[:principals].present?
      end
    end
  end
end
