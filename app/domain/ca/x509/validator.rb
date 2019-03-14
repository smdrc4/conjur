# frozen_string_literal: true

module CA
  module X509
    # Responsible for verifying that a certificate signing request is valid and permitted
    class Validator

      def initialize(inputs)
        @inputs = inputs
      end

      def call
        verify_role_is_host
        verify_csr_presence
        verify_csr_public_key
      end

      protected

      def verify_role_is_host
        raise ArgumentError, "Requestor is not a host." unless @inputs.role.kind == 'host'
      end

      def verify_csr_presence
        raise ArgumentError, "Signing parameter 'csr' is missing." unless @inputs.params[:csr].present?
      end

      def verify_csr_public_key
        csr = OpenSSL::X509::Request.new(@inputs.params[:csr])
        raise ::Exceptions::Forbidden, 'CSR cannot be verified' unless csr.verify(csr.public_key)
      end
    end
  end
end
