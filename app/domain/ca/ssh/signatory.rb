# frozen_string_literal: true

require 'securerandom'

module CA
  module SSH
    # CertificateAuthority implements the signing capabilities
    # for a Conjur configure CA service
    class Signatory

      # Creates a Certificate Authority from a configured Conjur webservice
      def initialize(inputs)
        @inputs = inputs
        @ca_cert = SignatoryCertificate.new(inputs.webservice)
      end

      def call
        # Populate certificate identity
        certificate.key_id = role.id
        certificate.key = public_key

        # Populate certificate validity
        now = Time.now
        certificate.valid_after = now
        certificate.valid_before = now + [ttl, max_ttl].min 
        certificate.valid_principals = principals

        # Populate the certificate usage
        certificate.type = :user
        certificate.extensions = {
          "permit-pty" => ""
        }
        certificate.critical_options = {}

        # Generate a random 20 byte (160 bit) serial number for the certificate
        certificate.serial = SecureRandom.random_number(1<<160)

        # Sign the certificate
        certificate.sign(@ca_cert.private_key)
      end

      protected

      def certificate
        @certificate ||= Net::SSH::Authentication::Certificate.new
      end

      def role
        @inputs.role
      end

      def principals
        @principals ||= Array(@inputs.params[:principals])
      end

      def ttl
        ttl_data = @inputs.params[:ttl]
        @ttl ||= if ttl_data.present?
          ISO8601::Duration.new(ttl_data).to_seconds 
        else
          max_ttl
        end
      end

      def public_key
        public_key_data = @inputs.params[:public_key]
        case public_key_format
        when :pem
          OpenSSL::PKey::RSA.new(public_key_data)
        when :openssh
          Net::SSH::KeyFactory.load_data_public_key(public_key_data)
        else
          raise ArgumentError, "Invalid public key format: #{public_key_format}"
        end
      end

      def public_key_format
        @public_key_format ||= (@inputs.params[:public_key_format].presence || 'openssh').downcase.to_sym
      end

      def max_ttl
        service_max_ttl = @inputs.webservice.annotation('ca/max-ttl')
        raise ArgumentError, "The max TTL (ca/max-ttl) for '#{service_id}' is missing." unless service_max_ttl.present?

        ISO8601::Duration.new(service_max_ttl).to_seconds
      end

      def service_id
        # CA services have ids like 'conjur/ca/<service_id>'
        @service_id ||= @inputs.webservice.identifier.split('/')[2]
      end
    end
  end
end
