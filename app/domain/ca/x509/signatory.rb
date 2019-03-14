# frozen_string_literal: true

require 'securerandom'

module CA
  module X509
    # CertificateAuthority implements the signing capabilities
    # for a Conjur configure CA service
    class Signatory

      attr_reader :service

      # Creates a Certificate Authority from a configured Conjur webservice
      def initialize(inputs)
        @inputs = inputs
        @ca_cert = SignatoryCertificate.new(inputs.webservice)
      end

      # Signs a certificate signing request (CSR) returning the X.509
      # certificate
      def call
        # Sign the certificate
        build_certificate.sign @ca_cert.private_key, OpenSSL::Digest::SHA256.new
      end

      protected

      def build_certificate
        OpenSSL::X509::Certificate.new.tap do |csr_cert|
          # This value is zero-based. This is a version 3 certificate.
          csr_cert.version = 2

          now = Time.now
          csr_cert.not_before = now
          csr_cert.not_after = now + [ttl, max_ttl].min 

          csr_cert.subject = subject
          csr_cert.public_key = csr.public_key
          csr_cert.issuer = @ca_cert.certificate.subject

          # Add certificate extensions
          extensions = {
            'basicConstraints' => 'CA:FALSE',
            'keyUsage' => 'keyEncipherment,dataEncipherment,digitalSignature',
            'subjectKeyIdentifier' => 'hash',
            'subjectAltName' => subject_alt_name(role)
          }

          OpenSSL::X509::ExtensionFactory.new.tap do |extension_factory|
            extension_factory.subject_certificate = csr_cert
            extension_factory.issuer_certificate = @ca_cert.certificate
  
            extensions.each do |key, value|
              extension = extension_factory.create_extension(key, value)
              csr_cert.add_extension(extension)
            end
          end

          # Generate a random 20 byte (160 bit) serial number for the certificate
          csr_cert.serial = SecureRandom.random_number(1<<160)
        end
      end

      def csr
        @csr ||= OpenSSL::X509::Request.new(@inputs.params[:csr])
      end

      def role
        @inputs.role
      end

      def ttl
        ttl_data = @inputs.params[:ttl]
        @ttl ||= if ttl_data.present?
          ISO8601::Duration.new(ttl_data).to_seconds 
        else
          max_ttl
        end
      end

      def subject
        common_name = [
          role.account,
          service_id,
          role.kind,
          role.identifier
        ].join(':')
        OpenSSL::X509::Name.new [['CN', common_name]]
      end

      def service_id
        # CA services have ids like 'conjur/ca/<service_id>'
        @service_id ||= @inputs.webservice.identifier.split('/')[2]
      end

      def subject_alt_name(role)
        [
          "DNS:#{leaf_domain_name(role)}",
          "URI:#{spiffe_id(role)}"
        ].join(', ')
      end

      def leaf_domain_name(role)
        role.identifier.split('/').last
      end

      def spiffe_id(role)
        [
          'spiffe://conjur',
          role.account,
          service_id,
          role.kind,
          role.identifier
        ].join('/')
      end

      def max_ttl
        service_max_ttl = @inputs.webservice.annotation('ca/max-ttl')
        raise ArgumentError, "The max TTL (ca/max-ttl) for '#{service_id}' is missing." unless service_max_ttl.present?

        ISO8601::Duration.new(service_max_ttl).to_seconds
      end
    end
  end
end
