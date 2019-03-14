module CA
  module X509
    # SignatoryCertificate represent the CA signing key stored in Conjur
    class SignatoryCertificate
      def initialize(service)
        @service = service
      end

      def private_key
        @private_key ||= load_private_key
      end

      def certificate
        # Parse the first certificate in the chain, which should be the
        # CA certificate
        @certificate ||= OpenSSL::X509::Certificate.new secret(certificate_var)
      end

      private

      def load_private_key
        private_key_data = secret(private_key_var)
        if private_key_password?
          OpenSSL::PKey::RSA.new(private_key_data, private_key_password)
        else
          OpenSSL::PKey::RSA.new(private_key_data)
        end
      end

      def private_key_password?
        private_key_password.present?
      end

      def private_key_password
        @private_key_password ||= secret(private_key_password_var)
      end

      def certificate_var
        @service.annotation('ca/certificate')
      end

      def private_key_var
        @service.annotation('ca/private-key')
      end

      def private_key_password_var
        @service.annotation('ca/private-key-password')
      end

      def secret(name)
        Resource[secret_id(name)]&.secret&.value if name
      end

      def secret_id(name)
        [@service.account, 'variable', name].join(':')
      end
    end
  end
end
