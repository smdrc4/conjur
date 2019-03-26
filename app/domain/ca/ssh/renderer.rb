# frozen_string_literal: true

module CA
  module SSH
    # Reponsible for rendering SSH certificates in OpenSSH format
    class Renderer
      def initialize(cert)
        @cert = cert
      end

      def call
        RenderedCertificate.new(cert_contents, 'application/x-openssh-file')
      end

      protected

      def cert_contents
        "#{@cert.ssh_type} #{Base64.strict_encode64(@cert.to_blob)}"
      end
    end
  end
end
