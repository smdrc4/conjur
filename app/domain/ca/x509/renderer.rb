# frozen_string_literal: true

module CA
  module X509
    # Responsible for rendering x.509 certificates in PEM format
    class Renderer
      def initialize(certificate)
        @certificate = certificate
      end 

      def call
        RenderedCertificate.new(@certificate.to_pem, 'application/x-pem-file')
      end
    end
  end
end
