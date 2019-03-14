# frozen_string_literal: true

module CA
  # A RenderedCertificate groups the plaintext content of a final
  # certificate with its appropriate content type for HTTP
  RenderedCertificate = Struct.new(:body, :content_type)
end
