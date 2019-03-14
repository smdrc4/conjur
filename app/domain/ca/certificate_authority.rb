# frozen_string_literal: true

module CA
  # A CertificateAuthority is responsible for grouping together the
  # three operations of a CA: validating, signing, and rendering 
  # certificates
  CertificateAuthority = Struct.new(:validator, :signatory, :renderer)
end
