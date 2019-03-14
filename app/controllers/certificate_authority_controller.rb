# frozen_string_literal: true

require "base64"

# Responsible for API calls to interact with a Conjur-configured
# certificate authority (CA) service
class CertificateAuthorityController < RestController
  include ActionController::MimeResponds
  include BodyParser

  before_action :verify_ca_exists
  before_action :verify_role
  before_action :verify_kind
  before_action :verify_request
 
  def sign_certificate
    signed_certificate = certificate_authority.signatory.new(signing_inputs).()
    rendered_certificate = render_certificate(signed_certificate)
    render body: rendered_certificate.body, content_type: rendered_certificate.content_type, status: :created
  end

  protected

  def available_ca_types
    {
      x509: CA::CertificateAuthority.new(
        ::CA::X509::Validator, 
        ::CA::X509::Signatory, 
        ::CA::X509::Renderer
      )
    }
  end

  def verify_role
    raise Forbidden, "Host is not authorized to sign." unless current_user.allowed_to?('sign', ca_resource)
  end

  def verify_kind
    raise ArgumentError, "Invalid certificate kind: '#{certificate_kind}'" unless available_ca_types.key?(certificate_kind)
  end

  def verify_ca_exists
    raise RecordNotFound, "There is no certificate authority with ID: #{service_id}" unless ca_resource
  end

  def verify_request
    certificate_authority.validator.new(signing_inputs).()
  end

  private

  def render_certificate(certificate)
    certificate_authority.renderer.new(certificate).()
  end

  def signing_inputs
    ::CA::SigningInputs.new(
      certificate_kind, 
      params, 
      current_user, 
      ca_resource, 
      ENV
    )
  end

  def certificate_authority
    available_ca_types[certificate_kind]
  end

  def certificate_kind
    (params[:kind] || 'x509').downcase.to_sym
  end

  def ca_resource
    identifier = Sequel.function(:identifier, :resource_id)
    kind = Sequel.function(:kind, :resource_id)
    account = Sequel.function(:account, :resource_id)

    @ca_resource ||= Resource
      .where(
        identifier => "conjur/ca/#{service_id}", 
        kind => 'webservice',
        account => account
      )
      .first
  end

  def service_id
    params[:service_id]
  end

  def account
    params[:account]
  end
end
