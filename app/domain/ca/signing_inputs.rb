# frozen_string_literal: true

module CA
  # SigningInputs collects together the major inputs required for a 
  # certificate authority
  SigningInputs =  Struct.new(:kind, :params, :role, :webservice, :env)
end
