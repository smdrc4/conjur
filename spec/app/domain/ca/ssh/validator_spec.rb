# frozen_string_literal: true

require 'spec_helper'

describe ::CA::SSH::Validator do
  describe '#validate' do

    let(:inputs) do
      ::CA::SigningInputs.new(kind, params, role, webservice, env)
    end
  
    let(:kind) { "ssh" }
    let(:params) do
      {
        public_key: public_key,
        principals: principals
      }
    end
    let(:role) { double("role") }
    let(:webservice) { double("webservice") }
    let(:env) { double("env") }

    let(:public_key) { double("public_key") }
    let(:principals) { double("principals") }

    subject { ::CA::SSH::Validator.new(inputs).() }

    context "when all of the inputs are valid" do
      it "returns without error" do
        subject
      end
    end
  end
end