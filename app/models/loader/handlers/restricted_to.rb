# frozen_string_literal: true

module Loader
  module Handlers
    # extends the policy loader to store the authentication network restriction
    # on a role's credentials.
    module RestrictedTo
  
      # When a cidr restriction is encountered in a policy, it is saved here. It can't be written directly 
      # into the temporary schema, because that schema doesn't have a credentials table. 
      def handle_restricted_to id, cidr
        policy_restricted_to_records << [ id, cidr ]
      end
  
      def store_restricted_to
        policy_restricted_to_records.each do |entry|
          id, cidr = entry
          role = ::Role[id]
          role.restricted_to = Array(cidr)
          role.save
        end
      end
  
      def policy_restricted_to_records
        @policy_restricted_to_records ||= []
      end
    end
  end
end
