# frozen_string_literal: true

require "base64"

module PQCrypto
  module JWT
    module Base64URL
      module_function

      def encode(bytes)
        Base64.urlsafe_encode64(String(bytes), padding: false)
      end

      def decode(value)
        raise ArgumentError, "base64url value must be a String" unless value.is_a?(String)

        bytes = value.b
        unless /\A[A-Za-z0-9_-]*\z/n.match?(bytes)
          raise ArgumentError, "base64url must use the unpadded URL-safe alphabet"
        end

        Base64.urlsafe_decode64(bytes)
      end
    end
    private_constant :Base64URL
  end
end
