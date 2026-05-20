# frozen_string_literal: true

require "jwt"
require "pq_crypto"

module PQCrypto
  module JWT
    module JWA
      EMPTY_CONTEXT = "".b.freeze
      VERIFY_ERRORS = [PQCrypto::Error, PQCrypto::JWT::Error, ::JWT::Error, ArgumentError, TypeError, EncodingError].freeze
      SIGN_ERRORS = [PQCrypto::Error, PQCrypto::JWT::Error, TypeError, EncodingError].freeze

      SignInput = Data.define(:data, :key)
      VerifyInput = Data.define(:data, :signature, :key)
      KeyRequirement = Data.define(:klass, :role)

      module MLDSA
        SECRET_KEY = KeyRequirement.new(PQCrypto::Signature::SecretKey, "signing").freeze
        PUBLIC_KEY = KeyRequirement.new(PQCrypto::Signature::PublicKey, "verification").freeze

        def valid_alg?(alg_to_validate)
          alg_to_validate == alg
        end

        def pq_crypto_algorithm
          self::PQ_CRYPTO_ALGORITHM
        end

        def streaming_supported?
          false
        end

        def sign_io(**)
          unsupported_streaming!
        end

        def verify_io(**)
          unsupported_streaming!
        end

        def verify_io!(**)
          unsupported_streaming!
        end

        def key_kind
          :signature
        end

        def sign(data:, signing_key:)
          input = SignInput.new(data: data, key: signing_key)
          ensure_secret_key!(input.key)
          raise ArgumentError, "data must be a String" unless input.data.is_a?(String)

          input.key.sign(input.data.b, context: EMPTY_CONTEXT)
        rescue PQCrypto::JWT::KeyTypeError, ArgumentError
          raise
        rescue *SIGN_ERRORS => e
          raise ::JWT::EncodeError, e.message
        end

        def verify(data:, signature:, verification_key:)
          input = VerifyInput.new(data: data, signature: signature, key: verification_key)
          return false unless public_key_for_this_algorithm?(input.key)
          return false unless input.data.is_a?(String)
          return false unless input.signature.is_a?(String)
          return false unless signature_length_valid?(input.signature)

          input.key.verify(input.data.b, input.signature.b, context: EMPTY_CONTEXT)
        rescue *VERIFY_ERRORS
          false
        end

        private

        def unsupported_streaming!
          raise PQCrypto::JWT::UnsupportedFeature, "#{alg} does not support streaming JWS"
        end

        def ensure_secret_key!(key)
          ensure_key!(key, SECRET_KEY)
        end

        def ensure_public_key!(key)
          ensure_key!(key, PUBLIC_KEY)
        end

        def ensure_key!(key, requirement)
          unless key.is_a?(requirement.klass)
            raise PQCrypto::JWT::KeyTypeError, "#{alg} #{requirement.role} requires #{requirement.klass}"
          end

          return if key.algorithm == pq_crypto_algorithm

          raise PQCrypto::JWT::KeyTypeError,
                "#{alg} #{requirement.role} requires #{pq_crypto_algorithm.inspect} key, got #{key.algorithm.inspect}"
        end

        def public_key_for_this_algorithm?(key)
          key.is_a?(PQCrypto::Signature::PublicKey) && key.algorithm == pq_crypto_algorithm
        end

        def signature_length_valid?(signature)
          details = PQCrypto::Signature.details(pq_crypto_algorithm)
          expected = details[:signature_bytes] || details["signature_bytes"]
          expected.nil? || signature.bytesize == expected
        rescue *VERIFY_ERRORS
          false
        end
      end
    end
  end
end
