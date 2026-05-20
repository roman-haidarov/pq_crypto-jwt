# frozen_string_literal: true

require "jwt"
require "pq_crypto"

module PQCrypto
  module JWT
    module JWA
      # RFC 9964: ML-DSA JOSE algorithms always use an empty FIPS 204 context.
      EMPTY_CONTEXT = "".b.freeze
      VERIFY_ERRORS = [PQCrypto::Error, PQCrypto::JWT::Error, ::JWT::Error, ArgumentError, TypeError, EncodingError].freeze

      module MLDSA
        def valid_alg?(alg_to_validate) = alg_to_validate == alg
        def pq_crypto_algorithm = self::PQ_CRYPTO_ALGORITHM
        def key_kind = :signature

        def sign(data:, signing_key:)
          ensure_key!(signing_key, PQCrypto::Signature::SecretKey, "signing")
          raise ArgumentError, "data must be a String" unless data.is_a?(String)

          signing_key.sign(data.b, context: EMPTY_CONTEXT)
        rescue PQCrypto::JWT::KeyTypeError, ArgumentError
          raise
        rescue StandardError => e
          raise ::JWT::EncodeError, e.message
        end

        def verify(data:, signature:, verification_key:)
          return false unless verification_key.is_a?(PQCrypto::Signature::PublicKey)
          return false unless verification_key.algorithm == pq_crypto_algorithm
          return false unless data.is_a?(String) && signature.is_a?(String)
          return false unless signature_length_valid?(signature)

          verification_key.verify(data.b, signature.b, context: EMPTY_CONTEXT)
        rescue *VERIFY_ERRORS
          false
        end

        private

        def ensure_key!(key, klass, role)
          unless key.is_a?(klass)
            raise PQCrypto::JWT::KeyTypeError, "#{alg} #{role} requires #{klass}"
          end
          return if key.algorithm == pq_crypto_algorithm

          raise PQCrypto::JWT::KeyTypeError,
                "#{alg} #{role} requires #{pq_crypto_algorithm.inspect} key, got #{key.algorithm.inspect}"
        end

        def signature_length_valid?(signature)
          expected = PQCrypto::Signature.details(pq_crypto_algorithm)[:signature_bytes]
          expected.nil? || signature.bytesize == expected
        rescue *VERIFY_ERRORS
          false
        end
      end
    end
  end
end
