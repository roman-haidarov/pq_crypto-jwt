# frozen_string_literal: true

require "jwt"
require "pq_crypto"

module PQCrypto
  module JWT
    module JWA
      module MLDSA
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
          raise PQCrypto::JWT::UnsupportedAlgorithm, "#{alg} does not support streaming JWS"
        end

        def verify_io(**)
          raise PQCrypto::JWT::UnsupportedAlgorithm, "#{alg} does not support streaming JWS"
        end

        def verify_io!(**)
          raise PQCrypto::JWT::UnsupportedAlgorithm, "#{alg} does not support streaming JWS"
        end

        def key_kind
          :signature
        end

        def sign(data:, signing_key:)
          ensure_secret_key!(signing_key)
          raise ArgumentError, "data must be a String" unless data.is_a?(String)

          signing_key.sign(data.b)
        rescue PQCrypto::JWT::KeyTypeError, ArgumentError
          raise
        rescue StandardError => e
          raise ::JWT::EncodeError, e.message
        end

        def verify(data:, signature:, verification_key:)
          return false unless public_key_for_this_algorithm?(verification_key)
          return false unless data.is_a?(String)
          return false unless signature.is_a?(String)
          return false unless signature_length_valid?(signature)

          verification_key.verify(data.b, signature.b)
        rescue PQCrypto::InvalidKeyError, PQCrypto::JWT::Error, ArgumentError
          false
        end

        private

        def ensure_secret_key!(key)
          unless key.is_a?(PQCrypto::Signature::SecretKey)
            raise PQCrypto::JWT::KeyTypeError,
                  "#{alg} signing requires PQCrypto::Signature::SecretKey"
          end

          return if key.algorithm == pq_crypto_algorithm

          raise PQCrypto::JWT::KeyTypeError,
                "#{alg} signing requires #{pq_crypto_algorithm.inspect} key, got #{key.algorithm.inspect}"
        end

        def ensure_public_key!(key)
          unless public_key_for_this_algorithm?(key)
            raise PQCrypto::JWT::KeyTypeError,
                  "#{alg} verification requires PQCrypto::Signature::PublicKey for #{pq_crypto_algorithm.inspect}"
          end
        end

        def public_key_for_this_algorithm?(key)
          key.is_a?(PQCrypto::Signature::PublicKey) && key.algorithm == pq_crypto_algorithm
        end

        def signature_length_valid?(signature)
          details = PQCrypto::Signature.details(pq_crypto_algorithm)
          expected = details[:signature_bytes] || details["signature_bytes"]
          expected.nil? || signature.bytesize == expected
        rescue StandardError
          true
        end
      end
    end
  end
end
