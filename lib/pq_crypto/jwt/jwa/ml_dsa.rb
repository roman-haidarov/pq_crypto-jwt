# frozen_string_literal: true

module PQCrypto
  module JWT
    module JWA
      class MLDSA
        include ::JWT::JWA::SigningAlgorithm
        include Streaming

        attr_reader :alg, :pq_crypto_algorithm

        def initialize(alg, pq_crypto_algorithm)
          @alg = String(alg).dup.freeze
          @pq_crypto_algorithm = pq_crypto_algorithm
          freeze
        end

        def valid_alg?(alg_to_validate) = alg_to_validate == alg
        def key_kind = :signature

        def sign(data:, signing_key:)
          ensure_key!(signing_key, PQCrypto::Signature::SecretKey, "signing")
          raise ArgumentError, "data must be a String" unless data.is_a?(String)

          signing_key.sign(data.b, context: EMPTY_CONTEXT)
        rescue KeyTypeError, ArgumentError
          raise
        rescue StandardError => error
          raise ::JWT::EncodeError, error.message
        end

        def verify(data:, signature:, verification_key:)
          verification_key.is_a?(PQCrypto::Signature::PublicKey) &&
            verification_key.algorithm == pq_crypto_algorithm &&
            data.is_a?(String) && signature.is_a?(String) &&
            signature_length_valid?(signature) &&
            verification_key.verify(data.b, signature.b, context: EMPTY_CONTEXT)
        rescue *VERIFY_ERRORS
          false
        end

        private

        def ensure_key!(key, klass, role)
          raise KeyTypeError, "#{alg} #{role} requires #{klass}" unless key.is_a?(klass)

          actual = key.algorithm
          return if actual == pq_crypto_algorithm

          raise KeyTypeError, "#{alg} #{role} requires #{pq_crypto_algorithm.inspect} key, got #{actual.inspect}"
        end

        def signature_length_valid?(signature)
          expected = PQCrypto::Signature.details(pq_crypto_algorithm)[:signature_bytes]
          expected.nil? || signature.bytesize == expected
        rescue *VERIFY_ERRORS
          false
        end
      end

      MLDSA44 = MLDSA.new("ML-DSA-44", :ml_dsa_44)
      MLDSA65 = MLDSA.new("ML-DSA-65", :ml_dsa_65)
      MLDSA87 = MLDSA.new("ML-DSA-87", :ml_dsa_87)
    end
  end
end
