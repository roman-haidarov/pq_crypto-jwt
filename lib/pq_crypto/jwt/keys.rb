# frozen_string_literal: true

module PQCrypto
  module JWT
    module Keys
      extend self

      EXPECT_VALUES = %i[auto signature].freeze
      LOAD_ERRORS = [PQCrypto::Error, ArgumentError].freeze

      def generate(alg)
        algorithm = PQCrypto::JWT.algorithm_for(alg)
        raise ArgumentError, "Unsupported PQCrypto JOSE algorithm: #{alg.inspect}" unless algorithm

        PQCrypto::Signature.generate(algorithm.pq_crypto_algorithm)
      end

      def public_from_pem(pem, expect: :auto)
        load_key(PQCrypto::Signature::PublicKey, expect) do |signature_only|
          signature_only ? PQCrypto::Signature.public_key_from_spki_pem(pem) : PQCrypto::Key.from_pem(pem)
        end
      end

      def public_from_der(der, expect: :auto)
        load_key(PQCrypto::Signature::PublicKey, expect) do |signature_only|
          signature_only ? PQCrypto::Signature.public_key_from_spki_der(der) : PQCrypto::Key.from_der(der)
        end
      end

      def secret_from_pem(pem, expect: :auto, passphrase: nil)
        load_key(PQCrypto::Signature::SecretKey, expect) do |signature_only|
          if signature_only
            PQCrypto::Signature.secret_key_from_pkcs8_pem(pem, passphrase:)
          else
            PQCrypto::Key.from_pem(pem, passphrase:)
          end
        end
      end

      def secret_from_der(der, expect: :auto, passphrase: nil)
        load_key(PQCrypto::Signature::SecretKey, expect) do |signature_only|
          if signature_only
            PQCrypto::Signature.secret_key_from_pkcs8_der(der, passphrase:)
          else
            PQCrypto::Key.from_der(der, passphrase:)
          end
        end
      end

      private

      def load_key(klass, expect, &)
        unless EXPECT_VALUES.include?(expect)
          raise ArgumentError, "expect: must be one of #{EXPECT_VALUES.map(&:inspect).join(', ')}"
        end

        key = decode_key(expect == :signature, &)
        return key if key.is_a?(klass)

        raise KeyTypeError, "Expected #{klass}, got #{key.class}"
      end

      def decode_key(signature_only)
        yield signature_only
      rescue *LOAD_ERRORS => error
        raise Error, error.message
      end
    end
  end
end
