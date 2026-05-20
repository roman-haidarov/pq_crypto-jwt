# frozen_string_literal: true

module PQCrypto
  module JWT
    module Keys
      module_function

      EXPECT_VALUES = [:auto, :signature].freeze
      LOAD_ERRORS = [PQCrypto::Error, ArgumentError].freeze

      def generate(alg)
        algorithm = PQCrypto::JWT.algorithm_for(alg)
        raise ArgumentError, "Unsupported PQCrypto JOSE algorithm: #{alg.inspect}" unless algorithm
        raise ArgumentError, "Unsupported key kind for #{alg.inspect}" unless algorithm.key_kind == :signature

        PQCrypto::Signature.generate(algorithm.pq_crypto_algorithm)
      end

      def public_from_pem(pem, expect: :auto)
        validate_expect!(expect)
        key = expect == :signature ? PQCrypto::Signature.public_key_from_spki_pem(pem) : PQCrypto::Key.from_pem(pem)
        as_public!(key)
      rescue *LOAD_ERRORS => e
        raise PQCrypto::JWT::Error, e.message
      end

      def public_from_der(der, expect: :auto)
        validate_expect!(expect)
        key = expect == :signature ? PQCrypto::Signature.public_key_from_spki_der(der) : PQCrypto::Key.from_der(der)
        as_public!(key)
      rescue *LOAD_ERRORS => e
        raise PQCrypto::JWT::Error, e.message
      end

      def secret_from_pem(pem, expect: :auto, passphrase: nil)
        validate_expect!(expect)
        key = expect == :signature ? PQCrypto::Signature.secret_key_from_pkcs8_pem(pem, passphrase: passphrase) : PQCrypto::Key.from_pem(pem, passphrase: passphrase)
        as_secret!(key)
      rescue *LOAD_ERRORS => e
        raise PQCrypto::JWT::Error, e.message
      end

      def secret_from_der(der, expect: :auto, passphrase: nil)
        validate_expect!(expect)
        key = expect == :signature ? PQCrypto::Signature.secret_key_from_pkcs8_der(der, passphrase: passphrase) : PQCrypto::Key.from_der(der, passphrase: passphrase)
        as_secret!(key)
      rescue *LOAD_ERRORS => e
        raise PQCrypto::JWT::Error, e.message
      end

      def validate_expect!(expect)
        return if EXPECT_VALUES.include?(expect)

        raise ArgumentError, "expect: must be one of #{EXPECT_VALUES.map(&:inspect).join(', ')}"
      end
      private_class_method :validate_expect!

      def as_public!(key)
        return key if key.is_a?(PQCrypto::Signature::PublicKey)

        raise PQCrypto::JWT::KeyTypeError, "Expected PQCrypto::Signature::PublicKey, got #{key.class}"
      end
      private_class_method :as_public!

      def as_secret!(key)
        return key if key.is_a?(PQCrypto::Signature::SecretKey)

        raise PQCrypto::JWT::KeyTypeError, "Expected PQCrypto::Signature::SecretKey, got #{key.class}"
      end
      private_class_method :as_secret!
    end
  end
end
