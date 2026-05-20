# frozen_string_literal: true

module PQCrypto
  module JWT
    module Keys
      module_function

      EXPECT_VALUES = [:auto, :signature].freeze
      LOAD_ERRORS = [PQCrypto::Error, ArgumentError].freeze
      LoaderSet = Data.define(:auto, :signature)

      KEY_LOADERS = {
        public_pem: LoaderSet.new(
          auto: ->(input, _) { PQCrypto::Key.from_pem(input) },
          signature: ->(input, _) { PQCrypto::Signature.public_key_from_spki_pem(input) }
        ),
        public_der: LoaderSet.new(
          auto: ->(input, _) { PQCrypto::Key.from_der(input) },
          signature: ->(input, _) { PQCrypto::Signature.public_key_from_spki_der(input) }
        ),
        secret_pem: LoaderSet.new(
          auto: ->(input, passphrase) { PQCrypto::Key.from_pem(input, passphrase: passphrase) },
          signature: ->(input, passphrase) { PQCrypto::Signature.secret_key_from_pkcs8_pem(input, passphrase: passphrase) }
        ),
        secret_der: LoaderSet.new(
          auto: ->(input, passphrase) { PQCrypto::Key.from_der(input, passphrase: passphrase) },
          signature: ->(input, passphrase) { PQCrypto::Signature.secret_key_from_pkcs8_der(input, passphrase: passphrase) }
        )
      }.freeze

      ENSURE_KEY_KIND = {
        public: ->(key) { ensure_signature_public_key!(key) },
        secret: ->(key) { ensure_signature_secret_key!(key) }
      }.freeze

      def generate(alg)
        algorithm = PQCrypto::JWT.algorithm_for(alg)
        raise ArgumentError, "Unsupported PQCrypto JOSE algorithm: #{alg.inspect}" unless algorithm
        raise ArgumentError, "Unsupported key kind for #{alg.inspect}" unless algorithm.key_kind == :signature

        PQCrypto::Signature.generate(algorithm.pq_crypto_algorithm)
      end

      def public_from_pem(pem, expect: :auto)
        load_key(:public_pem, :public, pem, expect: expect)
      end

      def public_from_der(der, expect: :auto)
        load_key(:public_der, :public, der, expect: expect)
      end

      def secret_from_pem(pem, expect: :auto, passphrase: nil)
        load_key(:secret_pem, :secret, pem, expect: expect, passphrase: passphrase)
      end

      def secret_from_der(der, expect: :auto, passphrase: nil)
        load_key(:secret_der, :secret, der, expect: expect, passphrase: passphrase)
      end

      def load_key(loader_key, key_kind, input, expect:, passphrase: nil)
        validate_expect!(expect)
        loader = KEY_LOADERS.fetch(loader_key).public_send(expect)
        ENSURE_KEY_KIND.fetch(key_kind).call(loader.call(input, passphrase))
      rescue *LOAD_ERRORS => e
        raise PQCrypto::JWT::Error, e.message
      end
      private_class_method :load_key

      def validate_expect!(expect)
        return if EXPECT_VALUES.include?(expect)

        raise ArgumentError, "expect: must be one of #{EXPECT_VALUES.map(&:inspect).join(', ')}"
      end
      private_class_method :validate_expect!

      def ensure_signature_public_key!(key)
        return key if key.is_a?(PQCrypto::Signature::PublicKey)

        raise PQCrypto::JWT::KeyTypeError, "Expected PQCrypto::Signature::PublicKey, got #{key.class}"
      end
      private_class_method :ensure_signature_public_key!

      def ensure_signature_secret_key!(key)
        return key if key.is_a?(PQCrypto::Signature::SecretKey)

        raise PQCrypto::JWT::KeyTypeError, "Expected PQCrypto::Signature::SecretKey, got #{key.class}"
      end
      private_class_method :ensure_signature_secret_key!
    end
  end
end
