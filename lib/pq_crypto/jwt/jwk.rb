# frozen_string_literal: true

require "base64"
require "digest"
require "json"

module PQCrypto
  module JWT
    module JWK
      module_function

      KTY = "AKP".freeze
      PRIVATE_EXPORT_OPTIONS = [:private, :include_private].freeze
      SEED_BYTES = defined?(PQCrypto::PKCS8::ML_DSA_SEED_BYTES) ? PQCrypto::PKCS8::ML_DSA_SEED_BYTES : 32
      PQ_IMPORT_ERRORS = [ArgumentError, PQCrypto::Error].freeze

      OptionalField = Data.define(:name, :coerce)
      PublicJWK = Data.define(:algorithm, :public_bytes, :kid, :use, :key_ops)
      SeedJWKRequest = Data.define(:seed, :alg, :kid, :public_key, :use, :key_ops, :verify_public)
      KeyByteSpec = Data.define(:field, :detail_key)
      SecretKeySource = Data.define(:secret_key, :public_key)
      SeedDeriver = Data.define(:method_name, :action)

      OPTIONAL_PUBLIC_FIELDS = [
        OptionalField.new("kid", ->(value) { String(value) }),
        OptionalField.new("use", ->(value) { String(value) }),
        OptionalField.new("key_ops", ->(value) { Array(value).map(&:to_s) })
      ].freeze
      PUBLIC_BYTES = KeyByteSpec.new("pub", :public_key_bytes).freeze
      SEED_DERIVERS = [
        SeedDeriver.new(:public_key_from_seed, ->(algorithm, seed) { PQCrypto::Signature.public_key_from_seed(algorithm, seed) }),
        SeedDeriver.new(:keypair_from_seed, ->(algorithm, seed) { PQCrypto::Signature.keypair_from_seed(algorithm, seed).public_key })
      ].freeze

      def from_public_key(public_key, kid: nil, use: nil, key_ops: nil)
        validate_public_key!(public_key)
        public_jwk(PublicJWK.new(
          algorithm: public_key.algorithm,
          public_bytes: public_key.to_bytes,
          kid: kid,
          use: use,
          key_ops: key_ops
        )).freeze
      end

      def from_seed(seed, alg:, kid: nil, public_key: nil, use: nil, key_ops: nil, verify_public: false)
        request = SeedJWKRequest.new(seed: seed, alg: alg, kid: kid, public_key: public_key, use: use, key_ops: key_ops, verify_public: verify_public)
        private_jwk_from_seed(request)
      end

      def from_secret_key(secret_key, kid: nil, public_key: nil, use: nil, key_ops: nil)
        source = secret_key_source(secret_key, public_key)
        validate_secret_key!(source.secret_key)
        from_seed(
          seed_from_secret_key(source.secret_key),
          alg: alg_for_algorithm!(source.secret_key.algorithm),
          kid: kid,
          public_key: source.public_key,
          use: use,
          key_ops: key_ops
        )
      end

      def public_key_from_jwk(hash)
        with_pq_import_errors do
          jwk = normalize_hash!(hash)
          algorithm = algorithm_from_jwk!(jwk)
          public_bytes = decode_required_key_bytes!(jwk, PUBLIC_BYTES, algorithm)
          PQCrypto::Signature.public_key_from_bytes(algorithm, public_bytes)
        end
      end

      def secret_key_from_jwk(hash, verify_public: false)
        with_pq_import_errors do
          jwk = normalize_hash!(hash)
          algorithm = algorithm_from_jwk!(jwk)
          decode_required_key_bytes!(jwk, PUBLIC_BYTES, algorithm)
          seed = decode_required_seed!(jwk, algorithm)
          verify_private_public_consistency!(jwk, algorithm, seed) if verify_public
          PQCrypto::Signature.secret_key_from_seed(algorithm, seed)
        end
      end

      def thumbprint(jwk_hash)
        jwk = normalize_hash!(jwk_hash)
        algorithm_from_jwk!(jwk)
        raise PQCrypto::JWT::Error, "JWK pub is required" unless jwk.key?("pub")

        canonical = JSON.generate({ "alg" => jwk.fetch("alg"), "kty" => KTY, "pub" => jwk.fetch("pub") })
        base64url(Digest::SHA256.digest(canonical.b))
      end

      def base64url(bytes)
        Base64.urlsafe_encode64(String(bytes).b, padding: false)
      end

      def base64url_decode(value)
        raw = String(value)
        padding = (4 - raw.bytesize % 4) % 4
        Base64.urlsafe_decode64(raw + ("=" * padding))
      rescue ArgumentError => e
        raise PQCrypto::JWT::Error, "Invalid base64url value: #{e.message}"
      end

      def normalize_hash!(hash)
        raise PQCrypto::JWT::Error, "JWK must be a Hash-like object" unless hash.respond_to?(:to_hash)

        hash.to_hash.each_with_object({}) { |(key, value), normalized| normalized[String(key)] = value }
      end

      def algorithm_from_jwk!(jwk)
        raise PQCrypto::JWT::Error, "Unsupported JWK kty: #{jwk.fetch('kty', nil).inspect}" unless jwk.fetch("kty", nil) == KTY

        pq_algorithm_from_jose!(jwk.fetch("alg", nil))
      end

      def pq_algorithm_from_jose!(alg)
        algorithm = PQCrypto::JWT.algorithm_for(alg)
        unless algorithm&.key_kind == :signature
          raise PQCrypto::JWT::UnsupportedAlgorithm, "Unsupported JWK alg: #{alg.inspect}"
        end

        algorithm.pq_crypto_algorithm
      end
      private_class_method :pq_algorithm_from_jose!

      def alg_for_algorithm!(algorithm)
        match = PQCrypto::JWT.signing_algorithms.find { |candidate| candidate.pq_crypto_algorithm == algorithm }
        raise PQCrypto::JWT::UnsupportedAlgorithm, "Unsupported pq_crypto signature algorithm: #{algorithm.inspect}" unless match

        match.alg
      end

      def public_jwk(spec)
        {
          "kty" => KTY,
          "alg" => alg_for_algorithm!(spec.algorithm),
          "pub" => base64url(spec.public_bytes)
        }.tap do |jwk|
          OPTIONAL_PUBLIC_FIELDS.each do |field|
            value = spec.public_send(field.name)
            jwk[field.name] = field.coerce.call(value) unless value.nil?
          end
        end
      end
      private_class_method :public_jwk

      def private_jwk_from_seed(request)
        algorithm = pq_algorithm_from_jose!(request.alg)
        seed = validate_seed!(request.seed, algorithm)
        derived_public = derive_public_for_seed(algorithm, seed, request)
        public_key = request.public_key || derived_public || missing_public_key_for_seed!

        validate_public_key_for_algorithm!(public_key, algorithm)
        verify_seed_public_match!(public_key, derived_public) if request.verify_public

        public_jwk(PublicJWK.new(
          algorithm: algorithm,
          public_bytes: public_key.to_bytes,
          kid: request.kid,
          use: request.use,
          key_ops: request.key_ops
        )).merge("priv" => base64url(seed)).freeze
      end
      private_class_method :private_jwk_from_seed

      def derive_public_for_seed(algorithm, seed, request)
        return nil unless request.public_key.nil? || request.verify_public

        public_key_from_seed_if_supported(algorithm, seed)
      end
      private_class_method :derive_public_for_seed

      def missing_public_key_for_seed!
        raise PQCrypto::JWT::UnsupportedFeature,
              "AKP JWK export from seed requires pq_crypto public_key_from_seed/keypair_from_seed or public_key:"
      end
      private_class_method :missing_public_key_for_seed!

      def validate_public_key_for_algorithm!(public_key, algorithm)
        validate_public_key!(public_key)
        return if public_key.algorithm == algorithm

        raise PQCrypto::JWT::KeyTypeError,
              "public_key algorithm mismatch: expected #{algorithm.inspect}, got #{public_key.algorithm.inspect}"
      end
      private_class_method :validate_public_key_for_algorithm!

      def verify_seed_public_match!(public_key, derived_public)
        unless derived_public
          raise PQCrypto::JWT::UnsupportedFeature,
                "AKP JWK pub/priv consistency verification requires pq_crypto public_key_from_seed/keypair_from_seed"
        end
        return if public_key.to_bytes == derived_public.to_bytes

        raise PQCrypto::JWT::Error, "AKP JWK public_key does not match priv seed"
      end
      private_class_method :verify_seed_public_match!

      def decode_required_key_bytes!(jwk, spec, algorithm)
        raise PQCrypto::JWT::Error, "JWK #{spec.field} is required" unless jwk.key?(spec.field)

        decoded = base64url_decode(jwk.fetch(spec.field))
        details = PQCrypto::Signature.details(algorithm)
        expected = details.fetch(spec.detail_key) { details.fetch(spec.detail_key.to_s) }
        return decoded.b if decoded.bytesize == expected

        raise PQCrypto::JWT::Error,
              "Invalid #{spec.field} length for #{algorithm.inspect}: expected #{expected}, got #{decoded.bytesize}"
      end
      private_class_method :decode_required_key_bytes!

      def decode_required_seed!(jwk, algorithm)
        raise PQCrypto::JWT::Error, "JWK priv is required" unless jwk.key?("priv")

        validate_seed!(base64url_decode(jwk.fetch("priv")), algorithm)
      end
      private_class_method :decode_required_seed!

      def validate_seed!(seed, algorithm)
        bytes = String(seed).b
        return bytes if bytes.bytesize == seed_bytes_for(algorithm)

        raise PQCrypto::JWT::Error,
              "Invalid priv seed length for #{algorithm.inspect}: expected #{seed_bytes_for(algorithm)}, got #{bytes.bytesize}"
      end
      private_class_method :validate_seed!

      def seed_bytes_for(_algorithm)
        SEED_BYTES
      end
      private_class_method :seed_bytes_for

      def validate_public_key!(public_key)
        raise PQCrypto::JWT::KeyTypeError, "Expected PQCrypto::Signature::PublicKey" unless public_key.is_a?(PQCrypto::Signature::PublicKey)

        validate_algorithm!(public_key.algorithm)
      end
      private_class_method :validate_public_key!

      def validate_secret_key!(secret_key)
        raise PQCrypto::JWT::KeyTypeError, "Expected PQCrypto::Signature::SecretKey" unless secret_key.is_a?(PQCrypto::Signature::SecretKey)

        validate_algorithm!(secret_key.algorithm)
      end
      private_class_method :validate_secret_key!

      def validate_algorithm!(algorithm)
        return if PQCrypto::JWT.signing_algorithms.any? { |candidate| candidate.pq_crypto_algorithm == algorithm }

        raise PQCrypto::JWT::KeyTypeError, "Unsupported signature algorithm: #{algorithm.inspect}"
      end
      private_class_method :validate_algorithm!

      def secret_key_source(secret_key, public_key)
        return SecretKeySource.new(secret_key: secret_key.secret_key, public_key: public_key || secret_key.public_key) if secret_key.is_a?(PQCrypto::Signature::Keypair)

        SecretKeySource.new(secret_key: secret_key, public_key: public_key)
      end
      private_class_method :secret_key_source

      def seed_from_secret_key(secret_key)
        reject_non_seed_key!(secret_key)
        return seed_from_to_seed!(secret_key) if secret_key.respond_to?(:to_seed)

        raise PQCrypto::JWT::UnsupportedFeature,
              "SecretKey seed export requires a public pq_crypto #to_seed API; use from_seed(..., public_key:) instead"
      end
      private_class_method :seed_from_secret_key

      def reject_non_seed_key!(secret_key)
        return unless secret_key.respond_to?(:seed?) && !secret_key.seed?

        raise PQCrypto::JWT::UnsupportedFeature,
              "SecretKey was not created from a seed; cannot export RFC 9964 AKP JWK"
      end
      private_class_method :reject_non_seed_key!

      def seed_from_to_seed!(secret_key)
        seed = secret_key.to_seed
        raise PQCrypto::JWT::UnsupportedFeature, "SecretKey #to_seed returned nil" if seed.nil?

        validate_seed!(seed, secret_key.algorithm)
      rescue PQCrypto::Error => e
        raise PQCrypto::JWT::UnsupportedFeature, "SecretKey seed export failed: #{e.message}"
      end
      private_class_method :seed_from_to_seed!

      def public_key_from_seed_if_supported(algorithm, seed)
        deriver = SEED_DERIVERS.find { |candidate| PQCrypto::Signature.respond_to?(candidate.method_name) }
        deriver&.action&.call(algorithm, seed)
      end
      private_class_method :public_key_from_seed_if_supported

      def verify_private_public_consistency!(jwk, algorithm, seed)
        verify_seed_public_match!(public_key_from_jwk(jwk), public_key_from_seed_if_supported(algorithm, seed))
      end
      private_class_method :verify_private_public_consistency!

      def with_pq_import_errors
        yield
      rescue *PQ_IMPORT_ERRORS => e
        raise PQCrypto::JWT::Error, e.message
      end
      private_class_method :with_pq_import_errors
    end
  end
end
