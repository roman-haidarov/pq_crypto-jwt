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

      def from_public_key(public_key, kid: nil, use: nil, key_ops: nil)
        validate_public_key!(public_key)
        base_public_jwk(public_key.algorithm, public_key.to_bytes, kid: kid, use: use, key_ops: key_ops).freeze
      end

      # RFC 9964 private AKP JWK uses the 32-byte raw ML-DSA seed in `priv`, not an expanded secret key.
      # The public key is required by JWK, so current pq_crypto 0.6.x callers must pass it until
      # pq_crypto exposes Signature.keypair_from_seed/public_key_from_seed as public API.
      # Pass verify_public: true to reject a public_key that does not match the seed once parent
      # public seed-derivation APIs are available; on pq_crypto 0.6.1 this raises UnsupportedFeature.
      def from_seed(seed, alg:, kid: nil, public_key: nil, use: nil, key_ops: nil, verify_public: false)
        algorithm = pq_algorithm_from_jose!(alg)
        seed_bytes = validate_seed!(seed, algorithm)
        derived_public = public_key_from_seed_if_supported(algorithm, seed_bytes) if public_key.nil? || verify_public
        public_key ||= derived_public
        unless public_key
          raise PQCrypto::JWT::UnsupportedFeature,
                "AKP JWK export from seed requires pq_crypto public_key_from_seed/keypair_from_seed or public_key:"
        end

        validate_public_key!(public_key)
        unless public_key.algorithm == algorithm
          raise PQCrypto::JWT::KeyTypeError,
                "public_key algorithm mismatch: expected #{algorithm.inspect}, got #{public_key.algorithm.inspect}"
        end

        if verify_public
          unless derived_public
            raise PQCrypto::JWT::UnsupportedFeature,
                  "AKP JWK pub/priv consistency verification requires pq_crypto public_key_from_seed/keypair_from_seed"
          end

          unless public_key.to_bytes == derived_public.to_bytes
            raise PQCrypto::JWT::Error, "AKP JWK public_key does not match priv seed"
          end
        end

        jwk = base_public_jwk(algorithm, public_key.to_bytes, kid: kid, use: use, key_ops: key_ops)
        jwk["priv"] = base64url(seed_bytes)
        jwk.freeze
      end

      def from_secret_key(secret_key, kid: nil, public_key: nil, use: nil, key_ops: nil)
        if secret_key.is_a?(PQCrypto::Signature::Keypair)
          public_key ||= secret_key.public_key
          secret_key = secret_key.secret_key
        end

        validate_secret_key!(secret_key)
        seed = seed_from_secret_key(secret_key)
        from_seed(seed, alg: alg_for_algorithm!(secret_key.algorithm), kid: kid, public_key: public_key, use: use, key_ops: key_ops)
      end

      def public_key_from_jwk(hash)
        jwk = normalize_hash!(hash)
        algorithm = algorithm_from_jwk!(jwk)
        public_bytes = decode_required_key_bytes!(jwk, "pub", algorithm, :public_key_bytes)
        PQCrypto::Signature.public_key_from_bytes(algorithm, public_bytes)
      rescue ArgumentError, PQCrypto::Error => e
        raise PQCrypto::JWT::Error, e.message
      end

      # Imports the RFC 9964 private AKP `priv` raw seed.
      #
      # `pub` is still required by the JWK shape. With pq_crypto 0.6.1 the adapter cannot
      # derive public bytes from a seed through public API, so `pub` is trusted as metadata by
      # default. Pass `verify_public: true` to require a public parent seed-derivation API and
      # reject mismatched `pub`/`priv` material.
      def secret_key_from_jwk(hash, verify_public: false)
        jwk = normalize_hash!(hash)
        algorithm = algorithm_from_jwk!(jwk)
        decode_required_key_bytes!(jwk, "pub", algorithm, :public_key_bytes)
        seed = decode_required_seed!(jwk, algorithm)

        verify_private_public_consistency!(jwk, algorithm, seed) if verify_public

        PQCrypto::Signature.secret_key_from_seed(algorithm, seed)
      rescue ArgumentError, PQCrypto::Error => e
        raise PQCrypto::JWT::Error, e.message
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
        unless hash.respond_to?(:to_hash)
          raise PQCrypto::JWT::Error, "JWK must be a Hash-like object"
        end

        hash.to_hash.each_with_object({}) do |(key, value), normalized|
          normalized[String(key)] = value
        end
      end

      def algorithm_from_jwk!(jwk)
        unless jwk.fetch("kty", nil) == KTY
          raise PQCrypto::JWT::Error, "Unsupported JWK kty: #{jwk.fetch('kty', nil).inspect}"
        end

        alg = jwk.fetch("alg", nil)
        pq_algorithm_from_jose!(alg)
      end

      def pq_algorithm_from_jose!(alg)
        algorithm = PQCrypto::JWT.algorithm_for(alg)
        raise PQCrypto::JWT::UnsupportedAlgorithm, "Unsupported JWK alg: #{alg.inspect}" unless algorithm
        raise PQCrypto::JWT::UnsupportedAlgorithm, "Unsupported JWK alg: #{alg.inspect}" unless algorithm.key_kind == :signature

        algorithm.pq_crypto_algorithm
      end
      private_class_method :pq_algorithm_from_jose!

      def alg_for_algorithm!(algorithm)
        match = PQCrypto::JWT.signing_algorithms.find { |candidate| candidate.pq_crypto_algorithm == algorithm }
        raise PQCrypto::JWT::UnsupportedAlgorithm, "Unsupported pq_crypto signature algorithm: #{algorithm.inspect}" unless match

        match.alg
      end

      def base_public_jwk(algorithm, public_bytes, kid: nil, use: nil, key_ops: nil)
        jwk = {
          "kty" => KTY,
          "alg" => alg_for_algorithm!(algorithm),
          "pub" => base64url(public_bytes),
        }
        jwk["kid"] = String(kid) unless kid.nil?
        jwk["use"] = String(use) unless use.nil?
        jwk["key_ops"] = Array(key_ops).map(&:to_s) unless key_ops.nil?
        jwk
      end
      private_class_method :base_public_jwk

      def decode_required_key_bytes!(jwk, field, algorithm, detail_key)
        raise PQCrypto::JWT::Error, "JWK #{field} is required" unless jwk.key?(field)

        decoded = base64url_decode(jwk.fetch(field))
        details = PQCrypto::Signature.details(algorithm)
        expected = details.fetch(detail_key) { details.fetch(detail_key.to_s) }
        unless decoded.bytesize == expected
          raise PQCrypto::JWT::Error,
                "Invalid #{field} length for #{algorithm.inspect}: expected #{expected}, got #{decoded.bytesize}"
        end

        decoded.b
      end
      private_class_method :decode_required_key_bytes!

      def decode_required_seed!(jwk, algorithm)
        raise PQCrypto::JWT::Error, "JWK priv is required" unless jwk.key?("priv")

        seed = base64url_decode(jwk.fetch("priv"))
        validate_seed!(seed, algorithm)
      end
      private_class_method :decode_required_seed!

      def validate_seed!(seed, algorithm)
        bytes = String(seed).b
        expected = seed_bytes_for(algorithm)
        unless bytes.bytesize == expected
          raise PQCrypto::JWT::Error,
                "Invalid priv seed length for #{algorithm.inspect}: expected #{expected}, got #{bytes.bytesize}"
        end
        bytes
      end
      private_class_method :validate_seed!

      def seed_bytes_for(_algorithm)
        if defined?(PQCrypto::PKCS8::ML_DSA_SEED_BYTES)
          PQCrypto::PKCS8::ML_DSA_SEED_BYTES
        else
          32
        end
      end
      private_class_method :seed_bytes_for

      def validate_public_key!(public_key)
        unless public_key.is_a?(PQCrypto::Signature::PublicKey)
          raise PQCrypto::JWT::KeyTypeError, "Expected PQCrypto::Signature::PublicKey"
        end

        validate_algorithm!(public_key.algorithm)
      end
      private_class_method :validate_public_key!

      def validate_secret_key!(secret_key)
        unless secret_key.is_a?(PQCrypto::Signature::SecretKey)
          raise PQCrypto::JWT::KeyTypeError, "Expected PQCrypto::Signature::SecretKey"
        end

        validate_algorithm!(secret_key.algorithm)
      end
      private_class_method :validate_secret_key!

      def validate_algorithm!(algorithm)
        return if PQCrypto::JWT.signing_algorithms.any? { |candidate| candidate.pq_crypto_algorithm == algorithm }

        raise PQCrypto::JWT::KeyTypeError, "Unsupported signature algorithm: #{algorithm.inspect}"
      end
      private_class_method :validate_algorithm!

      def seed_from_secret_key(secret_key)
        if secret_key.respond_to?(:seed?) && !secret_key.seed?
          raise PQCrypto::JWT::UnsupportedFeature,
                "SecretKey was not created from a seed; cannot export RFC 9964 AKP JWK"
        end

        if secret_key.respond_to?(:to_seed)
          begin
            seed = secret_key.to_seed
          rescue PQCrypto::Error => e
            raise PQCrypto::JWT::UnsupportedFeature, "SecretKey seed export failed: #{e.message}"
          end

          raise PQCrypto::JWT::UnsupportedFeature, "SecretKey #to_seed returned nil" if seed.nil?

          return validate_seed!(seed, secret_key.algorithm)
        end

        raise PQCrypto::JWT::UnsupportedFeature,
              "SecretKey seed export requires a public pq_crypto #to_seed API; use from_seed(..., public_key:) instead"
      end
      private_class_method :seed_from_secret_key

      def public_key_from_seed_if_supported(algorithm, seed)
        if PQCrypto::Signature.respond_to?(:public_key_from_seed)
          return PQCrypto::Signature.public_key_from_seed(algorithm, seed)
        end

        if PQCrypto::Signature.respond_to?(:keypair_from_seed)
          keypair = PQCrypto::Signature.keypair_from_seed(algorithm, seed)
          return keypair.public_key
        end

        nil
      end
      private_class_method :public_key_from_seed_if_supported

      def verify_private_public_consistency!(jwk, algorithm, seed)
        derived_public = public_key_from_seed_if_supported(algorithm, seed)
        unless derived_public
          raise PQCrypto::JWT::UnsupportedFeature,
                "AKP JWK pub/priv consistency verification requires pq_crypto public_key_from_seed/keypair_from_seed"
        end

        imported_public = public_key_from_jwk(jwk)
        return if imported_public.to_bytes == derived_public.to_bytes

        raise PQCrypto::JWT::Error, "AKP JWK pub does not match priv seed"
      end
      private_class_method :verify_private_public_consistency!
    end
  end
end
