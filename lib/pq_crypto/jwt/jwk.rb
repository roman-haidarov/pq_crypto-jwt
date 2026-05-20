# frozen_string_literal: true

require "base64"
require "digest"
require "json"

module PQCrypto
  module JWT
    module JWK
      module_function

      KTY = "AKP".freeze
      SEED_BYTES = defined?(PQCrypto::PKCS8::ML_DSA_SEED_BYTES) ? PQCrypto::PKCS8::ML_DSA_SEED_BYTES : 32

      def from_public_key(public_key, kid: nil, use: nil, key_ops: nil)
        validate_key!(public_key, PQCrypto::Signature::PublicKey)
        public_jwk(public_key.algorithm, public_key.to_bytes, kid: kid, use: use, key_ops: key_ops).freeze
      end

      def from_seed(seed, alg:, kid: nil, public_key: nil, use: nil, key_ops: nil, verify_public: false)
        algorithm = pq_algorithm_from_jose!(alg)
        seed_bytes = validate_seed!(seed, algorithm)
        derived = derive_public_key(algorithm, seed_bytes) if public_key.nil? || verify_public
        public_key ||= derived
        unless public_key
          raise PQCrypto::JWT::UnsupportedFeature,
                "AKP JWK export from seed requires pq_crypto public_key_from_seed/keypair_from_seed or public_key:"
        end

        validate_key!(public_key, PQCrypto::Signature::PublicKey)
        unless public_key.algorithm == algorithm
          raise PQCrypto::JWT::KeyTypeError, "public_key algorithm mismatch: expected #{algorithm.inspect}, got #{public_key.algorithm.inspect}"
        end
        check_seed_matches_public!(public_key, derived) if verify_public

        public_jwk(algorithm, public_key.to_bytes, kid: kid, use: use, key_ops: key_ops)
          .merge!("priv" => base64url(seed_bytes))
          .freeze
      end

      def from_secret_key(secret_key, kid: nil, public_key: nil, use: nil, key_ops: nil)
        if secret_key.is_a?(PQCrypto::Signature::Keypair)
          public_key ||= secret_key.public_key
          secret_key = secret_key.secret_key
        end
        validate_key!(secret_key, PQCrypto::Signature::SecretKey)

        from_seed(seed_from_secret_key!(secret_key),
                  alg: jose_alg_for!(secret_key.algorithm),
                  kid: kid, public_key: public_key, use: use, key_ops: key_ops)
      end

      def public_key_from_jwk(hash)
        jwk = normalize_hash!(hash)
        algorithm = algorithm_from_jwk!(jwk)
        PQCrypto::Signature.public_key_from_bytes(algorithm, decode_field!(jwk, "pub", algorithm))
      rescue ArgumentError, PQCrypto::Error => e
        raise PQCrypto::JWT::Error, e.message
      end

      def secret_key_from_jwk(hash, verify_public: false)
        jwk = normalize_hash!(hash)
        algorithm = algorithm_from_jwk!(jwk)
        decode_field!(jwk, "pub", algorithm)
        seed = validate_seed!(base64url_decode(jwk.fetch("priv") { raise PQCrypto::JWT::Error, "JWK priv is required" }), algorithm)
        check_seed_matches_public!(public_key_from_jwk(jwk), derive_public_key(algorithm, seed)) if verify_public

        PQCrypto::Signature.secret_key_from_seed(algorithm, seed)
      rescue ArgumentError, PQCrypto::Error => e
        raise PQCrypto::JWT::Error, e.message
      end

      def thumbprint(jwk_hash)
        jwk = normalize_hash!(jwk_hash)
        algorithm_from_jwk!(jwk)
        raise PQCrypto::JWT::Error, "JWK pub is required" unless jwk.key?("pub")

        canonical = JSON.generate("alg" => jwk.fetch("alg"), "kty" => KTY, "pub" => jwk.fetch("pub"))
        base64url(Digest::SHA256.digest(canonical.b))
      end

      def base64url(bytes)
        Base64.urlsafe_encode64(String(bytes).b, padding: false)
      end

      def base64url_decode(value)
        raw = String(value)
        Base64.urlsafe_decode64(raw + ("=" * ((4 - raw.bytesize % 4) % 4)))
      rescue ArgumentError => e
        raise PQCrypto::JWT::Error, "Invalid base64url value: #{e.message}"
      end

      def normalize_hash!(hash)
        raise PQCrypto::JWT::Error, "JWK must be a Hash-like object" unless hash.respond_to?(:to_hash)

        hash.to_hash.each_with_object({}) { |(key, value), out| out[String(key)] = value }
      end

      def algorithm_from_jwk!(jwk)
        raise PQCrypto::JWT::Error, "Unsupported JWK kty: #{jwk['kty'].inspect}" unless jwk["kty"] == KTY

        pq_algorithm_from_jose!(jwk["alg"])
      end

      def pq_algorithm_from_jose!(alg)
        algorithm = PQCrypto::JWT.algorithm_for(alg)
        raise PQCrypto::JWT::UnsupportedAlgorithm, "Unsupported JWK alg: #{alg.inspect}" unless algorithm&.key_kind == :signature

        algorithm.pq_crypto_algorithm
      end
      private_class_method :pq_algorithm_from_jose!

      def jose_alg_for!(pq_algorithm)
        match = PQCrypto::JWT.signing_algorithms.find { |candidate| candidate.pq_crypto_algorithm == pq_algorithm }
        raise PQCrypto::JWT::UnsupportedAlgorithm, "Unsupported pq_crypto signature algorithm: #{pq_algorithm.inspect}" unless match

        match.alg
      end
      private_class_method :jose_alg_for!

      def public_jwk(pq_algorithm, public_bytes, kid:, use:, key_ops:)
        jwk = { "kty" => KTY, "alg" => jose_alg_for!(pq_algorithm), "pub" => base64url(public_bytes) }
        jwk["kid"] = String(kid) unless kid.nil?
        jwk["use"] = String(use) unless use.nil?
        jwk["key_ops"] = Array(key_ops).map(&:to_s) unless key_ops.nil?
        jwk
      end
      private_class_method :public_jwk

      def decode_field!(jwk, field, algorithm)
        raise PQCrypto::JWT::Error, "JWK #{field} is required" unless jwk.key?(field)

        decoded = base64url_decode(jwk.fetch(field))
        expected = PQCrypto::Signature.details(algorithm).fetch(:public_key_bytes)
        raise PQCrypto::JWT::Error, "Invalid #{field} length for #{algorithm.inspect}: expected #{expected}, got #{decoded.bytesize}" unless decoded.bytesize == expected

        decoded.b
      end
      private_class_method :decode_field!

      def validate_seed!(seed, algorithm)
        bytes = String(seed).b
        return bytes if bytes.bytesize == SEED_BYTES

        raise PQCrypto::JWT::Error, "Invalid priv seed length for #{algorithm.inspect}: expected #{SEED_BYTES}, got #{bytes.bytesize}"
      end
      private_class_method :validate_seed!

      def validate_key!(key, klass)
        raise PQCrypto::JWT::KeyTypeError, "Expected #{klass}" unless key.is_a?(klass)
        return if PQCrypto::JWT.signing_algorithms.any? { |c| c.pq_crypto_algorithm == key.algorithm }

        raise PQCrypto::JWT::KeyTypeError, "Unsupported signature algorithm: #{key.algorithm.inspect}"
      end
      private_class_method :validate_key!

      def derive_public_key(algorithm, seed)
        return PQCrypto::Signature.public_key_from_seed(algorithm, seed) if PQCrypto::Signature.respond_to?(:public_key_from_seed)
        return PQCrypto::Signature.keypair_from_seed(algorithm, seed).public_key if PQCrypto::Signature.respond_to?(:keypair_from_seed)

        nil
      end
      private_class_method :derive_public_key

      def check_seed_matches_public!(public_key, derived)
        unless derived
          raise PQCrypto::JWT::UnsupportedFeature,
                "AKP JWK pub/priv consistency verification requires pq_crypto public_key_from_seed/keypair_from_seed"
        end
        return if public_key.to_bytes == derived.to_bytes

        raise PQCrypto::JWT::Error, "AKP JWK public_key does not match priv seed"
      end
      private_class_method :check_seed_matches_public!

      def seed_from_secret_key!(secret_key)
        if secret_key.respond_to?(:seed?) && !secret_key.seed?
          raise PQCrypto::JWT::UnsupportedFeature,
                "SecretKey was not created from a seed; cannot export RFC 9964 AKP JWK"
        end
        unless secret_key.respond_to?(:to_seed)
          raise PQCrypto::JWT::UnsupportedFeature,
                "SecretKey seed export requires a public pq_crypto #to_seed API; use from_seed(..., public_key:) instead"
        end

        seed = secret_key.to_seed
        raise PQCrypto::JWT::UnsupportedFeature, "SecretKey #to_seed returned nil" if seed.nil?

        validate_seed!(seed, secret_key.algorithm)
      rescue PQCrypto::Error => e
        raise PQCrypto::JWT::UnsupportedFeature, "SecretKey seed export failed: #{e.message}"
      end
      private_class_method :seed_from_secret_key!
    end
  end
end
