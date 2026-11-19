# frozen_string_literal: true

require "base64"
require "digest"
require "json"

module PQCrypto
  module JWT
    module JWK
      extend self

      KTY = "AKP"
      SEED_BYTES = defined?(PQCrypto::PKCS8::ML_DSA_SEED_BYTES) ? PQCrypto::PKCS8::ML_DSA_SEED_BYTES : 32
      THUMBPRINT_URI_PREFIX = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"

      def from_public_key(public_key, kid: nil, use: nil, key_ops: nil)
        validate_key!(public_key, PQCrypto::Signature::PublicKey)
        public_jwk(public_key, kid:, use:, key_ops:).freeze
      end

      def from_seed(seed, alg:, kid: nil, public_key: nil, use: nil, key_ops: nil, verify_public: false)
        algorithm = pq_algorithm_from_jose!(alg)
        seed = validate_seed!(seed, algorithm)
        derived = derive_public_key(algorithm, seed) if public_key.nil? || verify_public
        public_key ||= derived
        unless public_key
          raise UnsupportedFeature,
                "AKP JWK export from seed requires pq_crypto public_key_from_seed/keypair_from_seed or public_key:"
        end

        validate_key!(public_key, PQCrypto::Signature::PublicKey)
        actual = public_key.algorithm
        unless actual == algorithm
          raise KeyTypeError,
                "public_key algorithm mismatch: expected #{algorithm.inspect}, got #{actual.inspect}"
        end
        check_seed_matches_public!(public_key.to_bytes, derived) if verify_public

        public_jwk(public_key, kid:, use:, key_ops:).merge("priv" => base64url(seed).freeze).freeze
      end

      def from_secret_key(secret_key, kid: nil, public_key: nil, use: nil, key_ops: nil)
        if secret_key.is_a?(PQCrypto::Signature::Keypair)
          public_key ||= secret_key.public_key
          secret_key = secret_key.secret_key
        end
        validate_key!(secret_key, PQCrypto::Signature::SecretKey)

        seed = seed_from_secret_key!(secret_key)
        from_seed(seed, alg: jose_alg_for!(secret_key.algorithm), kid:, public_key:, use:, key_ops:)
      end

      def public_key_from_jwk(hash)
        _jwk, algorithm, public_bytes = parse_public!(hash)
        PQCrypto::Signature.public_key_from_bytes(algorithm, public_bytes)
      rescue ArgumentError, PQCrypto::Error => error
        raise Error, error.message
      end

      def secret_key_from_jwk(hash, verify_public: false)
        jwk, algorithm, public_bytes = parse_public!(hash)
        seed = validate_seed!(base64url_decode(jwk.fetch("priv") { raise Error, "JWK priv is required" }), algorithm)
        check_seed_matches_public!(public_bytes, derive_public_key(algorithm, seed)) if verify_public

        PQCrypto::Signature.secret_key_from_seed(algorithm, seed)
      rescue ArgumentError, PQCrypto::Error => error
        raise Error, error.message
      end

      def thumbprint(jwk_hash)
        jwk = parse_public!(jwk_hash).first
        base64url(Digest::SHA256.digest(JSON.generate("alg" => jwk["alg"], "kty" => KTY, "pub" => jwk["pub"])))
      end

      def thumbprint_uri(jwk_hash) = "#{THUMBPRINT_URI_PREFIX}#{thumbprint(jwk_hash)}"

      def base64url(bytes) = Base64URL.encode(bytes)

      def base64url_decode(value)
        Base64URL.decode(value)
      rescue ArgumentError => error
        raise Error, "Invalid base64url value: #{error.message}"
      end

      def normalize_hash!(hash)
        raise Error, "JWK must be a Hash-like object" unless hash.respond_to?(:to_hash)

        converted = hash.to_hash
        raise Error, "JWK #to_hash must return a Hash" unless converted.is_a?(Hash)

        converted.transform_keys { |key| String(key) }
      end

      def algorithm_from_jwk!(jwk)
        kty = jwk["kty"]
        raise Error, "Unsupported JWK kty: #{kty.inspect}" unless kty == KTY

        pq_algorithm_from_jose!(jwk["alg"])
      end

      private

      def parse_public!(hash)
        jwk = normalize_hash!(hash)
        algorithm = algorithm_from_jwk!(jwk)
        [jwk, algorithm, decode_public_bytes!(jwk, algorithm)]
      end

      def decode_public_bytes!(jwk, algorithm)
        raise Error, "JWK pub is required" unless jwk.key?("pub")

        bytes = base64url_decode(jwk["pub"])
        expected = PQCrypto::Signature.details(algorithm).fetch(:public_key_bytes)
        actual = bytes.bytesize
        return bytes if actual == expected

        raise Error, "Invalid pub length for #{algorithm.inspect}: expected #{expected}, got #{actual}"
      end

      def public_jwk(public_key, kid:, use:, key_ops:)
        {
          "kty" => KTY,
          "alg" => jose_alg_for!(public_key.algorithm),
          "pub" => base64url(public_key.to_bytes).freeze,
          "kid" => metadata_string(kid),
          "use" => metadata_string(use),
          "key_ops" => (Array(key_ops).map { |operation| operation.to_s.dup.freeze }.freeze unless key_ops.nil?)
        }.compact
      end

      def metadata_string(value)
        String(value).dup.freeze unless value.nil?
      end

      def pq_algorithm_from_jose!(alg)
        PQCrypto::JWT.algorithm_for(alg)&.pq_crypto_algorithm ||
          raise(UnsupportedAlgorithm, "Unsupported JWK alg: #{alg.inspect}")
      end

      def jose_alg_for!(pq_algorithm)
        signing_algorithm_for(pq_algorithm)&.alg ||
          raise(UnsupportedAlgorithm, "Unsupported pq_crypto signature algorithm: #{pq_algorithm.inspect}")
      end

      def signing_algorithm_for(pq_algorithm)
        PQCrypto::JWT.signing_algorithms.find { |algorithm| algorithm.pq_crypto_algorithm == pq_algorithm }
      end

      def validate_key!(key, klass)
        raise KeyTypeError, "Expected #{klass}" unless key.is_a?(klass)

        actual = key.algorithm
        return if signing_algorithm_for(actual)

        raise KeyTypeError, "Unsupported signature algorithm: #{actual.inspect}"
      end

      def validate_seed!(seed, algorithm)
        bytes = String(seed).b
        actual = bytes.bytesize
        return bytes if actual == SEED_BYTES

        raise Error, "Invalid priv seed length for #{algorithm.inspect}: expected #{SEED_BYTES}, got #{actual}"
      end

      def derive_public_key(algorithm, seed)
        if PQCrypto::Signature.respond_to?(:public_key_from_seed)
          PQCrypto::Signature.public_key_from_seed(algorithm, seed)
        elsif PQCrypto::Signature.respond_to?(:keypair_from_seed)
          PQCrypto::Signature.keypair_from_seed(algorithm, seed).public_key
        end
      end

      def check_seed_matches_public!(public_bytes, derived)
        unless derived
          raise UnsupportedFeature,
                "AKP JWK pub/priv consistency verification requires pq_crypto public_key_from_seed/keypair_from_seed"
        end
        raise Error, "AKP JWK public_key does not match priv seed" unless public_bytes == derived.to_bytes
      end

      def seed_from_secret_key!(secret_key)
        if secret_key.respond_to?(:seed?) && !secret_key.seed?
          raise UnsupportedFeature, "SecretKey was not created from a seed; cannot export RFC 9964 AKP JWK"
        end

        unless secret_key.respond_to?(:to_seed)
          raise UnsupportedFeature, "SecretKey seed export requires a public pq_crypto #to_seed API; " \
                                    "use from_seed(..., public_key:) instead"
        end

        seed = secret_key.to_seed
        raise UnsupportedFeature, "SecretKey #to_seed returned nil" if seed.nil?

        validate_seed!(seed, secret_key.algorithm)
      rescue PQCrypto::Error => error
        raise UnsupportedFeature, "SecretKey seed export failed: #{error.message}"
      end
    end
  end
end
