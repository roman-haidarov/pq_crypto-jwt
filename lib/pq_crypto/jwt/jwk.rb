# frozen_string_literal: true

require "base64"
require "digest"
require "json"

module PQCrypto
  module JWT
    module JWK
      module_function

      KTY = "AKP".freeze

      def from_public_key(public_key, kid: nil)
        validate_public_key!(public_key)
        base_public_jwk(public_key.algorithm, public_key.to_bytes, kid: kid).freeze
      end

      def from_secret_key(*, **)
        raise PQCrypto::JWT::UnsupportedAlgorithm,
              "Private AKP JWK export is not supported in the first release; use PEM/PKCS#8 for signing keys"
      end

      def public_key_from_jwk(hash)
        jwk = normalize_hash!(hash)
        reject_private_material!(jwk)
        algorithm = algorithm_from_jwk!(jwk)
        public_bytes = decode_required_key_bytes!(jwk, "pub", algorithm, :public_key_bytes)
        PQCrypto::Signature.public_key_from_bytes(algorithm, public_bytes)
      rescue ArgumentError => e
        raise PQCrypto::JWT::Error, e.message
      end

      def secret_key_from_jwk(*)
        raise PQCrypto::JWT::UnsupportedAlgorithm,
              "Private AKP JWK import is not supported in the first release; use PEM/PKCS#8 for signing keys"
      end

      def thumbprint(jwk_hash)
        jwk = normalize_hash!(jwk_hash)
        reject_private_material!(jwk)
        algorithm_from_jwk!(jwk)
        raise PQCrypto::JWT::Error, "JWK pub is required" unless jwk.key?("pub")

        canonical = JSON.generate({ "alg" => jwk.fetch("alg"), "kty" => KTY, "pub" => jwk.fetch("pub") })
        base64url(Digest::SHA256.digest(canonical.b))
      end

      def base64url(bytes)
        Base64.urlsafe_encode64(String(bytes).b, padding: false)
      end

      def base64url_decode(value)
        Base64.urlsafe_decode64(String(value))
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

      def reject_private_material!(jwk)
        return unless jwk.key?("priv")

        raise PQCrypto::JWT::UnsupportedAlgorithm,
              "Private AKP JWK material is not supported in the first release"
      end
      private_class_method :reject_private_material!

      def algorithm_from_jwk!(jwk)
        unless jwk.fetch("kty", nil) == KTY
          raise PQCrypto::JWT::Error, "Unsupported JWK kty: #{jwk.fetch('kty', nil).inspect}"
        end

        alg = jwk.fetch("alg", nil)
        algorithm = PQCrypto::JWT.algorithm_for(alg)
        raise PQCrypto::JWT::UnsupportedAlgorithm, "Unsupported JWK alg: #{alg.inspect}" unless algorithm
        raise PQCrypto::JWT::UnsupportedAlgorithm, "Unsupported JWK alg: #{alg.inspect}" unless algorithm.key_kind == :signature

        algorithm.pq_crypto_algorithm
      end

      def alg_for_algorithm!(algorithm)
        match = PQCrypto::JWT.signing_algorithms.find { |candidate| candidate.pq_crypto_algorithm == algorithm }
        raise PQCrypto::JWT::UnsupportedAlgorithm, "Unsupported pq_crypto signature algorithm: #{algorithm.inspect}" unless match

        match.alg
      end

      def base_public_jwk(algorithm, public_bytes, kid: nil)
        jwk = {
          "kty" => KTY,
          "alg" => alg_for_algorithm!(algorithm),
          "pub" => base64url(public_bytes),
        }
        jwk["kid"] = String(kid) unless kid.nil?
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

      def validate_public_key!(public_key)
        unless public_key.is_a?(PQCrypto::Signature::PublicKey)
          raise PQCrypto::JWT::KeyTypeError, "Expected PQCrypto::Signature::PublicKey"
        end

        validate_algorithm!(public_key.algorithm)
      end
      private_class_method :validate_public_key!

      def validate_algorithm!(algorithm)
        return if PQCrypto::JWT.signing_algorithms.any? { |candidate| candidate.pq_crypto_algorithm == algorithm }

        raise PQCrypto::JWT::KeyTypeError, "Unsupported signature algorithm: #{algorithm.inspect}"
      end
      private_class_method :validate_algorithm!
    end
  end
end
