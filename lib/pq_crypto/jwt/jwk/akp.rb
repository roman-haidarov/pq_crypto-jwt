# frozen_string_literal: true

require "jwt/jwk/key_base"

module JWT
  module JWK
    class AKP < KeyBase
      KTY = "AKP".freeze
      KTYS = [KTY, PQCrypto::Signature::PublicKey, JWT::JWK::AKP].freeze
      AKP_KEY_ELEMENTS = %i[kty alg pub priv].freeze
      PRIVATE_EXPORT_OPTIONS = %i[private include_private].freeze

      class NullKidGenerator
        def initialize(_jwk); end
        def generate = nil
      end

      def initialize(key, params = nil, options = {})
        params = params.is_a?(String) ? { kid: params } : (params || {})
        params = params.transform_keys(&:to_sym)
        key_params = extract_key_params(key)
        @checked_public_key = check_jwk_params!(key_params, params)
        super({ kid_generator: NullKidGenerator }.merge(options || {}), key_params.merge(params))
      end

      def private? = parameters.key?(:priv) && !parameters[:priv].nil?
      def verify_key = public_key

      def public_key
        @public_key ||= @checked_public_key || PQCrypto::JWT::JWK.public_key_from_jwk(string_export)
      end

      def signing_key = private? ? secret_key : public_key

      def secret_key
        raise JWT::JWKError, "AKP JWK does not contain private material" unless private?

        @secret_key ||= PQCrypto::JWT::JWK.secret_key_from_jwk(string_export(include_private: true))
      end

      def export(options = {})
        include_private = PRIVATE_EXPORT_OPTIONS.any? { |key| (options || {})[key] }
        parameters.clone.tap { |exported| exported.delete(:priv) unless include_private }
      end

      def members
        keys = private? ? %i[alg kty pub priv] : %i[alg kty pub]
        keys.each_with_object({}) { |key, out| out[key] = self[key] }
      end

      def key_digest = PQCrypto::JWT::JWK.thumbprint(string_export)
      def jwa = PQCrypto::JWT.algorithm_for(self[:alg]) || super

      def []=(key, value)
        raise ArgumentError, "cannot overwrite cryptographic key attributes" if AKP_KEY_ELEMENTS.include?(key.to_sym)

        super
      end

      private

      def string_export(include_private: false)
        export(include_private: include_private).transform_keys(&:to_s)
      end

      def extract_key_params(key)
        case key
        when JWT::JWK::AKP then key.export(include_private: key.private?)
        when Hash then key.transform_keys(&:to_sym)
        when PQCrypto::Signature::PublicKey
          PQCrypto::JWT::JWK.from_public_key(key).transform_keys(&:to_sym)
        when PQCrypto::Signature::Keypair, PQCrypto::Signature::SecretKey
          raise JWT::JWKError,
                "AKP private JWK export from SecretKey requires public seed-export APIs in pq_crypto; " \
                "use PQCrypto::JWT::JWK.from_seed(seed, alg:, public_key:) instead"
        else
          raise ArgumentError, "key must be an AKP JWK Hash or PQCrypto::Signature::PublicKey"
        end
      rescue PQCrypto::JWT::Error => e
        raise JWT::JWKError, e.message
      end

      def validate_private_seed_metadata!(jwk)
        seed = PQCrypto::JWT::JWK.base64url_decode(jwk.fetch("priv") { raise PQCrypto::JWT::Error, "JWK priv is required" })
        return if seed.bytesize == PQCrypto::JWT::JWK::SEED_BYTES

        raise PQCrypto::JWT::Error,
              "Invalid priv seed length for #{jwk.fetch('alg').inspect}: expected #{PQCrypto::JWT::JWK::SEED_BYTES}, got #{seed.bytesize}"
      end

      def check_jwk_params!(key_params, params)
        raise ArgumentError, "cannot overwrite cryptographic key attributes" unless (AKP_KEY_ELEMENTS & params.keys).empty?
        raise JWT::JWKError, "Incorrect 'kty' value: #{key_params[:kty]}, expected #{KTY}" unless key_params[:kty] == KTY
        raise JWT::JWKError, "AKP JWK alg is required" unless key_params[:alg]
        raise JWT::JWKError, "AKP JWK pub is required" unless key_params[:pub]
        raise JWT::JWKError, "Unsupported AKP JWK alg: #{key_params[:alg].inspect}" unless PQCrypto::JWT.algorithm_for(key_params[:alg])

        parsed = key_params.transform_keys(&:to_s)
        validate_private_seed_metadata!(parsed) if key_params.key?(:priv)
        PQCrypto::JWT::JWK.public_key_from_jwk(parsed)
      rescue PQCrypto::JWT::Error => e
        raise JWT::JWKError, e.message
      end
    end
  end
end
