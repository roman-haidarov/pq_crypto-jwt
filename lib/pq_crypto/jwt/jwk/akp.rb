# frozen_string_literal: true

require "jwt/jwk/key_base"

module JWT
  module JWK
    class AKP < KeyBase
      KTY = "AKP"
      KTYS = [KTY, PQCrypto::Signature::PublicKey, JWT::JWK::AKP].freeze
      AKP_KEY_ELEMENTS = %i[kty alg pub priv].freeze
      AKP_PUBLIC_KEY_ELEMENTS = %i[alg kty pub].freeze
      PRIVATE_EXPORT_OPTIONS = %i[private include_private].freeze

      class NullKidGenerator
        def initialize(_jwk); end
        def generate = nil
      end

      attr_reader :public_key

      def initialize(key, params = nil, options = {})
        params = { kid: params } if params.is_a?(String)
        params = (params || {}).transform_keys(&:to_sym)
        key_params = snapshot_key_params(extract_key_params(key))
        @public_key = validate_key_params!(key_params, params)
        super({ kid_generator: NullKidGenerator, **(options || {}) }, key_params.merge(params))
      end

      def private? = !self[:priv].nil?
      def verify_key = public_key
      def signing_key = private? ? secret_key : public_key

      def secret_key
        raise JWT::JWKError, "AKP JWK does not contain private material" unless private?

        self.cached_secret_key ||= PQCrypto::JWT::JWK.secret_key_from_jwk(string_export(include_private: true))
      end

      def export(options = {})
        include_private = (options || {}).values_at(*PRIVATE_EXPORT_OPTIONS).any?
        include_private ? parameters.dup : parameters.except(:priv)
      end

      def members = parameters.slice(*AKP_PUBLIC_KEY_ELEMENTS)

      def parameters = super.dup.freeze

      def key_digest = PQCrypto::JWT::JWK.thumbprint(string_export)
      def jwa = PQCrypto::JWT.algorithm_for(self[:alg]) || super

      def []=(key, value)
        raise ArgumentError, "cannot overwrite cryptographic key attributes" if AKP_KEY_ELEMENTS.include?(key.to_sym)

        super
      end

      private

      attr_accessor :cached_secret_key

      def snapshot_key_params(key_params)
        key_params.to_h do |name, value|
          copied = AKP_KEY_ELEMENTS.include?(name) && value.is_a?(String) ? value.dup.freeze : value
          [name, copied]
        end
      end

      def string_export(include_private: false) = export(include_private:).transform_keys(&:to_s)

      def extract_key_params(key)
        case key
        when JWT::JWK::AKP then key.export(include_private: key.private?)
        when Hash then key.transform_keys(&:to_sym)
        when PQCrypto::Signature::PublicKey then PQCrypto::JWT::JWK.from_public_key(key).transform_keys(&:to_sym)
        when PQCrypto::Signature::Keypair, PQCrypto::Signature::SecretKey
          raise JWT::JWKError,
                "AKP private JWK export from SecretKey requires public seed-export APIs in pq_crypto; " \
                "use PQCrypto::JWT::JWK.from_seed(seed, alg:, public_key:) instead"
        else
          raise ArgumentError, "key must be an AKP JWK Hash or PQCrypto::Signature::PublicKey"
        end
      rescue PQCrypto::JWT::Error => error
        raise JWT::JWKError, error.message
      end

      def validate_key_params!(key_params, params)
        raise ArgumentError, "cannot overwrite cryptographic key attributes" if AKP_KEY_ELEMENTS.intersect?(params.keys)

        kty, alg, pub = key_params.values_at(:kty, :alg, :pub)
        raise JWT::JWKError, "Incorrect 'kty' value: #{kty}, expected #{KTY}" unless kty == KTY
        raise JWT::JWKError, "AKP JWK alg is required" unless alg
        raise JWT::JWKError, "AKP JWK pub is required" unless pub
        raise JWT::JWKError, "Unsupported AKP JWK alg: #{alg.inspect}" unless PQCrypto::JWT.algorithm_for(alg)

        validate_seed_length!(key_params) if key_params.key?(:priv)
        PQCrypto::JWT::JWK.public_key_from_jwk(key_params)
      rescue PQCrypto::JWT::Error => error
        raise JWT::JWKError, error.message
      end

      def validate_seed_length!(key_params)
        actual = PQCrypto::JWT::JWK.base64url_decode(key_params[:priv]).bytesize
        expected = PQCrypto::JWT::JWK::SEED_BYTES
        return if actual == expected

        raise JWT::JWKError,
              "Invalid priv seed length for #{key_params[:alg].inspect}: expected #{expected}, got #{actual}"
      end
    end
  end
end
