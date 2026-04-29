# frozen_string_literal: true

require "jwt/jwk/key_base"

module JWT
  module JWK
    class AKP < KeyBase
      KTY = "AKP".freeze
      KTYS = [
        KTY,
        PQCrypto::Signature::PublicKey,
        JWT::JWK::AKP,
      ].freeze
      AKP_KEY_ELEMENTS = %i[kty alg pub priv].freeze

      class NullKidGenerator
        def initialize(_jwk); end

        def generate = nil
      end

      def initialize(key, params = nil, options = {})
        params ||= {}
        options ||= {}
        options = { kid_generator: NullKidGenerator }.merge(options)
        params = { kid: params } if params.is_a?(String)
        key_params = extract_key_params(key)
        params = params.transform_keys(&:to_sym)
        check_jwk_params!(key_params, params)
        super(options, key_params.merge(params))
      end

      def private?
        false
      end

      def public_key
        @public_key ||= PQCrypto::JWT::JWK.public_key_from_jwk(string_export)
      end

      def signing_key
        public_key
      end

      def verify_key
        public_key
      end

      def export(_options = {})
        parameters.clone.tap { |exported| exported.delete(:priv) }
      end

      def members
        %i[alg kty pub].each_with_object({}) { |key, out| out[key] = self[key] }
      end

      def key_digest
        PQCrypto::JWT::JWK.thumbprint(string_export)
      end

      def jwa
        PQCrypto::JWT.algorithm_for(self[:alg]) || super
      end

      def []=(key, value)
        raise ArgumentError, "cannot overwrite cryptographic key attributes" if AKP_KEY_ELEMENTS.include?(key.to_sym)

        super
      end

      private

      def string_export
        export.transform_keys(&:to_s)
      end

      def extract_key_params(key)
        case key
        when JWT::JWK::AKP
          key.export
        when Hash
          key.transform_keys(&:to_sym)
        when PQCrypto::Signature::PublicKey
          PQCrypto::JWT::JWK.from_public_key(key).transform_keys(&:to_sym)
        when PQCrypto::Signature::Keypair, PQCrypto::Signature::SecretKey
          raise JWT::JWKError, "AKP private JWK export is not supported in the first release"
        else
          raise ArgumentError, "key must be a public AKP JWK Hash or PQCrypto::Signature::PublicKey"
        end
      end

      def check_jwk_params!(key_params, params)
        raise ArgumentError, "cannot overwrite cryptographic key attributes" unless (AKP_KEY_ELEMENTS & params.keys).empty?
        raise JWT::JWKError, "Incorrect 'kty' value: #{key_params[:kty]}, expected #{KTY}" unless key_params[:kty] == KTY
        raise JWT::JWKError, "AKP JWK alg is required" unless key_params[:alg]
        raise JWT::JWKError, "AKP JWK pub is required" unless key_params[:pub]
        raise JWT::JWKError, "AKP private JWK import is not supported in the first release" if key_params[:priv]
        raise JWT::JWKError, "Unsupported AKP JWK alg: #{key_params[:alg].inspect}" unless PQCrypto::JWT.algorithm_for(key_params[:alg])
      end
    end
  end
end

JWT::JWK.classes.delete(JWT::JWK::AKP)
