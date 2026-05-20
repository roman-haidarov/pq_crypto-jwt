# frozen_string_literal: true

require "jwt/jwk/key_base"

module JWT
  module JWK
    class AKP < KeyBase
      KTY = "AKP".freeze
      KTYS = [KTY, PQCrypto::Signature::PublicKey, JWT::JWK::AKP].freeze
      AKP_KEY_ELEMENTS = %i[kty alg pub priv].freeze
      PRIVATE_EXPORT_OPTIONS = %i[private include_private].freeze

      KeyExtractor = Data.define(:match, :extract)
      ParamRule = Data.define(:message, :valid)
      CheckedKeys = Data.define(:public_key, :secret_key)

      KEY_EXTRACTORS = [
        KeyExtractor.new(->(key) { key.is_a?(JWT::JWK::AKP) }, ->(key) { key.export(include_private: key.private?) }),
        KeyExtractor.new(->(key) { key.is_a?(Hash) }, ->(key) { key.transform_keys(&:to_sym) }),
        KeyExtractor.new(->(key) { key.is_a?(PQCrypto::Signature::PublicKey) }, ->(key) { PQCrypto::JWT::JWK.from_public_key(key).transform_keys(&:to_sym) }),
        KeyExtractor.new(->(key) { key.is_a?(PQCrypto::Signature::Keypair) || key.is_a?(PQCrypto::Signature::SecretKey) },
                         ->(_) { raise JWT::JWKError, "AKP private JWK export from SecretKey requires public seed-export APIs in pq_crypto; use PQCrypto::JWT::JWK.from_seed(seed, alg:, public_key:) instead" })
      ].freeze

      PARAM_RULES = [
        ParamRule.new("cannot overwrite cryptographic key attributes", ->(key_params, params) { (AKP_KEY_ELEMENTS & params.keys).empty? }),
        ParamRule.new(nil, ->(key_params, _) { key_params[:kty] == KTY }),
        ParamRule.new("AKP JWK alg is required", ->(key_params, _) { key_params[:alg] }),
        ParamRule.new("AKP JWK pub is required", ->(key_params, _) { key_params[:pub] }),
        ParamRule.new(nil, ->(key_params, _) { PQCrypto::JWT.algorithm_for(key_params[:alg]) })
      ].freeze

      class NullKidGenerator
        def initialize(_jwk); end

        def generate = nil
      end

      def initialize(key, params = nil, options = {})
        normalized_params = normalize_params(params)
        key_params = extract_key_params(key)
        @checked_keys = check_jwk_params!(key_params, normalized_params)
        super({ kid_generator: NullKidGenerator }.merge(options || {}), key_params.merge(normalized_params))
      end

      def private?
        parameters.key?(:priv) && !parameters[:priv].nil?
      end

      def public_key
        @public_key ||= @checked_keys.public_key || PQCrypto::JWT::JWK.public_key_from_jwk(string_export(include_private: false))
      end

      def signing_key
        @signing_key ||= private? ? secret_key : public_key
      end

      def secret_key
        raise JWT::JWKError, "AKP JWK does not contain private material" unless private?

        @secret_key ||= @checked_keys.secret_key || PQCrypto::JWT::JWK.secret_key_from_jwk(string_export(include_private: true))
      end

      def verify_key
        public_key
      end

      def export(options = {})
        include_private = PRIVATE_EXPORT_OPTIONS.any? { |key| (options || {})[key] }
        parameters.clone.tap { |exported| exported.delete(:priv) unless include_private }
      end

      def members
        member_keys.each_with_object({}) { |key, out| out[key] = self[key] }
      end

      def key_digest
        PQCrypto::JWT::JWK.thumbprint(string_export(include_private: false))
      end

      def jwa
        PQCrypto::JWT.algorithm_for(self[:alg]) || super
      end

      def []=(key, value)
        raise ArgumentError, "cannot overwrite cryptographic key attributes" if AKP_KEY_ELEMENTS.include?(key.to_sym)

        super
      end

      private

      def member_keys
        private? ? %i[alg kty pub priv] : %i[alg kty pub]
      end

      def normalize_params(params)
        params = { kid: params } if params.is_a?(String)
        (params || {}).transform_keys(&:to_sym)
      end

      def string_export(include_private: false)
        export(include_private: include_private).transform_keys(&:to_s)
      end

      def extract_key_params(key)
        extractor = KEY_EXTRACTORS.find { |candidate| candidate.match.call(key) }
        raise ArgumentError, "key must be an AKP JWK Hash or PQCrypto::Signature::PublicKey" unless extractor

        extractor.extract.call(key)
      rescue PQCrypto::JWT::Error => e
        raise JWT::JWKError, e.message
      end

      def check_jwk_params!(key_params, params)
        validate_param_rules!(key_params, params)
        parsed = key_params.transform_keys(&:to_s)
        CheckedKeys.new(
          public_key: PQCrypto::JWT::JWK.public_key_from_jwk(parsed),
          secret_key: key_params[:priv] ? PQCrypto::JWT::JWK.secret_key_from_jwk(parsed) : nil
        )
      rescue PQCrypto::JWT::Error => e
        raise JWT::JWKError, e.message
      end

      def validate_param_rules!(key_params, params)
        PARAM_RULES.each do |rule|
          next if rule.valid.call(key_params, params)

          raise rule_error(rule, key_params)
        end
      end

      def rule_error(rule, key_params)
        message = rule.message || default_rule_message(key_params)
        rule.message == "cannot overwrite cryptographic key attributes" ? ArgumentError.new(message) : JWT::JWKError.new(message)
      end

      def default_rule_message(key_params)
        return "Incorrect 'kty' value: #{key_params[:kty]}, expected #{KTY}" unless key_params[:kty] == KTY

        "Unsupported AKP JWK alg: #{key_params[:alg].inspect}"
      end
    end
  end
end
