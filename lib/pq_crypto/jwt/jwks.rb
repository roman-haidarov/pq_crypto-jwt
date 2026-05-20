# frozen_string_literal: true

module PQCrypto
  module JWT
    module JWKS
      module_function

      CACHE_EMPTY = Object.new.freeze
      KID_STRATEGIES = %i[thumbprint thumbprint_uri].freeze

      def from_keys(public_keys, kids: nil, kid_strategy: nil)
        keys = Array(public_keys)
        validate_kid_options!(keys, kids, kid_strategy)

        jwks = keys.each_with_index.map do |public_key, index|
          jwk = PQCrypto::JWT::JWK.from_public_key(public_key, kid: kids&.fetch(index))
          apply_kid_strategy(jwk, kid_strategy)
        end
        { "keys" => jwks }.freeze
      end

      def find(jwks, kid: nil, alg: nil, thumbprint: nil)
        keys_from(jwks).find { |key| match?(key, kid, alg, thumbprint) }
      end

      def find_all(jwks, kid: nil, alg: nil, thumbprint: nil)
        keys_from(jwks).select { |key| match?(key, kid, alg, thumbprint) }
      end

      def loader(jwks_hash_or_callable)
        cached = CACHE_EMPTY
        mutex = Mutex.new

        lambda do |options = {}|
          options ||= {}
          mutex.synchronize do
            cached = CACHE_EMPTY if options[:invalidate]
            if cached.equal?(CACHE_EMPTY)
              cached = jwks_hash_or_callable.respond_to?(:call) ? jwks_hash_or_callable.call(options) : jwks_hash_or_callable
            end
            cached
          end
        end
      end

      def keys_from(jwks)
        source = jwks.respond_to?(:to_hash) ? jwks.to_hash : jwks
        keys = source.respond_to?(:[]) ? (source["keys"] || source[:keys]) : nil
        Array(keys).filter_map do |key|
          next nil unless key.respond_to?(:to_hash)

          normalized = key.to_hash.each_with_object({}) { |(k, v), out| out[String(k)] = v }
          valid_public_jwk?(normalized) ? normalized : nil
        end
      end
      private_class_method :keys_from

      def value_for(hash, key) = hash[key] || hash[key.to_sym]
      private_class_method :value_for

      def match?(key, kid, alg, thumbprint)
        (kid.nil? || value_for(key, "kid") == kid) &&
          (alg.nil? || value_for(key, "alg") == alg) &&
          (thumbprint.nil? || PQCrypto::JWT::JWK.thumbprint(key) == thumbprint)
      end
      private_class_method :match?

      def validate_kid_options!(public_keys, kids, kid_strategy)
        raise ArgumentError, "kid_strategy must be one of #{KID_STRATEGIES.inspect}" if kid_strategy && !KID_STRATEGIES.include?(kid_strategy)
        raise ArgumentError, "kids and kid_strategy are mutually exclusive" if kids && kid_strategy
        return unless kids

        unless kids.respond_to?(:to_ary)
          raise ArgumentError, "kids must be an Array with one kid per public key"
        end
        return if kids.size == public_keys.size

        raise ArgumentError, "kids.size must match public_keys.size"
      end
      private_class_method :validate_kid_options!

      def apply_kid_strategy(jwk, kid_strategy)
        return jwk unless kid_strategy

        kid = case kid_strategy
              when :thumbprint then PQCrypto::JWT::JWK.thumbprint(jwk)
              when :thumbprint_uri then PQCrypto::JWT::JWK.thumbprint_uri(jwk)
              end
        jwk.merge("kid" => kid).freeze
      end
      private_class_method :apply_kid_strategy

      def valid_public_jwk?(key)
        PQCrypto::JWT::JWK.public_key_from_jwk(key)
        true
      rescue PQCrypto::JWT::Error, ArgumentError, TypeError
        false
      end
      private_class_method :valid_public_jwk?
    end
  end
end
