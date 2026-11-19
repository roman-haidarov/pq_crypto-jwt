# frozen_string_literal: true

require_relative "jwks/validation_cache"
require_relative "jwks/loader"

module PQCrypto
  module JWT
    module JWKS
      extend self

      CACHE_EMPTY = Object.new.freeze
      KID_STRATEGIES = %i[thumbprint thumbprint_uri].freeze
      VALIDATION_CACHE_LIMIT = 1024
      VALIDATION_CACHE_FIELD_BYTES_LIMIT = 8192
      VALIDATION_CACHE = ValidationCache.new(VALIDATION_CACHE_LIMIT).freeze
      private_constant :VALIDATION_CACHE_FIELD_BYTES_LIMIT, :VALIDATION_CACHE, :ValidationCache, :Loader

      def from_keys(public_keys, kids: nil, kid_strategy: nil)
        public_keys = Array(public_keys)
        kids = normalize_kids!(public_keys.size, kids, kid_strategy)

        jwks = public_keys.zip(kids || []).map do |public_key, kid|
          jwk = JWK.from_public_key(public_key, kid:)
          kid_strategy ? jwk.merge("kid" => JWK.public_send(kid_strategy, jwk)).freeze : jwk
        end
        { "keys" => jwks }.freeze
      end

      def find(jwks, kid: nil, alg: nil, thumbprint: nil)
        enum_for(:each_candidate, jwks, kid:, alg:, thumbprint:).first
      end

      def find_all(jwks, kid: nil, alg: nil, thumbprint: nil)
        enum_for(:each_candidate, jwks, kid:, alg:, thumbprint:).to_a
      end

      def loader(jwks_hash_or_callable)
        Loader.new(jwks_hash_or_callable).method(:call).to_proc
      end

      def clear_validation_cache!
        VALIDATION_CACHE.clear
      end

      private

      def each_candidate(jwks, **filters)
        raw_keys_from(jwks).each do |key|
          jwk = JWK.normalize_hash!(key)
          yield jwk if match?(jwk, **filters)
        rescue Error, ArgumentError, TypeError
          nil
        end
      end

      def match?(jwk, kid:, alg:, thumbprint:)
        (kid.nil? || jwk["kid"] == kid) &&
          (alg.nil? || jwk["alg"] == alg) &&
          valid_public_jwk?(jwk) &&
          (thumbprint.nil? || JWK.thumbprint(jwk) == thumbprint)
      end

      def raw_keys_from(jwks)
        jwks = jwks.to_hash if jwks.respond_to?(:to_hash)
        return [] unless jwks.is_a?(Hash)

        Array(jwks["keys"] || jwks[:keys])
      end

      def normalize_kids!(count, kids, kid_strategy)
        if kid_strategy && !KID_STRATEGIES.include?(kid_strategy)
          raise ArgumentError, "kid_strategy must be one of #{KID_STRATEGIES.inspect}"
        end
        raise ArgumentError, "kids and kid_strategy are mutually exclusive" if kids && kid_strategy
        return unless kids

        kids = kids.to_ary if kids.respond_to?(:to_ary)
        raise ArgumentError, "kids must be an Array with one kid per public key" unless kids.is_a?(Array)
        raise ArgumentError, "kids.size must match public_keys.size" unless kids.size == count

        kids
      end

      def valid_public_jwk?(jwk)
        cache_key = validation_cache_key(jwk)
        return public_jwk?(jwk) unless cache_key

        VALIDATION_CACHE.fetch(cache_key) { public_jwk?(jwk) }
      end

      def validation_cache_key(jwk)
        fields = jwk.values_at("kty", "alg", "pub")
        cacheable = fields.all? { |field| field.is_a?(String) && field.bytesize <= VALIDATION_CACHE_FIELD_BYTES_LIMIT }
        fields.map { |field| field.dup.freeze }.freeze if cacheable
      end

      def public_jwk?(jwk)
        JWK.public_key_from_jwk(jwk)
        true
      rescue Error, ArgumentError, TypeError
        false
      end
    end
  end
end
