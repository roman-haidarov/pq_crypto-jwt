# frozen_string_literal: true

module PQCrypto
  module JWT
    module JWKS
      module_function

      CACHE_EMPTY = Object.new.freeze

      def from_keys(public_keys, kids: nil)
        keys = Array(public_keys).each_with_index.map do |public_key, index|
          PQCrypto::JWT::JWK.from_public_key(public_key, kid: kids&.fetch(index, nil))
        end
        { "keys" => keys }.freeze
      end

      def find(jwks, kid: nil, alg: nil, thumbprint: nil)
        keys_from(jwks).find { |key| match?(key, kid, alg, thumbprint) }
      end

      def find_all(jwks, kid: nil, alg: nil, thumbprint: nil)
        keys_from(jwks).select { |key| match?(key, kid, alg, thumbprint) }
      end

      def loader(jwks_hash_or_callable)
        cached = CACHE_EMPTY
        lambda do |options = {}|
          options ||= {}
          cached = CACHE_EMPTY if options[:invalidate]
          if cached.equal?(CACHE_EMPTY)
            cached = jwks_hash_or_callable.respond_to?(:call) ? jwks_hash_or_callable.call(options) : jwks_hash_or_callable
          end
          cached
        end
      end

      def keys_from(jwks)
        source = jwks.respond_to?(:to_hash) ? jwks.to_hash : jwks
        keys = source.respond_to?(:[]) ? (source["keys"] || source[:keys]) : nil
        Array(keys).map { |key| key.to_hash.each_with_object({}) { |(k, v), out| out[String(k)] = v } }
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
    end
  end
end
