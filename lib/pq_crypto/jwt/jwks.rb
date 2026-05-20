# frozen_string_literal: true

module PQCrypto
  module JWT
    module JWKS
      module_function

      CACHE_EMPTY = Object.new.freeze

      def from_keys(public_keys, kids: nil)
        keys = Array(public_keys).each_with_index.map do |public_key, index|
          kid = kids&.fetch(index, nil)
          PQCrypto::JWT::JWK.from_public_key(public_key, kid: kid)
        end
        { "keys" => keys }.freeze
      end

      def find(jwks, kid: nil, alg: nil, thumbprint: nil)
        keys_from(jwks).find do |key|
          (kid.nil? || value_for(key, "kid") == kid) &&
            (alg.nil? || value_for(key, "alg") == alg) &&
            (thumbprint.nil? || PQCrypto::JWT::JWK.thumbprint(key) == thumbprint)
        end
      end

      def find_all(jwks, kid: nil, alg: nil, thumbprint: nil)
        keys_from(jwks).select do |key|
          (kid.nil? || value_for(key, "kid") == kid) &&
            (alg.nil? || value_for(key, "alg") == alg) &&
            (thumbprint.nil? || PQCrypto::JWT::JWK.thumbprint(key) == thumbprint)
        end
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
        keys = source["keys"] || source[:keys] if source.respond_to?(:[])
        Array(keys).map { |key| stringify_hash(key) }
      end
      private_class_method :keys_from

      def stringify_hash(hash)
        hash.to_hash.each_with_object({}) { |(key, value), out| out[String(key)] = value }
      end
      private_class_method :stringify_hash

      def value_for(hash, key)
        hash[key] || hash[key.to_sym]
      end
      private_class_method :value_for
    end
  end
end
