# frozen_string_literal: true

module PQCrypto
  module JWT
    module JWKS
      module_function

      CACHE_EMPTY = Object.new.freeze
      KeyFilter = Data.define(:kid, :alg, :thumbprint) do
        def match?(key)
          values = { "kid" => kid, "alg" => alg, "thumbprint" => thumbprint }
          values.all? do |field, expected|
            expected.nil? || value_for(key, field) == expected
          end
        end

        private

        def value_for(key, field)
          field == "thumbprint" ? PQCrypto::JWT::JWK.thumbprint(key) : key[field] || key[field.to_sym]
        end
      end

      def from_keys(public_keys, kids: nil)
        keys = Array(public_keys).each_with_index.map do |public_key, index|
          PQCrypto::JWT::JWK.from_public_key(public_key, kid: kids&.fetch(index, nil))
        end
        { "keys" => keys }.freeze
      end

      def find(jwks, kid: nil, alg: nil, thumbprint: nil)
        find_all(jwks, kid: kid, alg: alg, thumbprint: thumbprint).first
      end

      def find_all(jwks, kid: nil, alg: nil, thumbprint: nil)
        filter = KeyFilter.new(kid: kid, alg: alg, thumbprint: thumbprint)
        keys_from(jwks).select { |key| filter.match?(key) }
      end

      def loader(jwks_hash_or_callable)
        cached = CACHE_EMPTY
        lambda do |options = {}|
          cached = CACHE_EMPTY if (options || {})[:invalidate]
          cached = resolve_jwks(jwks_hash_or_callable, options || {}) if cached.equal?(CACHE_EMPTY)
          cached
        end
      end

      def keys_from(jwks)
        source = jwks.respond_to?(:to_hash) ? jwks.to_hash : jwks
        keys = source["keys"] || source[:keys] if source.respond_to?(:[])
        Array(keys).map { |key| stringify_hash(key) }
      end
      private_class_method :keys_from

      def resolve_jwks(source, options)
        source.respond_to?(:call) ? source.call(options) : source
      end
      private_class_method :resolve_jwks

      def stringify_hash(hash)
        hash.to_hash.each_with_object({}) { |(key, value), out| out[String(key)] = value }
      end
      private_class_method :stringify_hash
    end
  end
end
