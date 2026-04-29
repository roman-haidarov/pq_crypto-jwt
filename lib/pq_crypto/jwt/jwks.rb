# frozen_string_literal: true

module PQCrypto
  module JWT
    module JWKS
      module_function

      def from_keys(public_keys, kids: nil)
        keys = Array(public_keys).each_with_index.map do |public_key, index|
          kid = kids&.fetch(index, nil)
          PQCrypto::JWT::JWK.from_public_key(public_key, kid: kid)
        end
        { "keys" => keys }.freeze
      end

      def find(jwks, kid: nil, alg: nil)
        keys_from(jwks).find do |key|
          (kid.nil? || value_for(key, "kid") == kid) &&
            (alg.nil? || value_for(key, "alg") == alg)
        end
      end

      def loader(jwks_hash_or_callable)
        cached = nil
        lambda do |options = {}|
          if jwks_hash_or_callable.respond_to?(:call)
            cached = nil if options && options[:invalidate]
            cached ||= jwks_hash_or_callable.call(options || {})
          else
            cached = nil if options && options[:invalidate]
            cached ||= jwks_hash_or_callable
          end
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
