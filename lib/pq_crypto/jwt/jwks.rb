# frozen_string_literal: true

module PQCrypto
  module JWT
    module JWKS
      module_function

      CACHE_EMPTY = Object.new.freeze
      KID_STRATEGIES = %i[thumbprint thumbprint_uri].freeze
      VALIDATION_CACHE_LIMIT = 1024
      VALIDATION_CACHE_FIELD_BYTES_LIMIT = 8192
      VALIDATION_CACHE = {}
      VALIDATION_CACHE_MUTEX = Mutex.new
      private_constant :VALIDATION_CACHE_FIELD_BYTES_LIMIT, :VALIDATION_CACHE, :VALIDATION_CACHE_MUTEX

      def from_keys(public_keys, kids: nil, kid_strategy: nil)
        keys = Array(public_keys)
        kids = normalize_kids!(keys, kids, kid_strategy)

        jwks = keys.each_with_index.map do |public_key, index|
          jwk = PQCrypto::JWT::JWK.from_public_key(public_key, kid: kids&.fetch(index))
          apply_kid_strategy(jwk, kid_strategy)
        end
        { "keys" => jwks }.freeze
      end

      def find(jwks, kid: nil, alg: nil, thumbprint: nil)
        each_candidate(jwks, kid, alg, thumbprint) do |key|
          return key
        end
        nil
      end

      def find_all(jwks, kid: nil, alg: nil, thumbprint: nil)
        matches = []
        each_candidate(jwks, kid, alg, thumbprint) { |key| matches << key }
        matches
      end

      def loader(jwks_hash_or_callable)
        cached = CACHE_EMPTY
        mutex = Mutex.new

        lambda do |options = {}|
          options ||= {}
          invalidate = options[:invalidate]
          current = cached
          return current if !invalidate && !current.equal?(CACHE_EMPTY)

          mutex.synchronize do
            cached = CACHE_EMPTY if invalidate
            if cached.equal?(CACHE_EMPTY)
              cached = jwks_hash_or_callable.respond_to?(:call) ? jwks_hash_or_callable.call(options) : jwks_hash_or_callable
            end
            cached
          end
        end
      end

      def raw_keys_from(jwks)
        source = jwks.respond_to?(:to_hash) ? jwks.to_hash : jwks
        keys = source.respond_to?(:[]) ? (source["keys"] || source[:keys]) : nil
        Array(keys)
      end
      private_class_method :raw_keys_from

      def each_candidate(jwks, kid, alg, thumbprint)
        raw_keys_from(jwks).each do |key|
          next unless key.respond_to?(:to_hash)

          normalized = normalize_jwk_hash(key.to_hash)
          next unless cheap_match?(normalized, kid, alg)
          next unless cached_valid_public_jwk?(normalized)
          next unless thumbprint.nil? || PQCrypto::JWT::JWK.thumbprint(normalized) == thumbprint

          yield normalized
        rescue PQCrypto::JWT::Error, ArgumentError, TypeError
          next
        end
      end
      private_class_method :each_candidate

      def normalize_jwk_hash(hash)
        hash.each_with_object({}) { |(key, value), out| out[String(key)] = value }
      end
      private_class_method :normalize_jwk_hash

      def value_for(hash, key) = hash[key] || hash[key.to_sym]
      private_class_method :value_for

      def cheap_match?(key, kid, alg)
        (kid.nil? || value_for(key, "kid") == kid) &&
          (alg.nil? || value_for(key, "alg") == alg)
      end
      private_class_method :cheap_match?

      def normalize_kids!(public_keys, kids, kid_strategy)
        raise ArgumentError, "kid_strategy must be one of #{KID_STRATEGIES.inspect}" if kid_strategy && !KID_STRATEGIES.include?(kid_strategy)
        raise ArgumentError, "kids and kid_strategy are mutually exclusive" if kids && kid_strategy
        return nil unless kids

        unless kids.respond_to?(:to_ary)
          raise ArgumentError, "kids must be an Array with one kid per public key"
        end

        normalized = kids.to_ary
        unless normalized.is_a?(Array)
          raise ArgumentError, "kids must be an Array with one kid per public key"
        end
        raise ArgumentError, "kids.size must match public_keys.size" unless normalized.size == public_keys.size

        normalized
      end
      private_class_method :normalize_kids!

      def apply_kid_strategy(jwk, kid_strategy)
        return jwk unless kid_strategy

        kid = case kid_strategy
              when :thumbprint then PQCrypto::JWT::JWK.thumbprint(jwk)
              when :thumbprint_uri then PQCrypto::JWT::JWK.thumbprint_uri(jwk)
              end
        jwk.merge("kid" => kid).freeze
      end
      private_class_method :apply_kid_strategy

      def cached_valid_public_jwk?(key)
        cache_key = validation_cache_key(key)
        return valid_public_jwk?(key) unless cache_key

        VALIDATION_CACHE_MUTEX.synchronize do
          cached = VALIDATION_CACHE[cache_key]
          return cached unless cached.nil?
        end

        result = valid_public_jwk?(key)
        VALIDATION_CACHE_MUTEX.synchronize do
          VALIDATION_CACHE.shift if VALIDATION_CACHE.size >= VALIDATION_CACHE_LIMIT
          VALIDATION_CACHE[cache_key] = result
        end
        result
      end
      private_class_method :cached_valid_public_jwk?

      def validation_cache_key(key)
        kty = key["kty"]
        alg = key["alg"]
        pub = key["pub"]
        return nil unless kty.is_a?(String) && alg.is_a?(String) && pub.is_a?(String)
        return nil if kty.bytesize > VALIDATION_CACHE_FIELD_BYTES_LIMIT
        return nil if alg.bytesize > VALIDATION_CACHE_FIELD_BYTES_LIMIT
        return nil if pub.bytesize > VALIDATION_CACHE_FIELD_BYTES_LIMIT

        [kty.dup.freeze, alg.dup.freeze, pub.dup.freeze].freeze
      end
      private_class_method :validation_cache_key

      def valid_public_jwk?(key)
        PQCrypto::JWT::JWK.public_key_from_jwk(key)
        true
      rescue PQCrypto::JWT::Error, ArgumentError, TypeError
        false
      end
      private_class_method :valid_public_jwk?

      def clear_validation_cache!
        VALIDATION_CACHE_MUTEX.synchronize { VALIDATION_CACHE.clear }
      end
    end
  end
end
