# frozen_string_literal: true

require "jwt"
require "monitor"
require "pq_crypto"

require_relative "jwt/version"
require_relative "jwt/errors"
require_relative "jwt/jwa"
require_relative "jwt/jwa/ml_dsa_44"
require_relative "jwt/jwa/ml_dsa_65"
require_relative "jwt/jwa/ml_dsa_87"
require_relative "jwt/keys"
require_relative "jwt/jwk"
require_relative "jwt/jwk/akp"
require_relative "jwt/jwks"

module PQCrypto
  module JWT
    MLDSA44 = JWA::MLDSA44
    MLDSA65 = JWA::MLDSA65
    MLDSA87 = JWA::MLDSA87

    SIGNING_ALGORITHMS = [JWA::MLDSA44, JWA::MLDSA65, JWA::MLDSA87].freeze
    KEM_ALGORITHMS = [].freeze
    ALGORITHMS = SIGNING_ALGORITHMS.freeze
    ALGORITHMS_BY_JOSE = ALGORITHMS.to_h { |algorithm| [algorithm.alg, algorithm] }.freeze

    class << self
      def algorithms
        ALGORITHMS
      end

      def signing_algorithms
        SIGNING_ALGORITHMS
      end

      # Kept as an explicit empty list so callers can branch safely.
      # ML-KEM/JWE is intentionally not part of the first stable release.
      def kem_algorithms
        KEM_ALGORITHMS
      end

      def algorithm_for(alg_string)
        ALGORITHMS_BY_JOSE[alg_string]
      end

      def register!
        registration_monitor.synchronize do
          return true if registered?

          SIGNING_ALGORITHMS.each { |algorithm| ::JWT::JWA.register_algorithm(algorithm) }
          ensure_akp_jwk_registered!
          @registered = true
        end
        true
      end

      def registered?
        @registered == true
      end

      private

      def registration_monitor
        @registration_monitor ||= Monitor.new
      end

      def ensure_akp_jwk_registered!
        classes = ::JWT::JWK.classes
        classes << ::JWT::JWK::AKP unless classes.include?(::JWT::JWK::AKP)
      end
    end
  end
end
