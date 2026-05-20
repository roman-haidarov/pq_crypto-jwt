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
    ALGORITHMS_BY_JOSE = SIGNING_ALGORITHMS.to_h { |algorithm| [algorithm.alg, algorithm] }.freeze

    REGISTRATION_MUTEX = Monitor.new

    class << self
      def algorithms = SIGNING_ALGORITHMS
      def signing_algorithms = SIGNING_ALGORITHMS
      def kem_algorithms = KEM_ALGORITHMS
      def algorithm_for(alg_string) = ALGORITHMS_BY_JOSE[alg_string]
      def registered? = @registered == true

      def register!
        REGISTRATION_MUTEX.synchronize do
          return true if registered?

          SIGNING_ALGORITHMS.each { |algorithm| ::JWT::JWA.register_algorithm(algorithm) }
          ::JWT::JWK.classes << ::JWT::JWK::AKP unless ::JWT::JWK.classes.include?(::JWT::JWK::AKP)
          @registered = true
        end
        true
      end
    end
  end
end
