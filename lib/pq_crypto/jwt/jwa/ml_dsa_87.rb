# frozen_string_literal: true

require_relative "../jwa"

module PQCrypto
  module JWT
    module JWA
      module MLDSA87
        extend ::JWT::JWA::SigningAlgorithm
        extend PQCrypto::JWT::JWA::MLDSA

        ALG = "ML-DSA-87".freeze
        PQ_CRYPTO_ALGORITHM = :ml_dsa_87

        def self.alg = ALG
      end
    end
  end
end
