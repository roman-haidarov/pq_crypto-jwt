# frozen_string_literal: true

require_relative "../jwa"

module PQCrypto
  module JWT
    module JWA
      module MLDSA44
        extend ::JWT::JWA::SigningAlgorithm
        extend PQCrypto::JWT::JWA::MLDSA

        ALG = "ML-DSA-44".freeze
        PQ_CRYPTO_ALGORITHM = :ml_dsa_44

        def self.alg = ALG
      end
    end
  end
end
