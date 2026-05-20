# frozen_string_literal: true

require_relative "../jwa"
require_relative "ml_dsa_streaming"

module PQCrypto
  module JWT
    module JWA
      module MLDSA44
        extend ::JWT::JWA::SigningAlgorithm
        extend PQCrypto::JWT::JWA::MLDSA
        extend PQCrypto::JWT::JWA::MLDSAStreaming

        ALG = "ML-DSA-44".freeze
        PQ_CRYPTO_ALGORITHM = :ml_dsa_44

        def self.alg = ALG
      end
    end
  end
end
