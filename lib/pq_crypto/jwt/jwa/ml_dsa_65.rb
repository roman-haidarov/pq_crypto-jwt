# frozen_string_literal: true

require_relative "../jwa"
require_relative "ml_dsa_streaming"

module PQCrypto
  module JWT
    module JWA
      module MLDSA65
        extend ::JWT::JWA::SigningAlgorithm
        extend PQCrypto::JWT::JWA::MLDSA
        extend PQCrypto::JWT::JWA::MLDSAStreaming

        ALG = "ML-DSA-65".freeze
        PQ_CRYPTO_ALGORITHM = :ml_dsa_65

        def self.alg = ALG
      end
    end
  end
end
