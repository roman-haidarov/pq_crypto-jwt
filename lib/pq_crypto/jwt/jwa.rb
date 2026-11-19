# frozen_string_literal: true

require_relative "jwa/streaming"
require_relative "jwa/detached_signing_input_io"
require_relative "jwa/ml_dsa"

module PQCrypto
  module JWT
    module JWA
      EMPTY_CONTEXT = "".b.freeze
      VERIFY_ERRORS = [
        PQCrypto::Error, PQCrypto::JWT::Error,
        ::JWT::DecodeError, ::JWT::VerificationError, ::JWT::JWKError,
        ArgumentError, TypeError, EncodingError
      ].freeze
      MLDSAStreaming = Streaming
    end
  end
end
