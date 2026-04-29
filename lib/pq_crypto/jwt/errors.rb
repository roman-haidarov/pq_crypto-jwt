# frozen_string_literal: true

module PQCrypto
  module JWT
    class Error < StandardError; end
    class UnsupportedAlgorithm < Error; end
    class KeyTypeError < Error; end
  end
end
