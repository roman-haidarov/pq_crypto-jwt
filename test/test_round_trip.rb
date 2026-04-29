# frozen_string_literal: true

require_relative "test_helper"

class TestRoundTrip < Minitest::Test
  include PQCryptoJWTTestHelpers

  ALGORITHMS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"].freeze

  def test_round_trip_for_all_algorithms
    ALGORITHMS.each do |alg|
      keypair = PQCrypto::JWT::Keys.generate(alg)
      payload = { "foo" => "bar", "exp" => Time.now.to_i + 60 }
      token = JWT.encode(payload, keypair.secret_key, alg)
      decoded_payload, decoded_header = JWT.decode(token, keypair.public_key, true, algorithm: alg)

      assert_equal "bar", decoded_payload.fetch("foo"), "payload mismatch for #{alg}"
      assert_equal alg, decoded_header.fetch("alg"), "header alg mismatch for #{alg}"
    end
  end
end
