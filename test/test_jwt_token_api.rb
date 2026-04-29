# frozen_string_literal: true

require_relative "test_helper"

class TestJWTTokenAPI < Minitest::Test
  def test_token_and_encoded_token_api
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    token = JWT::Token.new(payload: { "pay" => "load" }, header: { "kid" => "k1" })

    token.sign!(algorithm: "ML-DSA-65", key: keypair.secret_key)
    encoded_token = JWT::EncodedToken.new(token.jwt)
    encoded_token.verify_signature!(algorithm: "ML-DSA-65", key: keypair.public_key)
    encoded_token.verify_claims!({})

    assert_equal "load", encoded_token.payload.fetch("pay")
    assert_equal "ML-DSA-65", encoded_token.header.fetch("alg")
  end
end
