# frozen_string_literal: true

require_relative "test_helper"

class TestJWKThumbprint < Minitest::Test
  def test_thumbprint_ignores_kid
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk_a = PQCrypto::JWT::JWK.from_public_key(keypair.public_key, kid: "a")
    jwk_b = PQCrypto::JWT::JWK.from_public_key(keypair.public_key, kid: "b")

    assert_equal PQCrypto::JWT::JWK.thumbprint(jwk_a), PQCrypto::JWT::JWK.thumbprint(jwk_b)
  end
end
