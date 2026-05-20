# frozen_string_literal: true

require_relative "test_helper"

class TestJWKThumbprint < Minitest::Test
  def test_thumbprint_ignores_kid
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk_a = PQCrypto::JWT::JWK.from_public_key(keypair.public_key, kid: "a")
    jwk_b = PQCrypto::JWT::JWK.from_public_key(keypair.public_key, kid: "b")

    assert_equal PQCrypto::JWT::JWK.thumbprint(jwk_a), PQCrypto::JWT::JWK.thumbprint(jwk_b)
  end

  def test_thumbprint_rejects_invalid_public_key_length
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key).dup
    jwk["pub"] = PQCrypto::JWT::JWK.base64url("x")

    assert_raises(PQCrypto::JWT::Error) { PQCrypto::JWT::JWK.thumbprint(jwk) }
  end

  def test_thumbprint_uri_uses_rfc9278_prefix
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key)

    assert_equal "urn:ietf:params:oauth:jwk-thumbprint:sha-256:#{PQCrypto::JWT::JWK.thumbprint(jwk)}",
                 PQCrypto::JWT::JWK.thumbprint_uri(jwk)
  end
end
