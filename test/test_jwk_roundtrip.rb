# frozen_string_literal: true

require_relative "test_helper"

class TestJWKRoundtrip < Minitest::Test
  def test_signature_public_key_jwk_round_trip
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key, kid: "sig-key")
    imported_public_key = PQCrypto::JWT::JWK.public_key_from_jwk(jwk)

    assert_equal keypair.public_key.to_bytes, imported_public_key.to_bytes
    assert jwk.frozen?
    assert_equal "AKP", jwk.fetch("kty")
    assert_equal "ML-DSA-65", jwk.fetch("alg")
    assert_equal "sig-key", jwk.fetch("kid")
    refute jwk.key?("priv")
  end

  def test_private_key_jwk_export_is_not_in_first_release_scope
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")

    assert_raises(PQCrypto::JWT::UnsupportedAlgorithm) { PQCrypto::JWT::JWK.from_secret_key(keypair) }
  end

  def test_private_key_jwk_import_is_not_in_first_release_scope
    assert_raises(PQCrypto::JWT::UnsupportedAlgorithm) do
      PQCrypto::JWT::JWK.secret_key_from_jwk({ "kty" => "AKP", "alg" => "ML-DSA-65", "pub" => "", "priv" => "" })
    end
  end

  def test_public_key_from_jwk_rejects_private_material
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key).dup
    jwk["priv"] = "private-material"

    assert_raises(PQCrypto::JWT::UnsupportedAlgorithm) { PQCrypto::JWT::JWK.public_key_from_jwk(jwk) }
  end

  def test_jwk_rejects_unsupported_alg
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key).dup
    jwk["alg"] = "ML-KEM-768"

    assert_raises(PQCrypto::JWT::UnsupportedAlgorithm) { PQCrypto::JWT::JWK.public_key_from_jwk(jwk) }
  end

  def test_jwk_rejects_invalid_kty
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key).dup
    jwk["kty"] = "RSA"

    assert_raises(PQCrypto::JWT::Error) { PQCrypto::JWT::JWK.public_key_from_jwk(jwk) }
  end

  def test_jwk_rejects_invalid_base64url_pub
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key).dup
    jwk["pub"] = "not valid ***"

    assert_raises(PQCrypto::JWT::Error) { PQCrypto::JWT::JWK.public_key_from_jwk(jwk) }
  end
end
