# frozen_string_literal: true

require_relative "test_helper"

class TestJWKRoundtrip < Minitest::Test
  def test_signature_public_key_jwk_round_trip
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key, kid: "sig-key", use: "sig", key_ops: ["verify"])
    imported_public_key = PQCrypto::JWT::JWK.public_key_from_jwk(jwk)

    assert_equal keypair.public_key.to_bytes, imported_public_key.to_bytes
    assert jwk.frozen?
    assert_equal "AKP", jwk.fetch("kty")
    assert_equal "ML-DSA-65", jwk.fetch("alg")
    assert_equal "sig-key", jwk.fetch("kid")
    assert_equal "sig", jwk.fetch("use")
    assert_equal ["verify"], jwk.fetch("key_ops")
    refute jwk.key?("priv")
  end

  def test_private_key_jwk_export_requires_seed_material
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")

    assert_raises(PQCrypto::JWT::UnsupportedFeature) do
      PQCrypto::JWT::JWK.from_secret_key(keypair)
    end
  end

  def test_private_key_jwk_export_from_seed_aware_keypair_when_parent_exposes_seed
    skip "pq_crypto does not expose public seed-aware keypair API yet" unless PQCrypto::Signature.respond_to?(:keypair_from_seed)

    seed = "s" * 32
    keypair = PQCrypto::Signature.keypair_from_seed(:ml_dsa_65, seed)
    jwk = PQCrypto::JWT::JWK.from_secret_key(keypair, kid: "seed-key")

    assert_equal "AKP", jwk.fetch("kty")
    assert_equal "ML-DSA-65", jwk.fetch("alg")
    assert_equal "seed-key", jwk.fetch("kid")
    assert_equal PQCrypto::JWT::JWK.base64url(seed), jwk.fetch("priv")
  end

  def test_private_key_jwk_import_from_seed
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    seed = "z" * 32
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key).merge("priv" => PQCrypto::JWT::JWK.base64url(seed))
    secret_key = PQCrypto::JWT::JWK.secret_key_from_jwk(jwk)

    assert_instance_of PQCrypto::Signature::SecretKey, secret_key
    assert_equal :ml_dsa_65, secret_key.algorithm
  end

  def test_public_key_from_jwk_accepts_private_material_but_uses_public_part_only
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key).dup
    jwk["priv"] = PQCrypto::JWT::JWK.base64url("z" * 32)

    imported = PQCrypto::JWT::JWK.public_key_from_jwk(jwk)

    assert_equal keypair.public_key.to_bytes, imported.to_bytes
  end

  def test_secret_key_from_jwk_rejects_invalid_private_seed_length
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key).merge("priv" => PQCrypto::JWT::JWK.base64url("x" * 31))

    assert_raises(PQCrypto::JWT::Error) { PQCrypto::JWT::JWK.secret_key_from_jwk(jwk) }
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
