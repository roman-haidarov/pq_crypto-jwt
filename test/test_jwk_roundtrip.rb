# frozen_string_literal: true

require_relative "test_helper"

class TestJWKRoundtrip < Minitest::Test
  include PQCryptoJWTTestHelpers

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

  def test_akp_jwk_does_not_expand_private_seed_on_initialize
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key).merge("priv" => PQCrypto::JWT::JWK.base64url("z" * 32))
    called = false

    with_stub(PQCrypto::JWT::JWK, :secret_key_from_jwk, lambda { |*_args, **_kwargs|
      called = true
      raise "secret key should be materialized lazily"
    }) do
      akp = JWT::JWK::AKP.new(jwk)

      refute called, "secret_key_from_jwk was called during AKP#initialize"
      assert akp.private?
    end
  end

  def test_akp_jwk_materializes_secret_key_lazily_on_demand
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    seed = "z" * 32
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key).merge("priv" => PQCrypto::JWT::JWK.base64url(seed))

    akp = JWT::JWK::AKP.new(jwk)
    secret_key = akp.secret_key
    secret_key_again = akp.secret_key

    assert_instance_of PQCrypto::Signature::SecretKey, secret_key
    assert_same secret_key, secret_key_again, "secret_key should be memoized after first materialization"
  end

  def test_akp_jwk_rejects_invalid_private_seed_metadata_without_expansion
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key).merge("priv" => PQCrypto::JWT::JWK.base64url("x" * 31))

    assert_raises(JWT::JWKError) { JWT::JWK::AKP.new(jwk) }
  end

  def test_private_key_jwk_export_requires_seed_material
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")

    assert_raises(PQCrypto::JWT::UnsupportedFeature) do
      PQCrypto::JWT::JWK.from_secret_key(keypair)
    end
  end

  def test_from_seed_requires_public_key_until_parent_exposes_public_derivation
    skip "pq_crypto exposes public seed derivation" if seed_derivation_supported?

    assert_raises(PQCrypto::JWT::UnsupportedFeature) do
      PQCrypto::JWT::JWK.from_seed("s" * 32, alg: "ML-DSA-65")
    end
  end

  def test_private_key_jwk_import_strict_public_check_requires_parent_derivation
    skip "pq_crypto exposes public seed derivation" if seed_derivation_supported?

    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key).merge("priv" => PQCrypto::JWT::JWK.base64url("z" * 32))

    assert_raises(PQCrypto::JWT::UnsupportedFeature) do
      PQCrypto::JWT::JWK.secret_key_from_jwk(jwk, verify_public: true)
    end
  end

  def test_private_key_jwk_export_from_seed_aware_keypair_when_parent_exposes_seed
    unless PQCrypto::Signature.respond_to?(:keypair_from_seed)
      skip "pq_crypto does not expose public seed-aware keypair API yet"
    end

    seed = "s" * 32
    keypair = PQCrypto::Signature.keypair_from_seed(:ml_dsa_65, seed)
    skip "pq_crypto SecretKey does not expose #to_seed yet" unless keypair.secret_key.respond_to?(:to_seed)

    jwk = PQCrypto::JWT::JWK.from_secret_key(keypair, kid: "seed-key")

    assert_equal "AKP", jwk.fetch("kty")
    assert_equal "ML-DSA-65", jwk.fetch("alg")
    assert_equal "seed-key", jwk.fetch("kid")
    assert_equal PQCrypto::JWT::JWK.base64url(seed), jwk.fetch("priv")
  end

  def test_private_key_jwk_import_without_public_verification_trusts_metadata
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key).merge("priv" => PQCrypto::JWT::JWK.base64url("z" * 32))

    secret_key = PQCrypto::JWT::JWK.secret_key_from_jwk(jwk, verify_public: false)

    assert_instance_of PQCrypto::Signature::SecretKey, secret_key
    assert_equal :ml_dsa_65, secret_key.algorithm
  end

  def test_from_seed_preserves_export_metadata
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_seed("s" * 32, alg: "ML-DSA-65", public_key: keypair.public_key,
                                                 kid: "seed-key", use: "sig", key_ops: [:sign])

    assert_predicate jwk, :frozen?
    assert_equal "seed-key", jwk.fetch("kid")
    assert_equal "sig", jwk.fetch("use")
    assert_equal ["sign"], jwk.fetch("key_ops")
    assert_equal PQCrypto::JWT::JWK.base64url("s" * 32), jwk.fetch("priv")
  end

  def test_from_seed_rejects_public_key_of_another_algorithm
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-44")

    assert_raises(PQCrypto::JWT::KeyTypeError) do
      PQCrypto::JWT::JWK.from_seed("s" * 32, alg: "ML-DSA-65", public_key: keypair.public_key)
    end
  end

  def test_akp_thumbprint_members_exclude_private_seed
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    public_jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key)
    private_jwk = public_jwk.merge("priv" => PQCrypto::JWT::JWK.base64url("z" * 32))

    akp = JWT::JWK::AKP.new(private_jwk, nil, kid_generator: JWT::JWK::Thumbprint)

    assert_equal %i[alg kty pub], akp.members.keys
    assert_equal PQCrypto::JWT::JWK.thumbprint(public_jwk), akp.kid
  end

  def test_private_key_jwk_import_strict_public_check_rejects_mismatch_when_parent_derivation_exists
    skip "pq_crypto does not expose public seed derivation" unless seed_derivation_supported?

    seed = "z" * 32
    mismatched_keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_public_key(mismatched_keypair.public_key).merge("priv" => PQCrypto::JWT::JWK.base64url(seed))

    assert_raises(PQCrypto::JWT::Error) do
      PQCrypto::JWT::JWK.secret_key_from_jwk(jwk, verify_public: true)
    end
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

  def test_jwk_rejects_padded_public_key_and_thumbprint_input
    jwk = PQCrypto::JWT::JWK.from_public_key(PQCrypto::JWT::Keys.generate("ML-DSA-65").public_key)
    padded = jwk.merge("pub" => "#{jwk.fetch('pub')}=")

    assert_raises(PQCrypto::JWT::Error) { PQCrypto::JWT::JWK.public_key_from_jwk(padded) }
    assert_raises(PQCrypto::JWT::Error) { PQCrypto::JWT::JWK.thumbprint(padded) }
  end

  def test_jwk_rejects_standard_base64_alphabet
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key)
    standard = Base64.strict_encode64("\xff".b * keypair.public_key.to_bytes.bytesize).delete("=")

    assert_raises(PQCrypto::JWT::Error) { PQCrypto::JWT::JWK.public_key_from_jwk(jwk.merge("pub" => standard)) }
  end

  def test_jwk_rejects_non_string_base64url_member
    jwk = PQCrypto::JWT::JWK.from_public_key(PQCrypto::JWT::Keys.generate("ML-DSA-65").public_key)
    encoded = jwk.fetch("pub")
    pub = Object.new
    pub.define_singleton_method(:to_s) { encoded }

    assert_raises(PQCrypto::JWT::Error) { PQCrypto::JWT::JWK.public_key_from_jwk(jwk.merge("pub" => pub)) }
  end

  def test_jwk_rejects_padded_private_seed
    jwk = PQCrypto::JWT::JWK.from_public_key(PQCrypto::JWT::Keys.generate("ML-DSA-65").public_key)
    private_jwk = jwk.merge("priv" => "#{PQCrypto::JWT::JWK.base64url('s' * 32)}=")

    assert_raises(PQCrypto::JWT::Error) { PQCrypto::JWT::JWK.secret_key_from_jwk(private_jwk) }
    assert_raises(JWT::JWKError) { JWT::JWK::AKP.new(private_jwk) }
  end

  def test_jwk_rejects_broken_hash_protocol_with_domain_error
    broken = Object.new
    broken.define_singleton_method(:to_hash) { nil }

    assert_raises(PQCrypto::JWT::Error) { PQCrypto::JWT::JWK.public_key_from_jwk(broken) }
  end

  def test_jwk_metadata_uses_string_conversion_protocol
    kid = Object.new
    kid.define_singleton_method(:to_str) { "converted-kid" }
    kid.define_singleton_method(:to_s) { "wrong-kid" }
    jwk = PQCrypto::JWT::JWK.from_public_key(PQCrypto::JWT::Keys.generate("ML-DSA-65").public_key, kid: kid)

    assert_equal "converted-kid", jwk.fetch("kid")
    assert_predicate jwk.fetch("kid"), :frozen?
  end

  def test_akp_copies_input_key_strings
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key)
    input = jwk.transform_values(&:dup)
    akp = JWT::JWK::AKP.new(input)
    input.fetch("pub").replace(PQCrypto::JWT::JWK.base64url("x" * keypair.public_key.to_bytes.bytesize))

    assert_equal jwk.fetch("pub"), akp[:pub]
    assert_equal keypair.public_key.to_bytes, PQCrypto::JWT::JWK.public_key_from_jwk(akp.export).to_bytes
  end

  def test_akp_cryptographic_members_are_immutable_but_metadata_is_not
    akp = JWT::JWK::AKP.new(PQCrypto::JWT::JWK.from_public_key(PQCrypto::JWT::Keys.generate("ML-DSA-65").public_key))

    assert_raises(FrozenError) { akp.export.fetch(:pub).replace("changed") }
    assert_raises(FrozenError) { akp.members.fetch(:alg).replace("changed") }
    assert_raises(FrozenError) { akp[:pub].replace("changed") }
    assert_raises(FrozenError) { akp.parameters[:pub] = "changed" }
    assert_raises(ArgumentError) { akp[:pub] = "changed" }

    akp[:kid] = "rotation-key"
    assert_equal "rotation-key", akp.kid
  end
end
