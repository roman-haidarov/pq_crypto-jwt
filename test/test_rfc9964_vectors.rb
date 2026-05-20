# frozen_string_literal: true

require_relative "test_helper"

class TestRFC9964Vectors < Minitest::Test
  EXPECTED_SIZES = {
    "ML-DSA-44" => { public_key_bytes: 1_312, signature_bytes: 2_420 },
    "ML-DSA-65" => { public_key_bytes: 1_952, signature_bytes: 3_309 },
    "ML-DSA-87" => { public_key_bytes: 2_592, signature_bytes: 4_627 },
  }.freeze

  JWA_BY_ALG = {
    "ML-DSA-44" => PQCrypto::JWT::JWA::MLDSA44,
    "ML-DSA-65" => PQCrypto::JWT::JWA::MLDSA65,
    "ML-DSA-87" => PQCrypto::JWT::JWA::MLDSA87,
  }.freeze

  def test_rfc9964_public_key_and_signature_sizes
    EXPECTED_SIZES.each do |alg, sizes|
      keypair = PQCrypto::JWT::Keys.generate(alg)
      signature = JWA_BY_ALG.fetch(alg).sign(data: "payload", signing_key: keypair.secret_key)

      assert_equal sizes.fetch(:public_key_bytes), keypair.public_key.to_bytes.bytesize, alg
      assert_equal sizes.fetch(:signature_bytes), signature.bytesize, alg
      assert_equal sizes.fetch(:public_key_bytes), PQCrypto::Signature.details(keypair.public_key.algorithm).fetch(:public_key_bytes), alg
      assert_equal sizes.fetch(:signature_bytes), PQCrypto::Signature.details(keypair.public_key.algorithm).fetch(:signature_bytes), alg
    end
  end

  def test_rfc9964_akp_thumbprint_canonical_member_vector
    jwk = {
      "kty" => "AKP",
      "alg" => "ML-DSA-65",
      "pub" => Base64.urlsafe_encode64("a" * EXPECTED_SIZES.fetch("ML-DSA-65").fetch(:public_key_bytes), padding: false),
      "kid" => "ignored",
      "use" => "sig",
    }

    assert_equal "xRachD-oTrh4aM1HInZiM7NYQPFLDcQX7EiJYS2BtUM", PQCrypto::JWT::JWK.thumbprint(jwk)
  end
end
