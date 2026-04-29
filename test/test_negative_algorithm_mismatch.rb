# frozen_string_literal: true

require_relative "test_helper"

class TestNegativeAlgorithmMismatch < Minitest::Test
  def test_algorithm_mismatch_raises
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-44")
    token = JWT.encode({ "foo" => "bar" }, keypair.secret_key, "ML-DSA-44")

    assert_raises(JWT::DecodeError) do
      JWT.decode(token, keypair.public_key, true, algorithm: PQCrypto::JWT::MLDSA65)
    end
  end

  def test_wrong_key_type_on_sign_raises_key_type_error
    rsa_key = OpenSSL::PKey::RSA.generate(2048)

    assert_raises(PQCrypto::JWT::KeyTypeError) do
      PQCrypto::JWT::MLDSA65.sign(data: "payload", signing_key: rsa_key)
    end
  end
end
