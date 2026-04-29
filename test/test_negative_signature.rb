# frozen_string_literal: true

require_relative "test_helper"

class TestNegativeSignature < Minitest::Test
  include PQCryptoJWTTestHelpers

  def test_tampered_signature_raises_verification_error
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    token = JWT.encode({ "foo" => "bar" }, keypair.secret_key, "ML-DSA-65")
    tampered = tamper_signature(token)

    assert_raises(JWT::VerificationError) do
      JWT.decode(tampered, keypair.public_key, true, algorithm: "ML-DSA-65")
    end
  end
end
