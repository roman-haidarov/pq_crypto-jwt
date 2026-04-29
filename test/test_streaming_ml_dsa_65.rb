# frozen_string_literal: true

require_relative "test_helper"

class TestStreamingMLDSA65 < Minitest::Test
  include PQCryptoJWTTestHelpers

  def test_streaming_round_trip
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    payload = "a" * (4 * 1024 * 1024 + 17)
    token = PQCrypto::JWT::JWA::MLDSA65.sign_io(signing_key: keypair.secret_key, payload_io: StringIO.new(payload))

    assert PQCrypto::JWT::JWA::MLDSA65.verify_io!(verification_key: keypair.public_key,
                                                  token: token,
                                                  payload_io: StringIO.new(payload))
  end

  def test_streaming_negative_payload_flip
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    payload = "b" * (4 * 1024 * 1024 + 17)
    token = PQCrypto::JWT::JWA::MLDSA65.sign_io(signing_key: keypair.secret_key, payload_io: StringIO.new(payload))

    refute PQCrypto::JWT::JWA::MLDSA65.verify_io(verification_key: keypair.public_key,
                                                 token: token,
                                                 payload_io: StringIO.new(flip_byte(payload)))
  end

  def test_streaming_non_65_raises
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-44")

    assert_raises(PQCrypto::JWT::UnsupportedAlgorithm) do
      PQCrypto::JWT::JWA::MLDSA44.sign_io(signing_key: keypair.secret_key, payload_io: StringIO.new("payload"))
    end
  end
end
