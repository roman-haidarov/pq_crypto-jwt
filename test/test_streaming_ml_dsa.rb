# frozen_string_literal: true

require_relative "test_helper"

class TestStreamingMLDSA < Minitest::Test
  include PQCryptoJWTTestHelpers

  ALGORITHMS = {
    "ML-DSA-44" => PQCrypto::JWT::JWA::MLDSA44,
    "ML-DSA-65" => PQCrypto::JWT::JWA::MLDSA65,
    "ML-DSA-87" => PQCrypto::JWT::JWA::MLDSA87,
  }.freeze

  def test_streaming_round_trip_for_all_algorithms
    ALGORITHMS.each do |alg, jwa|
      keypair = PQCrypto::JWT::Keys.generate(alg)
      payload = "a" * (512 * 1024 + 17)
      token = jwa.sign_io(signing_key: keypair.secret_key, payload_io: StringIO.new(payload))

      assert jwa.verify_io!(verification_key: keypair.public_key,
                            token: token,
                            payload_io: StringIO.new(payload)), alg
    end
  end

  def test_streaming_negative_payload_flip
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    payload = "b" * (512 * 1024 + 17)
    token = PQCrypto::JWT::JWA::MLDSA65.sign_io(signing_key: keypair.secret_key, payload_io: StringIO.new(payload))

    refute PQCrypto::JWT::JWA::MLDSA65.verify_io(verification_key: keypair.public_key,
                                                 token: token,
                                                 payload_io: StringIO.new(flip_byte(payload)))
  end

  def test_streaming_sign_rejects_b64_header
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")

    assert_raises(ArgumentError) do
      PQCrypto::JWT::JWA::MLDSA65.sign_io(signing_key: keypair.secret_key,
                                          payload_io: StringIO.new("payload"),
                                          header_fields: { b64: false })
    end
  end

  def test_streaming_sign_rejects_crit_header
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")

    assert_raises(ArgumentError) do
      PQCrypto::JWT::JWA::MLDSA65.sign_io(signing_key: keypair.secret_key,
                                          payload_io: StringIO.new("payload"),
                                          header_fields: { "crit" => ["b64"] })
    end
  end

  def test_streaming_sign_rejects_non_positive_chunk_size
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")

    assert_raises(ArgumentError) do
      PQCrypto::JWT::JWA::MLDSA65.sign_io(signing_key: keypair.secret_key,
                                          payload_io: StringIO.new("payload"),
                                          chunk_size: 0)
    end
  end

  def test_streaming_verify_rejects_non_positive_chunk_size
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    token = PQCrypto::JWT::JWA::MLDSA65.sign_io(signing_key: keypair.secret_key, payload_io: StringIO.new("payload"))

    refute PQCrypto::JWT::JWA::MLDSA65.verify_io(verification_key: keypair.public_key,
                                                 token: token,
                                                 payload_io: StringIO.new("payload"),
                                                 chunk_size: 0)
  end

  def test_streaming_verify_rejects_critical_header_even_with_valid_signature
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    token = detached_token_for_header(keypair.secret_key, { "alg" => "ML-DSA-65", "crit" => ["b64"] }, "payload")

    refute PQCrypto::JWT::JWA::MLDSA65.verify_io(verification_key: keypair.public_key,
                                                 token: token,
                                                 payload_io: StringIO.new("payload"))
  end

  def test_streaming_verify_rejects_unencoded_payload_header_even_with_valid_signature
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    token = detached_token_for_header(keypair.secret_key,
                                      { "alg" => "ML-DSA-65", "b64" => false, "crit" => ["b64"] },
                                      "payload")

    refute PQCrypto::JWT::JWA::MLDSA65.verify_io(verification_key: keypair.public_key,
                                                 token: token,
                                                 payload_io: StringIO.new("payload"))
  end

  def test_streaming_rejects_non_hash_header
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    header = Base64.urlsafe_encode64(JSON.generate([]), padding: false)
    signature = Base64.urlsafe_encode64("x" * PQCrypto::Signature.details(:ml_dsa_65).fetch(:signature_bytes), padding: false)
    token = "#{header}..#{signature}"

    refute PQCrypto::JWT::JWA::MLDSA65.verify_io(verification_key: keypair.public_key,
                                                 token: token,
                                                 payload_io: StringIO.new("payload"))
  end

  def test_streaming_rejects_malformed_base64url_header
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    signature = Base64.urlsafe_encode64("x" * PQCrypto::Signature.details(:ml_dsa_65).fetch(:signature_bytes), padding: false)
    token = "not valid ***..#{signature}"

    refute PQCrypto::JWT::JWA::MLDSA65.verify_io(verification_key: keypair.public_key,
                                                 token: token,
                                                 payload_io: StringIO.new("payload"))
  end

  def test_streaming_rejects_extra_compact_segments
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    token = PQCrypto::JWT::JWA::MLDSA65.sign_io(signing_key: keypair.secret_key, payload_io: StringIO.new("payload"))

    refute PQCrypto::JWT::JWA::MLDSA65.verify_io(verification_key: keypair.public_key,
                                                 token: "#{token}.extra",
                                                 payload_io: StringIO.new("payload"))
  end

  def test_detached_signing_input_rejects_non_positive_chunk_size
    encoded_header = Base64.urlsafe_encode64(JSON.generate("alg" => "ML-DSA-65"), padding: false)

    assert_raises(ArgumentError) do
      PQCrypto::JWT::JWA::DetachedSigningInputIO.new(encoded_header, StringIO.new("payload"), chunk_size: 0)
    end
  end

  def test_detached_signing_input_read_nil_reads_to_eof
    encoded_header = Base64.urlsafe_encode64(JSON.generate("alg" => "ML-DSA-65"), padding: false)
    io = PQCrypto::JWT::JWA::DetachedSigningInputIO.new(encoded_header, StringIO.new("payload"), chunk_size: 2)
    all = io.read

    expected = "#{encoded_header}.#{Base64.urlsafe_encode64('payload', padding: false)}"
    assert_equal expected, all
    assert_nil io.read
  end

  def test_streaming_verify_strict_raises_decode_error_for_malformed_token
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")

    assert_raises(JWT::DecodeError) do
      PQCrypto::JWT::JWA::MLDSA65.verify_io(verification_key: keypair.public_key,
                                            token: "not-a-detached-jws",
                                            payload_io: StringIO.new("payload"),
                                            strict: true)
    end
  end

  def test_streaming_verify_strict_raises_verification_error_for_crypto_failure
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    payload = "payload"
    token = PQCrypto::JWT::JWA::MLDSA65.sign_io(signing_key: keypair.secret_key, payload_io: StringIO.new(payload))

    assert_raises(JWT::VerificationError) do
      PQCrypto::JWT::JWA::MLDSA65.verify_io(verification_key: keypair.public_key,
                                            token: token,
                                            payload_io: StringIO.new(flip_byte(payload)),
                                            strict: true)
    end
  end

  def test_detached_signing_input_io_compatibility_methods
    encoded_header = Base64.urlsafe_encode64(JSON.generate("alg" => "ML-DSA-65"), padding: false)
    io = PQCrypto::JWT::JWA::DetachedSigningInputIO.new(encoded_header, StringIO.new("payload"), chunk_size: 2)

    assert_same io, io.binmode
    assert io.binmode?
    assert_equal encoded_header.byteslice(0, 3), io.readpartial(3)
    io.read until io.read.nil?
    assert_raises(EOFError) { io.readpartial(1) }
    assert_nil io.close
  end

  private

  def detached_token_for_header(secret_key, header, payload)
    encoded_header = Base64.urlsafe_encode64(JSON.generate(header), padding: false)
    input = PQCrypto::JWT::JWA::DetachedSigningInputIO.new(encoded_header, StringIO.new(payload), chunk_size: 2)
    signature = secret_key.sign_io(input, chunk_size: 2, context: PQCrypto::JWT::JWA::EMPTY_CONTEXT)
    "#{encoded_header}..#{Base64.urlsafe_encode64(signature, padding: false)}"
  end
end
