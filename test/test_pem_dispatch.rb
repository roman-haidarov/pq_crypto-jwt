# frozen_string_literal: true

require_relative "test_helper"

class TestPEMDispatch < Minitest::Test
  def test_signature_spki_auto_dispatch
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    imported = PQCrypto::JWT::Keys.public_from_pem(keypair.public_key.to_spki_pem)

    assert_instance_of PQCrypto::Signature::PublicKey, imported
    assert_equal keypair.public_key.to_bytes, imported.to_bytes
  end

  def test_signature_spki_explicit_dispatch
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    imported = PQCrypto::JWT::Keys.public_from_pem(keypair.public_key.to_spki_pem, expect: :signature)

    assert_instance_of PQCrypto::Signature::PublicKey, imported
    assert_equal keypair.public_key.to_bytes, imported.to_bytes
  end

  def test_secret_pkcs8_auto_dispatch
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    imported = PQCrypto::JWT::Keys.secret_from_pem(keypair.secret_key.to_pkcs8_pem)

    assert_instance_of PQCrypto::Signature::SecretKey, imported
  end

  def test_unsupported_expect_value_raises
    assert_raises(ArgumentError) { PQCrypto::JWT::Keys.public_from_pem("", expect: :kem) }
  end

  def test_unknown_pem_raises
    rsa = OpenSSL::PKey::RSA.generate(2048)

    assert_raises(PQCrypto::JWT::Error) { PQCrypto::JWT::Keys.public_from_pem(rsa.public_key.to_pem) }
  end
end
