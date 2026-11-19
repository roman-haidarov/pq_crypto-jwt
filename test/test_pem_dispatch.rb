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

  def test_der_auto_and_explicit_dispatch
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    public_der = keypair.public_key.to_spki_der
    secret_der = keypair.secret_key.to_pkcs8_der

    %i[auto signature].each do |expect|
      public_key = PQCrypto::JWT::Keys.public_from_der(public_der, expect: expect)
      secret_key = PQCrypto::JWT::Keys.secret_from_der(secret_der, expect: expect)

      assert_equal keypair.public_key.to_bytes, public_key.to_bytes
      assert_instance_of PQCrypto::Signature::SecretKey, secret_key
    end
  end

  def test_public_import_rejects_secret_key
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")

    assert_raises(PQCrypto::JWT::KeyTypeError) do
      PQCrypto::JWT::Keys.public_from_pem(keypair.secret_key.to_pkcs8_pem)
    end
  end

  def test_unsupported_expect_value_raises
    assert_raises(ArgumentError) { PQCrypto::JWT::Keys.public_from_pem("", expect: :kem) }
  end

  def test_unknown_pem_raises
    rsa = OpenSSL::PKey::RSA.generate(2048)

    assert_raises(PQCrypto::JWT::Error) { PQCrypto::JWT::Keys.public_from_pem(rsa.public_key.to_pem) }
  end
end
