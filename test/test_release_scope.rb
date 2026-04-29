# frozen_string_literal: true

require_relative "test_helper"

class TestReleaseScope < Minitest::Test
  def test_first_release_does_not_expose_jwe_namespace_by_default
    refute PQCrypto::JWT::JWA.const_defined?(:JWE, false)
  end

  def test_first_release_rejects_ml_kem_key_generation
    assert_raises(ArgumentError) { PQCrypto::JWT::Keys.generate("ML-KEM-768") }
  end
end
