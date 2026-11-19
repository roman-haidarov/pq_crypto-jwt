# frozen_string_literal: true

require_relative "test_helper"
require "open3"

class TestReleaseScope < Minitest::Test
  def test_first_release_does_not_expose_jwe_namespace_by_default
    refute PQCrypto::JWT::JWA.const_defined?(:JWE, false)
  end

  def test_first_release_rejects_ml_kem_key_generation
    assert_raises(ArgumentError) { PQCrypto::JWT::Keys.generate("ML-KEM-768") }
  end

  def test_legacy_algorithm_require_paths_load_the_gem_on_their_own
    lib = File.expand_path("../lib", __dir__)

    %w[ml_dsa_44 ml_dsa_65 ml_dsa_87 ml_dsa_streaming].each do |name|
      script = "PQCrypto::JWT.register! && PQCrypto::JWT::JWA::MLDSAStreaming::DEFAULT_CHUNK_SIZE"
      _stdout, stderr, status = Open3.capture3(Gem.ruby, "-I", lib, "-r", "pq_crypto/jwt/jwa/#{name}", "-e", script)

      assert status.success?, stderr
    end
  end
end
