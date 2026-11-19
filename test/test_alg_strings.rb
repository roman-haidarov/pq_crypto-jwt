# frozen_string_literal: true

require_relative "test_helper"

class TestAlgStrings < Minitest::Test
  include PQCryptoJWTTestHelpers

  JWS_ALGS = %w[ML-DSA-44 ML-DSA-65 ML-DSA-87].freeze

  def test_algorithms_are_exact_and_case_sensitive
    assert_equal JWS_ALGS, PQCrypto::JWT.algorithms.map(&:alg)
    PQCrypto::JWT.algorithms.each { |algorithm| refute algorithm.valid_alg?(algorithm.alg.downcase) }
  end

  def test_public_algorithm_lists
    assert_equal JWS_ALGS, PQCrypto::JWT.signing_algorithms.map(&:alg)
    assert_empty PQCrypto::JWT.kem_algorithms
    assert_same PQCrypto::JWT::JWA::MLDSA65, PQCrypto::JWT.algorithm_for("ML-DSA-65")
    assert_nil PQCrypto::JWT.algorithm_for("ML-KEM-768")
  end

  def test_encoded_headers_use_exact_alg_strings
    JWS_ALGS.each do |alg|
      keypair = PQCrypto::JWT::Keys.generate(alg)
      token = JWT.encode({ "foo" => "bar" }, keypair.secret_key, alg)
      assert_equal alg, decode_header(token).fetch("alg")
    end
  end

  def test_algorithms_are_frozen_ruby_jwt_signing_algorithms
    PQCrypto::JWT.algorithms.each do |algorithm|
      assert_kind_of JWT::JWA::SigningAlgorithm, algorithm
      assert_predicate algorithm, :frozen?
      assert_equal :signature, algorithm.key_kind
    end
  end

  def test_register_is_idempotent
    assert PQCrypto::JWT.register!
    assert PQCrypto::JWT.register!
    assert_predicate PQCrypto::JWT, :registered?
    assert_equal 1, JWT::JWK.classes.count(JWT::JWK::AKP)
  end
end
