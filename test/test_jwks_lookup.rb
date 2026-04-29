# frozen_string_literal: true

require_relative "test_helper"

class TestJWKSLookup < Minitest::Test
  def test_find_by_kid_and_alg
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwks = PQCrypto::JWT::JWKS.from_keys([keypair.public_key], kids: ["kid-1"])

    jwk = PQCrypto::JWT::JWKS.find(jwks, kid: "kid-1", alg: "ML-DSA-65")

    assert_equal "kid-1", jwk.fetch("kid")
  end

  def test_loader_refreshes_on_invalidate
    calls = 0
    loader = PQCrypto::JWT::JWKS.loader(lambda do |_options|
      calls += 1
      { "keys" => [] }
    end)

    loader.call
    loader.call
    loader.call(invalidate: true)

    assert_equal 2, calls
  end

  def test_jwks_decode_with_akp_adapter
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwks = PQCrypto::JWT::JWKS.from_keys([keypair.public_key], kids: ["kid-1"])
    token = JWT.encode({ "pay" => "load" }, keypair.secret_key, "ML-DSA-65", kid: "kid-1")

    payload, header = JWT.decode(token, nil, true, algorithms: ["ML-DSA-65"], jwks: jwks)

    assert_equal "load", payload.fetch("pay")
    assert_equal "ML-DSA-65", header.fetch("alg")
  end
end
