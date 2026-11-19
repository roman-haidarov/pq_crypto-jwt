# frozen_string_literal: true

require_relative "test_helper"

require "open3"
require "tempfile"

class TestJOSEInterop < Minitest::Test
  def test_node_jose_interop_for_ml_dsa_65
    unless ENV["JOSE_INTEROP"] == "1"
      skip "set JOSE_INTEROP=1 and install Node jose to run cross-implementation interop"
    end

    node_version, node_version_err, node_version_status = Open3.capture3("node", "--version")
    skip "node is unavailable: #{node_version_err}" unless node_version_status.success?
    skip "Node.js >= 24 is required for ML-DSA WebCrypto" unless node_version.match?(/\Av(?:2[4-9]|[3-9]\d)\./)

    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    public_jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key, kid: "ruby")
    token = JWT.encode({ "pay" => "load" }, keypair.secret_key, "ML-DSA-65", kid: "ruby")

    Tempfile.create(["pq-crypto-jwt-jose-interop", ".json"]) do |input|
      input.write(JSON.generate("public_jwk" => public_jwk, "token" => token))
      input.flush

      stdout, stderr, status = Open3.capture3("node", File.expand_path("jose_interop.mjs", __dir__), input.path)
      assert status.success?, stderr

      output = JSON.parse(stdout)
      node_public_key = PQCrypto::JWT::JWK.public_key_from_jwk(output.fetch("public_jwk"))
      payload, header = JWT.decode(output.fetch("token"), node_public_key, true, algorithms: ["ML-DSA-65"])

      assert_equal "load", payload.fetch("pay")
      assert_equal "ML-DSA-65", header.fetch("alg")
    end
  end
end
