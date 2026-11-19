# frozen_string_literal: true

require "timeout"
require_relative "test_helper"

class TestJWKSLookup < Minitest::Test
  def setup
    PQCrypto::JWT::JWKS.clear_validation_cache!
  end

  def test_find_by_kid_and_alg
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwks = PQCrypto::JWT::JWKS.from_keys([keypair.public_key], kids: ["kid-1"])

    jwk = PQCrypto::JWT::JWKS.find(jwks, kid: "kid-1", alg: "ML-DSA-65")

    assert_equal "kid-1", jwk.fetch("kid")
  end

  def test_find_all_applies_lookup_options
    first = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    second = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwks = PQCrypto::JWT::JWKS.from_keys([first.public_key, second.public_key], kids: %w[first second])

    matches = PQCrypto::JWT::JWKS.find_all(jwks, kid: "second", alg: "ML-DSA-65")

    assert_equal(["second"], matches.map { |jwk| jwk.fetch("kid") })
  end

  def test_find_by_thumbprint
    first = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    second = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwks = PQCrypto::JWT::JWKS.from_keys([first.public_key, second.public_key], kids: %w[first second])
    thumbprint = PQCrypto::JWT::JWK.thumbprint(jwks.fetch("keys").fetch(1))

    assert_equal "second", PQCrypto::JWT::JWKS.find(jwks, thumbprint: thumbprint).fetch("kid")
    assert_nil PQCrypto::JWT::JWKS.find(jwks, thumbprint: "unknown")
  end

  def test_from_keys_validates_kid_strategy
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")

    assert_raises(ArgumentError) { PQCrypto::JWT::JWKS.from_keys([keypair.public_key], kid_strategy: :random) }
    assert_raises(ArgumentError) do
      PQCrypto::JWT::JWKS.from_keys([keypair.public_key], kids: ["kid-1"], kid_strategy: :thumbprint)
    end
  end

  def test_from_keys_rejects_mismatched_kids_length
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")

    assert_raises(ArgumentError) do
      PQCrypto::JWT::JWKS.from_keys([keypair.public_key], kids: [])
    end
  end

  def test_from_keys_accepts_to_ary_kids
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    kids = Object.new
    kids.define_singleton_method(:to_ary) { ["kid-1"] }

    jwks = PQCrypto::JWT::JWKS.from_keys([keypair.public_key], kids: kids)

    assert_equal "kid-1", jwks.fetch("keys").fetch(0).fetch("kid")
  end

  def test_from_keys_supports_thumbprint_kid_strategy
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwks = PQCrypto::JWT::JWKS.from_keys([keypair.public_key], kid_strategy: :thumbprint)
    jwk = jwks.fetch("keys").fetch(0)

    assert_equal PQCrypto::JWT::JWK.thumbprint(jwk), jwk.fetch("kid")
  end

  def test_from_keys_supports_thumbprint_uri_kid_strategy
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwks = PQCrypto::JWT::JWKS.from_keys([keypair.public_key], kid_strategy: :thumbprint_uri)
    jwk = jwks.fetch("keys").fetch(0)

    assert_equal PQCrypto::JWT::JWK.thumbprint_uri(jwk), jwk.fetch("kid")
  end

  def test_find_ignores_structurally_invalid_keys
    valid_keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    invalid = { "kty" => "AKP", "pub" => "missing-alg" }
    valid = PQCrypto::JWT::JWK.from_public_key(valid_keypair.public_key, kid: "valid")
    jwks = { "keys" => [invalid, valid] }

    jwk = PQCrypto::JWT::JWKS.find(jwks, kid: "valid")

    assert_equal "valid", jwk.fetch("kid")
  end

  def test_find_prefilters_by_kid_before_reconstructing_public_keys
    target = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    unrelated = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwks = {
      "keys" => [
        PQCrypto::JWT::JWK.from_public_key(unrelated.public_key, kid: "unrelated"),
        PQCrypto::JWT::JWK.from_public_key(target.public_key, kid: "target")
      ]
    }
    reconstructed_kids = []
    original = PQCrypto::JWT::JWK.method(:public_key_from_jwk)

    PQCrypto::JWT::JWK.define_singleton_method(:public_key_from_jwk) do |jwk, *args, **kwargs|
      reconstructed_kids << jwk["kid"]
      original.call(jwk, *args, **kwargs)
    end

    found = PQCrypto::JWT::JWKS.find(jwks, kid: "target")

    assert_equal "target", found.fetch("kid")
    assert_equal ["target"], reconstructed_kids
  ensure
    PQCrypto::JWT::JWK.singleton_class.send(:remove_method, :public_key_from_jwk)
    PQCrypto::JWT::JWK.define_singleton_method(:public_key_from_jwk, original) if original
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

  def test_loader_fast_path_does_not_serialize_after_warm_cache
    fetch_count = 0
    loader = PQCrypto::JWT::JWKS.loader(lambda do |_options|
      fetch_count += 1
      { "keys" => [] }
    end)

    loader.call
    threads = Array.new(32) { Thread.new { loader.call } }
    threads.each(&:join)

    assert_equal 1, fetch_count
  end

  def test_loader_concurrent_cold_cache_fetches_only_once
    fetch_count = 0
    fetch_started = false
    release_gate = Queue.new

    loader = PQCrypto::JWT::JWKS.loader(lambda do |_options|
      fetch_count += 1
      fetch_started = true
    release_gate.pop
      { "keys" => [] }
    end)

    waiters = Array.new(8) { Thread.new { loader.call } }
    Timeout.timeout(2) { Thread.pass until fetch_started }
    8.times { release_gate << :go }
    waiters.each(&:join)

    assert_equal 1, fetch_count, "double-checked locking should coalesce concurrent cold fetches"
  end

  def test_validation_cache_avoids_repeated_public_key_reconstruction
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwks = PQCrypto::JWT::JWKS.from_keys([keypair.public_key], kids: ["kid-1"])
    call_count = 0
    original = PQCrypto::JWT::JWK.method(:public_key_from_jwk)

    PQCrypto::JWT::JWK.define_singleton_method(:public_key_from_jwk) do |*args, **kwargs|
      call_count += 1
      original.call(*args, **kwargs)
    end

    PQCrypto::JWT::JWKS.find(jwks, kid: "kid-1")
    first_count = call_count

    PQCrypto::JWT::JWKS.find(jwks, kid: "kid-1")
    PQCrypto::JWT::JWKS.find(jwks, kid: "kid-1")

    assert_equal first_count, call_count, "validation cache should suppress repeated public_key_from_jwk calls"
  ensure
    PQCrypto::JWT::JWK.singleton_class.send(:remove_method, :public_key_from_jwk)
    PQCrypto::JWT::JWK.define_singleton_method(:public_key_from_jwk, original) if original
  end

  def test_clear_validation_cache_forces_revalidation
    keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
    jwks = PQCrypto::JWT::JWKS.from_keys([keypair.public_key], kids: ["kid-1"])

    PQCrypto::JWT::JWKS.find(jwks, kid: "kid-1")
    PQCrypto::JWT::JWKS.clear_validation_cache!

    call_count = 0
    original = PQCrypto::JWT::JWK.method(:public_key_from_jwk)
    PQCrypto::JWT::JWK.define_singleton_method(:public_key_from_jwk) do |*args, **kwargs|
      call_count += 1
      original.call(*args, **kwargs)
    end

    PQCrypto::JWT::JWKS.find(jwks, kid: "kid-1")

    assert_operator call_count, :>=, 1, "clear_validation_cache! should force at least one reconstruction"
  ensure
    PQCrypto::JWT::JWK.singleton_class.send(:remove_method, :public_key_from_jwk)
    PQCrypto::JWT::JWK.define_singleton_method(:public_key_from_jwk, original) if original
  end

  def test_lookup_ignores_non_hash_containers
    [nil, [], "invalid", 42].each do |container|
      assert_nil PQCrypto::JWT::JWKS.find(container)
      assert_empty PQCrypto::JWT::JWKS.find_all(container)
    end
  end

  def test_lookup_skips_broken_and_padded_entries
    jwk = PQCrypto::JWT::JWK.from_public_key(PQCrypto::JWT::Keys.generate("ML-DSA-65").public_key, kid: "good")
    broken = Object.new
    broken.define_singleton_method(:to_hash) { nil }
    padded = jwk.merge("kid" => "padded", "pub" => "#{jwk.fetch('pub')}=")

    assert_equal [jwk], PQCrypto::JWT::JWKS.find_all({ "keys" => [broken, padded, jwk] })
  end
end
