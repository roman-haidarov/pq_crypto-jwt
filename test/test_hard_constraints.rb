# frozen_string_literal: true

require_relative "test_helper"

class TestHardConstraints < Minitest::Test
  FORBIDDEN_LIB_PATTERNS = [
    /__send__/,
    /_native_/,
    /__test_/,
    /Testing::/,
    /pqc_container_/,
    /instance_variable_get/,
    /instance_variable_defined/
  ].freeze

  def test_no_native_extension_layout
    root = File.expand_path("..", __dir__)

    refute Dir.exist?(File.join(root, "ext"))
    refute Dir.exist?(File.join(root, "bin"))
    refute Dir.exist?(File.join(root, "spec"))
  end

  def test_gemspec_extensions_are_empty
    gemspec = File.read(File.expand_path("../pq_crypto-jwt.gemspec", __dir__))

    assert_match(/spec\.extensions\s*=\s*\[\]/, gemspec)
  end


  def test_runtime_ruby_floor_is_31
    gemspec = File.read(File.expand_path("../pq_crypto-jwt.gemspec", __dir__))

    assert_match(/spec\.required_ruby_version\s*=\s*">= 3\.1\.0"/, gemspec)
  end

  def test_runtime_dependencies_track_current_parent_line
    gemspec = File.read(File.expand_path("../pq_crypto-jwt.gemspec", __dir__))

    assert_match(/spec\.add_dependency\s+"pq_crypto",\s+"~> 0\.6\.1"/, gemspec)
    assert_match(/spec\.add_dependency\s+"jwt",\s+">= 3\.1",\s+"< 4\.0"/, gemspec)
  end

  def test_akp_auto_dispatch_does_not_claim_private_key_export
    refute_includes JWT::JWK::AKP::KTYS, PQCrypto::Signature::SecretKey
    refute_includes JWT::JWK::AKP::KTYS, PQCrypto::Signature::Keypair
  end

  def test_lib_avoids_private_pq_crypto_api
    lib_files = Dir[File.expand_path("../lib/**/*.rb", __dir__)]

    lib_files.each do |file|
      body = File.read(file)
      FORBIDDEN_LIB_PATTERNS.each do |pattern|
        refute_match pattern, body, "#{file} references #{pattern.inspect}"
      end
    end
  end
end
