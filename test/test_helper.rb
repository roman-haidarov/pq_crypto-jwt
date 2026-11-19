# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "base64"
require "json"
require "minitest/autorun"
require "openssl"
require "securerandom"
require "stringio"
require "pq_crypto/jwt"

PQCrypto::JWT.register!

module PQCryptoJWTTestHelpers
  def seed_derivation_supported?
    PQCrypto::Signature.respond_to?(:public_key_from_seed) || PQCrypto::Signature.respond_to?(:keypair_from_seed)
  end

  def decode_header(token)
    JSON.parse(Base64.urlsafe_decode64(token.split(".").fetch(0)))
  end

  def tamper_signature(token)
    header, payload, signature = token.split(".", 3)
    raw_signature = Base64.urlsafe_decode64(signature)
    tampered = raw_signature.dup
    tampered.setbyte(0, tampered.getbyte(0) ^ 0x01)
    [header, payload, Base64.urlsafe_encode64(tampered, padding: false)].join(".")
  end

  def flip_byte(bytes)
    changed = bytes.dup
    changed.setbyte(0, changed.getbyte(0) ^ 0x01)
    changed
  end

  def with_stub(target, method_name, replacement)
    singleton = target.singleton_class
    visibility = %i[public protected private].find do |level|
      singleton.public_send(:"#{level}_method_defined?", method_name, false)
    end
    original = singleton.instance_method(method_name) if visibility

    target.define_singleton_method(method_name, replacement)
    yield
  ensure
    singleton.send(:remove_method, method_name) if singleton.method_defined?(method_name, false)
    if original
      singleton.send(:define_method, method_name, original)
      singleton.send(visibility, method_name)
    end
  end
end
