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
    had_own = singleton.method_defined?(method_name) || singleton.private_method_defined?(method_name)
    original = had_own ? target.method(method_name) : nil

    target.define_singleton_method(method_name, replacement)
    yield
  ensure
    singleton.send(:remove_method, method_name) if singleton.method_defined?(method_name) || singleton.private_method_defined?(method_name)
    target.define_singleton_method(method_name, original) if original
  end
end
