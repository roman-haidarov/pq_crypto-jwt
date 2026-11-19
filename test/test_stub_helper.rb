# frozen_string_literal: true

require_relative "test_helper"

class TestStubHelper < Minitest::Test
  include PQCryptoJWTTestHelpers

  def test_restores_an_inherited_method
    implementation = Module.new { def value = :original }
    target = Object.new.extend(implementation)

    with_stub(target, :value, -> { :temporary }) { assert_equal :temporary, target.value }

    assert_equal :original, target.value
    assert_same implementation, target.method(:value).owner
  end

  def test_restores_an_own_private_singleton_method
    target = Object.new
    target.define_singleton_method(:value) { :original }
    target.singleton_class.send(:private, :value)

    with_stub(target, :value, -> { :temporary }) { assert_equal :temporary, target.value }

    assert_equal :original, target.send(:value)
    assert target.singleton_class.private_method_defined?(:value, false)
  end
end
