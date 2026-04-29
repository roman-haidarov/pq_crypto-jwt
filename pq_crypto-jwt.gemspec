# frozen_string_literal: true

require_relative "lib/pq_crypto/jwt/version"

Gem::Specification.new do |spec|
  spec.name          = "pq_crypto-jwt"
  spec.version       = PQCrypto::JWT::VERSION
  spec.authors       = ["Roman Haydarov"]
  spec.email         = ["romanhajdarov@gmail.com"]
  spec.summary       = "ML-DSA JWS algorithms for ruby-jwt backed by pq_crypto"
  spec.description   = "Ruby-only adapter that adds post-quantum ML-DSA JWS signing and AKP JWK/JWKS helpers to ruby-jwt, backed by pq_crypto."
  spec.homepage      = "https://github.com/roman-haidarov/pq_crypto-jwt"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 3.4.0"

  spec.files = Dir["lib/**/*.rb", "README.md", "CHANGELOG.md", "LICENSE.txt"]
  spec.require_paths = ["lib"]
  spec.extensions    = []

  spec.add_dependency "pq_crypto", "~> 0.4"
  spec.add_dependency "jwt", ">= 3.1", "< 4.0"

  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "minitest", "~> 5.0"
end
