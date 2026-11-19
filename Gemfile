# frozen_string_literal: true

source "https://rubygems.org"

gemspec

jwt_version = ENV.fetch("JWT_VERSION", "")
gem "jwt", jwt_version unless jwt_version.empty?
