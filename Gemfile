# frozen_string_literal: true

source "https://rubygems.org"

gemspec

if ENV["JWT_VERSION"] && !ENV["JWT_VERSION"].empty?
  gem "jwt", ENV.fetch("JWT_VERSION")
end
