# frozen_string_literal: true

module PQCrypto
  module JWT
    module JWKS
      class Loader
        def initialize(source)
          @fetch = source.respond_to?(:call) ? source : proc { source }
          @cached = CACHE_EMPTY
          @mutex = Mutex.new
        end

        def call(options = {})
          options ||= {}
          invalidate = options[:invalidate]
          current = cached
          return current unless invalidate || current.equal?(CACHE_EMPTY)

          mutex.synchronize { refresh(options, invalidate) }
        end

        private

        attr_reader :fetch, :mutex
        attr_accessor :cached

        def refresh(options, invalidate)
          self.cached = CACHE_EMPTY if invalidate
          self.cached = fetch.call(options) if cached.equal?(CACHE_EMPTY)
          cached
        end
      end
    end
  end
end
