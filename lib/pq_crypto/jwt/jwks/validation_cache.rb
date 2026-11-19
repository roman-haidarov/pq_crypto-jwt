# frozen_string_literal: true

module PQCrypto
  module JWT
    module JWKS
      class ValidationCache
        MISSING = Object.new.freeze

        def initialize(limit)
          @limit = limit
          @entries = {}
          @mutex = Mutex.new
        end

        def fetch(key)
          cached = mutex.synchronize { entries.fetch(key, MISSING) }
          return cached unless cached.equal?(MISSING)

          result = yield
          mutex.synchronize { store(key, result) }
          result
        end

        def clear
          mutex.synchronize { entries.clear }
        end

        private

        attr_reader :limit, :entries, :mutex

        def store(key, result)
          entries.shift if entries.size >= limit && !entries.key?(key)
          entries[key] = result
        end
      end
    end
  end
end
