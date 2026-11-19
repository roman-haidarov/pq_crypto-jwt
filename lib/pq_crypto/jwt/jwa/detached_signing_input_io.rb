# frozen_string_literal: true

require "base64"

module PQCrypto
  module JWT
    module JWA
      class DetachedSigningInputIO
        def initialize(encoded_header, payload_io, chunk_size: Streaming::DEFAULT_CHUNK_SIZE)
          @chunk_size = Streaming.validate_chunk_size!(chunk_size)
          @payload_io = payload_io
          @buffer = "#{encoded_header}.".b
          @carry = "".b
          @eof = false
        end

        def read(length = nil, outbuf = nil)
          raise ArgumentError, "negative length #{length} given" if length&.negative?
          return emit(+"", outbuf) if length&.zero?

          fill(length)
          emit(take(length || buffer.bytesize), outbuf) unless buffer.empty?
        end

        def readpartial(maxlen, outbuf = nil)
          result = read(maxlen, outbuf)
          raise EOFError if result.nil? || result.empty?

          result
        end

        def binmode = self
        def binmode? = true
        def close = nil

        private

        attr_reader :chunk_size, :payload_io
        attr_accessor :buffer, :carry, :eof

        def emit(result, outbuf) = outbuf ? outbuf.replace(result) : result

        def take(length)
          head = buffer.byteslice(0, length)
          self.buffer = buffer.byteslice(head.bytesize..)
          head
        end

        def fill(length)
          feed until eof || (length && buffer.bytesize >= length)
        end

        def feed
          chunk = payload_io.read(chunk_size)
          if chunk.nil? || chunk.empty?
            buffer << encode(carry)
            self.eof = true
          else
            bytes = carry + chunk.b
            size = bytes.bytesize
            aligned = size - (size % 3)
            buffer << encode(bytes.byteslice(0, aligned))
            self.carry = bytes.byteslice(aligned..)
          end
        end

        def encode(bytes) = Base64.urlsafe_encode64(bytes, padding: false)
      end
    end
  end
end
