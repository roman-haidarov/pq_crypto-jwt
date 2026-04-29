# frozen_string_literal: true

require "base64"
require "json"

module PQCrypto
  module JWT
    module JWA
      module MLDSAStreaming
        DEFAULT_CHUNK_SIZE = 1 << 20
        EMPTY_CONTEXT = "".b.freeze

        def streaming_supported?
          pq_crypto_algorithm == :ml_dsa_65 &&
            PQCrypto::Signature.supported.include?(:ml_dsa_65)
        end

        def sign_io(signing_key:, payload_io: nil, io: nil, header_fields: {}, chunk_size: DEFAULT_CHUNK_SIZE)
          raise PQCrypto::JWT::UnsupportedAlgorithm, "#{alg} does not support streaming JWS" unless streaming_supported?

          ensure_secret_key!(signing_key)
          source = payload_io || io
          raise ArgumentError, "payload_io must respond to #read" unless source.respond_to?(:read)

          header = stringify_keys(header_fields || {}).merge("alg" => alg)
          encoded_header = base64url(JSON.generate(header))
          signing_input = DetachedSigningInputIO.new(encoded_header, source, chunk_size: chunk_size)
          signature = signing_key.sign_io(signing_input, chunk_size: chunk_size, context: EMPTY_CONTEXT)
          "#{encoded_header}..#{base64url(signature)}"
        rescue PQCrypto::JWT::Error, ArgumentError
          raise
        rescue StandardError => e
          raise ::JWT::EncodeError, e.message
        end

        def verify_io(verification_key:, token:, payload_io:, chunk_size: DEFAULT_CHUNK_SIZE)
          raise PQCrypto::JWT::UnsupportedAlgorithm, "#{alg} does not support streaming JWS" unless streaming_supported?
          ensure_public_key!(verification_key)
          raise ArgumentError, "token must be a String" unless token.is_a?(String)
          raise ArgumentError, "payload_io must respond to #read" unless payload_io.respond_to?(:read)

          encoded_header, encoded_payload, encoded_signature = token.split(".", -1)
          return false unless encoded_header && encoded_payload == "" && encoded_signature

          header = JSON.parse(Base64.urlsafe_decode64(encoded_header))
          return false unless header["alg"] == alg

          signature = Base64.urlsafe_decode64(encoded_signature)
          signing_input = DetachedSigningInputIO.new(encoded_header, payload_io, chunk_size: chunk_size)
          verified = verification_key.verify_io(signing_input, signature, chunk_size: chunk_size, context: EMPTY_CONTEXT)
          return false unless verified

          [payload_position(payload_io), header]
        rescue JSON::ParserError, ArgumentError, PQCrypto::InvalidKeyError
          false
        end

        def verify_io!(verification_key:, token:, payload_io:, chunk_size: DEFAULT_CHUNK_SIZE)
          result = verify_io(verification_key: verification_key, token: token, payload_io: payload_io, chunk_size: chunk_size)
          raise ::JWT::VerificationError, "Streaming JWS verification failed" unless result

          true
        end

        private

        def base64url(bytes)
          Base64.urlsafe_encode64(String(bytes).b, padding: false)
        end

        def stringify_keys(hash)
          hash.each_with_object({}) { |(key, value), out| out[String(key)] = value }
        end

        def payload_position(payload_io)
          payload_io.respond_to?(:pos) ? payload_io.pos : nil
        end
      end

      class DetachedSigningInputIO
        def initialize(encoded_header, payload_io, chunk_size: MLDSAStreaming::DEFAULT_CHUNK_SIZE)
          @prefix = "#{encoded_header}.".b
          @payload_io = payload_io
          @chunk_size = chunk_size
          @buffer = +""
          @carry = +""
          @prefix_done = false
          @payload_done = false
        end

        def read(length = nil, outbuf = nil)
          length ||= @chunk_size
          fill(length)
          return nil if @buffer.empty?

          result = @buffer.byteslice(0, length)
          @buffer = @buffer.byteslice(result.bytesize..-1) || +""
          outbuf&.replace(result)
          outbuf || result
        end

        private

        def fill(length)
          @buffer << @prefix unless consume_prefix?
          while @buffer.bytesize < length && !@payload_done
            chunk = @payload_io.read(@chunk_size)
            if chunk.nil? || chunk.empty?
              @buffer << Base64.urlsafe_encode64(@carry, padding: false) unless @carry.empty?
              @carry = +""
              @payload_done = true
              break
            end

            bytes = @carry + chunk.b
            full_length = bytes.bytesize - (bytes.bytesize % 3)
            if full_length.positive?
              @buffer << Base64.urlsafe_encode64(bytes.byteslice(0, full_length), padding: false)
              @carry = bytes.byteslice(full_length..-1) || +""
            else
              @carry = bytes
            end
          end
        end

        def consume_prefix?
          return true if @prefix_done

          @prefix_done = true
          false
        end
      end
    end
  end
end
