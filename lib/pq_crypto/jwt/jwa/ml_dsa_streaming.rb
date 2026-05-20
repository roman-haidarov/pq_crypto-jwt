# frozen_string_literal: true

require "base64"
require "json"

module PQCrypto
  module JWT
    module JWA
      module MLDSAStreaming
        DEFAULT_CHUNK_SIZE = 1 << 20
        STREAMING_ERRORS = [JSON::ParserError, ArgumentError, PQCrypto::Error, PQCrypto::JWT::Error, EncodingError].freeze

        SignIORequest = Data.define(:signing_key, :source, :header_fields, :chunk_size)
        VerifyIORequest = Data.define(:verification_key, :token, :payload_io, :chunk_size)
        DetachedToken = Data.define(:encoded_header, :encoded_signature, :header, :signature)

        def streaming_supported?
          PQCrypto::Signature.supported.include?(pq_crypto_algorithm)
        rescue PQCrypto::Error
          false
        end

        def sign_io(signing_key:, payload_io: nil, io: nil, header_fields: {}, chunk_size: DEFAULT_CHUNK_SIZE)
          ensure_streaming_supported!
          request = SignIORequest.new(
            signing_key: signing_key,
            source: payload_io || io,
            header_fields: header_fields || {},
            chunk_size: chunk_size
          )
          ensure_secret_key!(request.signing_key)
          ensure_readable!(request.source, "payload_io")

          encoded_header = encoded_header_for(request.header_fields)
          signing_input = DetachedSigningInputIO.new(encoded_header, request.source, chunk_size: request.chunk_size)
          signature = request.signing_key.sign_io(signing_input, chunk_size: request.chunk_size, context: EMPTY_CONTEXT)
          "#{encoded_header}..#{base64url(signature)}"
        rescue PQCrypto::JWT::Error, ArgumentError
          raise
        rescue PQCrypto::Error, TypeError, EncodingError => e
          raise ::JWT::EncodeError, e.message
        end

        def verify_io(verification_key:, token:, payload_io:, chunk_size: DEFAULT_CHUNK_SIZE)
          ensure_streaming_supported!
          request = VerifyIORequest.new(
            verification_key: verification_key,
            token: token,
            payload_io: payload_io,
            chunk_size: chunk_size
          )
          ensure_public_key!(request.verification_key)
          raise ArgumentError, "token must be a String" unless request.token.is_a?(String)
          ensure_readable!(request.payload_io, "payload_io")

          detached = parse_detached_token(request.token)
          return false unless detached
          return false unless detached.header["alg"] == alg
          return false unless signature_length_valid?(detached.signature)

          signing_input = DetachedSigningInputIO.new(detached.encoded_header, request.payload_io, chunk_size: request.chunk_size)
          verified = request.verification_key.verify_io(
            signing_input,
            detached.signature,
            chunk_size: request.chunk_size,
            context: EMPTY_CONTEXT
          )
          verified ? [payload_position(request.payload_io), detached.header] : false
        rescue *STREAMING_ERRORS
          false
        end

        def verify_io!(verification_key:, token:, payload_io:, chunk_size: DEFAULT_CHUNK_SIZE)
          verified = verify_io(
            verification_key: verification_key,
            token: token,
            payload_io: payload_io,
            chunk_size: chunk_size
          )
          raise ::JWT::VerificationError, "Streaming JWS verification failed" unless verified

          true
        end

        private

        def ensure_streaming_supported!
          raise PQCrypto::JWT::UnsupportedFeature, "#{alg} does not support streaming JWS" unless streaming_supported?
        end

        def ensure_readable!(object, name)
          raise ArgumentError, "#{name} must respond to #read" unless object.respond_to?(:read)
        end

        def encoded_header_for(header_fields)
          base64url(JSON.generate(stringify_keys(header_fields).merge("alg" => alg)))
        end

        def parse_detached_token(token)
          encoded_header, encoded_payload, encoded_signature = token.split(".", -1)
          return nil unless token.count(".") == 2
          return nil unless encoded_payload == ""

          header = JSON.parse(base64url_decode(encoded_header))
          return nil unless header.is_a?(Hash)

          DetachedToken.new(
            encoded_header: encoded_header,
            encoded_signature: encoded_signature,
            header: header,
            signature: base64url_decode(encoded_signature)
          )
        end

        def base64url(bytes)
          Base64.urlsafe_encode64(String(bytes).b, padding: false)
        end

        def base64url_decode(raw)
          value = String(raw)
          padding = (4 - value.bytesize % 4) % 4
          Base64.urlsafe_decode64(value + ("=" * padding))
        end

        def stringify_keys(hash)
          hash.each_with_object({}) { |(key, value), out| out[String(key)] = value }
        end

        def payload_position(payload_io)
          payload_io.respond_to?(:pos) ? payload_io.pos : nil
        end
      end

      class DetachedSigningInputIO
        ReadRequest = Data.define(:length, :outbuf)

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
          request = ReadRequest.new(length: length, outbuf: outbuf)
          result = request.length.nil? ? read_to_eof : read_slice(request.length)
          return nil if result.nil?

          replace_outbuf(request.outbuf, result)
        end

        private

        def read_to_eof
          fill_until_eof
          drain_buffer
        end

        def read_slice(length)
          raise ArgumentError, "negative length #{length} given" if length.negative?
          return +"" if length.zero?

          fill(length)
          return nil if @buffer.empty?

          @buffer.byteslice(0, length).tap { |chunk| @buffer = @buffer.byteslice(chunk.bytesize..-1) || +"" }
        end

        def drain_buffer
          return nil if @buffer.empty?

          @buffer.tap { @buffer = +"" }
        end

        def replace_outbuf(outbuf, result)
          outbuf&.replace(result)
          outbuf || result
        end

        def fill_until_eof
          fill(@chunk_size) until @payload_done
        end

        def fill(length)
          @buffer << @prefix unless consume_prefix?
          read_payload_chunks(length)
        end

        def read_payload_chunks(length)
          while @buffer.bytesize < length && !@payload_done
            chunk = @payload_io.read(@chunk_size)
            chunk.nil? || chunk.empty? ? finish_payload! : append_payload_chunk(chunk)
          end
        end

        def append_payload_chunk(chunk)
          bytes = @carry + chunk.b
          full_length = bytes.bytesize - (bytes.bytesize % 3)
          return @carry = bytes unless full_length.positive?

          @buffer << Base64.urlsafe_encode64(bytes.byteslice(0, full_length), padding: false)
          @carry = bytes.byteslice(full_length..-1) || +""
        end

        def finish_payload!
          @buffer << Base64.urlsafe_encode64(@carry, padding: false) unless @carry.empty?
          @carry = +""
          @payload_done = true
        end

        def consume_prefix?
          @prefix_done.tap { @prefix_done = true }
        end
      end
    end
  end
end
