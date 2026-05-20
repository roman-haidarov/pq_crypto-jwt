# frozen_string_literal: true

require "base64"
require "json"

module PQCrypto
  module JWT
    module JWA
      module MLDSAStreaming
        DEFAULT_CHUNK_SIZE = 1 << 20
        STREAMING_DECODE_ERRORS = [JSON::ParserError, ArgumentError, TypeError, EncodingError].freeze
        STREAMING_VERIFY_ERRORS = [PQCrypto::Error, PQCrypto::JWT::Error].freeze

        def streaming_supported?
          PQCrypto::Signature.supported.include?(pq_crypto_algorithm)
        rescue PQCrypto::Error
          false
        end

        def sign_io(signing_key:, payload_io: nil, io: nil, header_fields: {}, chunk_size: DEFAULT_CHUNK_SIZE)
          ensure_streaming!
          ensure_key!(signing_key, PQCrypto::Signature::SecretKey, "signing")
          validate_chunk_size!(chunk_size)
          source = payload_io || io
          raise ArgumentError, "payload_io must respond to #read" unless source.respond_to?(:read)

          header = normalize_signing_header!(header_fields).merge("alg" => alg)
          encoded_header = base64url(JSON.generate(header))
          input = DetachedSigningInputIO.new(encoded_header, source, chunk_size: chunk_size)
          signature = signing_key.sign_io(input, chunk_size: chunk_size, context: EMPTY_CONTEXT)
          "#{encoded_header}..#{base64url(signature)}"
        rescue PQCrypto::JWT::Error, ArgumentError
          raise
        rescue StandardError => e
          raise ::JWT::EncodeError, e.message
        end

        def verify_io(verification_key:, token:, payload_io:, chunk_size: DEFAULT_CHUNK_SIZE, strict: false)
          ensure_streaming!
          ensure_key!(verification_key, PQCrypto::Signature::PublicKey, "verification")
          validate_chunk_size!(chunk_size)
          return streaming_decode_failure!(strict, "token must be a String") unless token.is_a?(String)
          return streaming_decode_failure!(strict, "payload_io must respond to #read") unless payload_io.respond_to?(:read)

          encoded_header, encoded_payload, encoded_signature, extra = token.split(".", -1)
          unless extra.nil? && encoded_payload == "" && encoded_signature
            return streaming_decode_failure!(strict, "compact detached JWS must have exactly three segments and an empty payload segment")
          end

          header = JSON.parse(Base64.urlsafe_decode64(encoded_header))
          return streaming_decode_failure!(strict, "unsupported streaming JWS protected header") unless supported_streaming_header?(header)

          signature = Base64.urlsafe_decode64(encoded_signature)
          return streaming_verify_failure!(strict, "invalid #{alg} signature length") unless signature_length_valid?(signature)

          input = DetachedSigningInputIO.new(encoded_header, payload_io, chunk_size: chunk_size)
          return streaming_verify_failure!(strict, "Streaming JWS verification failed") unless verification_key.verify_io(input, signature, chunk_size: chunk_size, context: EMPTY_CONTEXT)

          [payload_io.respond_to?(:pos) ? payload_io.pos : nil, header]
        rescue *STREAMING_DECODE_ERRORS => e
          streaming_decode_failure!(strict, e.message)
        rescue *STREAMING_VERIFY_ERRORS => e
          streaming_verify_failure!(strict, e.message)
        end

        def verify_io!(**kwargs)
          verify_io(**kwargs) || raise(::JWT::VerificationError, "Streaming JWS verification failed")
          true
        end

        private

        def ensure_streaming!
          return if streaming_supported?

          raise PQCrypto::JWT::UnsupportedFeature, "#{alg} does not support streaming JWS"
        end

        def base64url(bytes)
          Base64.urlsafe_encode64(String(bytes).b, padding: false)
        end

        def normalize_signing_header!(header_fields)
          unless header_fields.respond_to?(:to_hash)
            raise ArgumentError, "header_fields must be a Hash-like object"
          end

          header = header_fields.to_hash.each_with_object({}) { |(key, value), out| out[String(key)] = value }
          unsupported = %w[b64 crit] & header.keys
          unless unsupported.empty?
            raise ArgumentError, "unsupported protected header#{unsupported.size == 1 ? '' : 's'}: #{unsupported.join(', ')}"
          end

          header
        end

        def supported_streaming_header?(header)
          return false unless header.is_a?(Hash) && header["alg"] == alg
          return false if header.key?("crit")
          return false if header.key?("b64") && header["b64"] != true

          true
        end

        def validate_chunk_size!(chunk_size)
          return if chunk_size.is_a?(Integer) && chunk_size.positive?

          raise ArgumentError, "chunk_size must be a positive Integer"
        end

        def streaming_decode_failure!(strict, message)
          raise ::JWT::DecodeError, message if strict

          false
        end

        def streaming_verify_failure!(strict, message)
          raise ::JWT::VerificationError, message if strict

          false
        end
      end

      class DetachedSigningInputIO
        def initialize(encoded_header, payload_io, chunk_size: MLDSAStreaming::DEFAULT_CHUNK_SIZE)
          unless chunk_size.is_a?(Integer) && chunk_size.positive?
            raise ArgumentError, "chunk_size must be a positive Integer"
          end

          @prefix = "#{encoded_header}.".b
          @payload_io = payload_io
          @chunk_size = chunk_size
          @buffer = +""
          @carry = +""
          @prefix_done = false
          @payload_done = false
        end

        def read(length = nil, outbuf = nil)
          if length.nil?
            drain_until_eof
            return nil if @buffer.empty?

            result = @buffer
            @buffer = +""
          else
            raise ArgumentError, "negative length #{length} given" if length.negative?
            return replace_outbuf(outbuf, +"") if length.zero?

            fill(length)
            return nil if @buffer.empty?

            result = @buffer.byteslice(0, length)
            @buffer = @buffer.byteslice(result.bytesize..-1) || +""
          end

          replace_outbuf(outbuf, result)
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

        def replace_outbuf(outbuf, result)
          outbuf&.replace(result)
          outbuf || result
        end

        def drain_until_eof
          consume_prefix
          feed_one_chunk until @payload_done
        end

        def fill(length)
          consume_prefix
          feed_one_chunk while @buffer.bytesize < length && !@payload_done
        end

        def consume_prefix
          return if @prefix_done

          @buffer << @prefix
          @prefix_done = true
        end

        def feed_one_chunk
          chunk = @payload_io.read(@chunk_size)
          if chunk.nil? || chunk.empty?
            @buffer << Base64.urlsafe_encode64(@carry, padding: false) unless @carry.empty?
            @carry = +""
            @payload_done = true
            return
          end

          bytes = @carry + chunk.b
          aligned = bytes.bytesize - (bytes.bytesize % 3)
          if aligned.positive?
            @buffer << Base64.urlsafe_encode64(bytes.byteslice(0, aligned), padding: false)
            @carry = bytes.byteslice(aligned..-1) || +""
          else
            @carry = bytes
          end
        end
      end
    end
  end
end
