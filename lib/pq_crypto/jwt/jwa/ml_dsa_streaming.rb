# frozen_string_literal: true

require "base64"
require "json"

module PQCrypto
  module JWT
    module JWA
      module MLDSAStreaming
        DEFAULT_CHUNK_SIZE = 1 << 20
        STREAMING_ERRORS = [JSON::ParserError, ArgumentError, PQCrypto::Error, PQCrypto::JWT::Error, EncodingError].freeze

        def streaming_supported?
          PQCrypto::Signature.supported.include?(pq_crypto_algorithm)
        rescue PQCrypto::Error
          false
        end

        def sign_io(signing_key:, payload_io: nil, io: nil, header_fields: {}, chunk_size: DEFAULT_CHUNK_SIZE)
          ensure_streaming!
          ensure_key!(signing_key, PQCrypto::Signature::SecretKey, "signing")
          source = payload_io || io
          raise ArgumentError, "payload_io must respond to #read" unless source.respond_to?(:read)

          encoded_header = base64url(JSON.generate(header_fields.transform_keys(&:to_s).merge("alg" => alg)))
          input = DetachedSigningInputIO.new(encoded_header, source, chunk_size: chunk_size)
          signature = signing_key.sign_io(input, chunk_size: chunk_size, context: EMPTY_CONTEXT)
          "#{encoded_header}..#{base64url(signature)}"
        rescue PQCrypto::JWT::Error, ArgumentError
          raise
        rescue StandardError => e
          raise ::JWT::EncodeError, e.message
        end

        def verify_io(verification_key:, token:, payload_io:, chunk_size: DEFAULT_CHUNK_SIZE)
          ensure_streaming!
          ensure_key!(verification_key, PQCrypto::Signature::PublicKey, "verification")
          raise ArgumentError, "token must be a String" unless token.is_a?(String)
          raise ArgumentError, "payload_io must respond to #read" unless payload_io.respond_to?(:read)

          encoded_header, encoded_payload, encoded_signature, extra = token.split(".", -1)
          return false unless extra.nil? && encoded_payload == "" && encoded_signature

          header = JSON.parse(Base64.urlsafe_decode64(encoded_header))
          return false unless header.is_a?(Hash) && header["alg"] == alg

          signature = Base64.urlsafe_decode64(encoded_signature)
          return false unless signature_length_valid?(signature)

          input = DetachedSigningInputIO.new(encoded_header, payload_io, chunk_size: chunk_size)
          return false unless verification_key.verify_io(input, signature, chunk_size: chunk_size, context: EMPTY_CONTEXT)

          [payload_io.respond_to?(:pos) ? payload_io.pos : nil, header]
        rescue *STREAMING_ERRORS
          false
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
      end

      # Lazily concatenates "<encoded_header>." with the base64url-encoded payload stream,
      # so the JWS signing input can be fed to pq_crypto without materialising the payload.
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
