# frozen_string_literal: true

require "base64"
require "json"

module PQCrypto
  module JWT
    module JWA
      module Streaming
        DEFAULT_CHUNK_SIZE = 1 << 20
        DECODE_ERRORS = [JSON::ParserError, ArgumentError, TypeError, EncodingError].freeze
        VERIFY_ERRORS = [PQCrypto::Error, PQCrypto::JWT::Error].freeze
        UNSUPPORTED_HEADERS = %w[b64 crit].freeze
        STREAMING_DECODE_ERRORS = DECODE_ERRORS
        STREAMING_VERIFY_ERRORS = VERIFY_ERRORS

        def self.validate_chunk_size!(chunk_size)
          return chunk_size if chunk_size.is_a?(Integer) && chunk_size.positive?

          raise ArgumentError, "chunk_size must be a positive Integer"
        end

        def streaming_supported?
          PQCrypto::Signature.supported.include?(pq_crypto_algorithm)
        rescue PQCrypto::Error
          false
        end

        def sign_io(signing_key:, payload_io: nil, io: nil, header_fields: {}, chunk_size: DEFAULT_CHUNK_SIZE)
          payload_io ||= io
          validate_stream!(signing_key, PQCrypto::Signature::SecretKey, "signing", chunk_size)
          raise ArgumentError, "payload_io must respond to #read" unless payload_io.respond_to?(:read)

          encoded_header = base64url(JSON.generate(signing_header(header_fields)))
          input = DetachedSigningInputIO.new(encoded_header, payload_io, chunk_size:)
          "#{encoded_header}..#{base64url(signing_key.sign_io(input, chunk_size:, context: EMPTY_CONTEXT))}"
        rescue PQCrypto::JWT::Error, ArgumentError
          raise
        rescue StandardError => error
          raise ::JWT::EncodeError, error.message
        end

        def verify_io(verification_key:, token:, payload_io:, chunk_size: DEFAULT_CHUNK_SIZE, strict: false)
          verify_detached!(verification_key, token, payload_io, chunk_size)
        rescue ::JWT::DecodeError
          raise if strict

          false
        end

        def verify_io!(**kwargs)
          verify_io(**kwargs) || raise(::JWT::VerificationError, "Streaming JWS verification failed")
          true
        end

        private

        def verify_detached!(verification_key, token, payload_io, chunk_size)
          validate_stream!(verification_key, PQCrypto::Signature::PublicKey, "verification", chunk_size)
          raise ::JWT::DecodeError, "token must be a String" unless token.is_a?(String)
          raise ::JWT::DecodeError, "payload_io must respond to #read" unless payload_io.respond_to?(:read)

          encoded_header, header, signature = decode_detached(token)
          input = DetachedSigningInputIO.new(encoded_header, payload_io, chunk_size:)
          unless verification_key.verify_io(input, signature, chunk_size:, context: EMPTY_CONTEXT)
            raise ::JWT::VerificationError, "Streaming JWS verification failed"
          end

          [payload_position(payload_io), header]
        rescue *DECODE_ERRORS => error
          raise ::JWT::DecodeError, error.message
        rescue *VERIFY_ERRORS => error
          raise ::JWT::VerificationError, error.message
        end

        def decode_detached(token)
          case token.split(".", -1)
          in [encoded_header, "", encoded_signature]
            header = JSON.parse(Base64URL.decode(encoded_header))
            raise ::JWT::DecodeError, "unsupported streaming JWS protected header" unless streamable_header?(header)

            signature = Base64URL.decode(encoded_signature)
            raise ::JWT::VerificationError, "invalid #{alg} signature length" unless signature_length_valid?(signature)

            [encoded_header, header, signature]
          else
            raise ::JWT::DecodeError,
                  "compact detached JWS must have exactly three segments and an empty payload segment"
          end
        end

        def ensure_streaming!
          raise UnsupportedFeature, "#{alg} does not support streaming JWS" unless streaming_supported?
        end

        def validate_stream!(key, klass, role, chunk_size)
          ensure_streaming!
          ensure_key!(key, klass, role)
          Streaming.validate_chunk_size!(chunk_size)
        end

        def payload_position(payload_io)
          payload_io.pos if payload_io.respond_to?(:pos)
        end

        def signing_header(header_fields)
          raise ArgumentError, "header_fields must be a Hash-like object" unless header_fields.respond_to?(:to_hash)

          converted = header_fields.to_hash
          raise ArgumentError, "header_fields #to_hash must return a Hash" unless converted.is_a?(Hash)

          header = converted.transform_keys { |key| String(key) }
          unsupported = UNSUPPORTED_HEADERS & header.keys
          unless unsupported.empty?
            raise ArgumentError, "unsupported protected header#{'s' if unsupported.size > 1}: #{unsupported.join(', ')}"
          end

          header.merge("alg" => alg)
        end

        def streamable_header?(header)
          header.is_a?(Hash) && header["alg"] == alg && !header.key?("crit") && header.fetch("b64", true) == true
        end

        def base64url(bytes) = Base64URL.encode(bytes)
      end
    end
  end
end
