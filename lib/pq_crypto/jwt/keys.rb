# frozen_string_literal: true

require "base64"
require "openssl"
require "set"

module PQCrypto
  module JWT
    module Keys
      module_function

      EXPECT_VALUES = [:auto, :signature].freeze

      def generate(alg)
        algorithm = PQCrypto::JWT.algorithm_for(alg)
        raise ArgumentError, "Unsupported PQCrypto JOSE algorithm: #{alg.inspect}" unless algorithm
        raise ArgumentError, "Unsupported key kind for #{alg.inspect}" unless algorithm.key_kind == :signature

        PQCrypto::Signature.generate(algorithm.pq_crypto_algorithm)
      end

      def public_from_pem(pem, expect: :auto)
        validate_expect!(expect)
        return PQCrypto::Signature.public_key_from_spki_pem(pem) if expect == :signature

        dispatch_public_from_pem(pem)
      end

      def secret_from_pem(pem, expect: :auto)
        validate_expect!(expect)
        return PQCrypto::Signature.secret_key_from_pkcs8_pem(pem) if expect == :signature

        dispatch_secret_from_pem(pem)
      end

      def validate_expect!(expect)
        return if EXPECT_VALUES.include?(expect)

        raise ArgumentError, "expect: must be one of #{EXPECT_VALUES.map(&:inspect).join(', ')}"
      end
      private_class_method :validate_expect!

      def dispatch_public_from_pem(pem)
        oid = spki_oid_from_pem(pem)
        return PQCrypto::Signature.public_key_from_spki_pem(pem) if signature_oids.include?(oid.to_s)

        raise PQCrypto::JWT::Error, "Unknown or unsupported PQCrypto SPKI algorithm OID: #{oid.inspect}"
      end
      private_class_method :dispatch_public_from_pem

      def dispatch_secret_from_pem(pem)
        oid = pkcs8_oid_from_pem(pem)
        return PQCrypto::Signature.secret_key_from_pkcs8_pem(pem) if signature_oids.include?(oid.to_s)

        raise PQCrypto::JWT::Error, "Unknown or unsupported PQCrypto PKCS#8 algorithm OID: #{oid.inspect}"
      end
      private_class_method :dispatch_secret_from_pem

      def spki_oid_from_pem(pem)
        sequence = OpenSSL::ASN1.decode(pem_to_der(pem))
        sequence.value.fetch(0).value.fetch(0).oid
      rescue StandardError => e
        raise PQCrypto::JWT::Error, "Unable to read SPKI algorithm OID: #{e.message}"
      end
      private_class_method :spki_oid_from_pem

      def pkcs8_oid_from_pem(pem)
        sequence = OpenSSL::ASN1.decode(pem_to_der(pem))
        sequence.value.fetch(1).value.fetch(0).oid
      rescue StandardError => e
        raise PQCrypto::JWT::Error, "Unable to read PKCS#8 algorithm OID: #{e.message}"
      end
      private_class_method :pkcs8_oid_from_pem

      def pem_to_der(pem)
        body = pem.to_s.lines.reject { |line| line.start_with?("-----") }.join
        Base64.decode64(body)
      end
      private_class_method :pem_to_der

      def signature_oids
        @signature_oids ||= PQCrypto::JWT.signing_algorithms.filter_map do |algorithm|
          oid_for_algorithm(algorithm.pq_crypto_algorithm)
        end.to_set
      end
      private_class_method :signature_oids

      def oid_for_algorithm(algorithm)
        return unless PQCrypto.const_defined?(:AlgorithmRegistry)

        oid = PQCrypto::AlgorithmRegistry.standard_oid(algorithm)
        oid&.to_s
      rescue StandardError
        nil
      end
      private_class_method :oid_for_algorithm
    end
  end
end
