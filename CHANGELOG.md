# Changelog

## Initial public release

### Included

- ML-DSA JWS algorithms for `ruby-jwt`:
  - `ML-DSA-44`
  - `ML-DSA-65`
  - `ML-DSA-87`
- Explicit `PQCrypto::JWT.register!` registration.
- ML-DSA key generation helper through `PQCrypto::JWT::Keys.generate`.
- ML-DSA SPKI/PKCS#8 PEM import helpers.
- Public AKP JWK import/export helpers for ML-DSA verification keys.
- JWKS construction, lookup, and loader helpers.
- ML-DSA-65 streaming detached JWS helper.
- Negative tests for signature tampering, algorithm mismatch, wrong key type, unsupported algorithms, and malformed JWK inputs.

### Deliberately not included

- ML-KEM JWE key agreement or key wrap.
- JWE compact or JSON serialization.
- JWE content encryption, AAD, IV, or authentication tag handling.
- Private AKP JWK import/export; use PEM/PKCS#8 for signing keys.
- Experimental draft behavior that is not ready for interoperability testing.

### Security status

- Unaudited.
- Backed by `pq_crypto`.
- Tracks draft ML-DSA JOSE identifiers; identifiers and wire formats may change before RFC publication.
