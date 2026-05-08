# Changelog

## 0.1.2

### Changed

- Lowered the supported Ruby floor from `>= 3.4.0` to `>= 3.1.0`, matching the `pq_crypto` 0.5.x compatibility line.
- Updated the runtime dependency to `pq_crypto >= 0.5.3, < 0.6` so Ruby 3.1-3.3 use the compatibility path from the core gem while Ruby 3.4+ keeps the optimized path.
- Expanded CI coverage to Ruby 3.1, 3.2, 3.3, 3.4, and 4.0 on Linux and macOS.
- Added hard-constraint tests for the Ruby floor and `pq_crypto` dependency range.

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
