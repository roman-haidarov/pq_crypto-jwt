# Changelog

## 0.2.0

### Changed

- Retargeted the adapter to the current parent line: `pq_crypto ~> 0.6.1`.
- Updated documentation and release language from draft-era ML-DSA JOSE wording to RFC 9964 terminology.
- Explicitly pass the RFC 9964 empty ML-DSA context in all one-shot and streaming sign/verify paths.
- Streaming detached JWS now applies to `ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87` instead of only `ML-DSA-65`.
- PEM/DER loading now delegates to `PQCrypto::Key.from_pem` / `PQCrypto::Key.from_der` for auto-dispatch instead of manually parsing ASN.1 OIDs in the JWT adapter.
- `signature_length_valid?` now fails closed when signature metadata cannot be resolved.
- `JWT::JWK.classes` is no longer mutated at require-time; AKP registration happens through `PQCrypto::JWT.register!`.
- CI matrix now covers Ruby `3.2`, `3.3`, `3.4`, `4.0` crossed with `jwt ~> 3.1.0` and `jwt ~> 3.2.0`.

### Added

- `PQCrypto::JWT::UnsupportedFeature` for release-scope or parent-API-gated functionality.
- Seed-based private AKP JWK import via `PQCrypto::JWT::JWK.secret_key_from_jwk`.
- Optional strict private JWK `pub`/`priv` consistency verification via `verify_public: true` for both import and explicit seed export; this is gated on future parent public seed-derivation APIs.
- Explicit seed-based private AKP JWK export via `PQCrypto::JWT::JWK.from_seed(..., public_key:)`, with optional `verify_public: true` consistency checking when parent support exists.
- Reserved `PQCrypto::JWT::JWK.from_secret_key` for future seed-exporting parent keys; current `pq_crypto 0.6.1` keys raise `UnsupportedFeature` instead of reading private parent state.
- Optional public JWK metadata on export: `use:` and `key_ops:`.
- DER helper methods:
  - `PQCrypto::JWT::Keys.public_from_der`
  - `PQCrypto::JWT::Keys.secret_from_der`
- JWKS lookup helpers for JWK thumbprint fallback and multi-match rotation windows:
  - `PQCrypto::JWT::JWKS.find(..., thumbprint:)`
  - `PQCrypto::JWT::JWKS.find_all`
- Negative tests for malformed streaming headers, extra compact segments, invalid private seed lengths, strict private JWK verification gating, dependency constraints, private API constraints, and read contract behavior.

### Fixed

- Removed private parent-state reads from private AKP JWK export; the adapter no longer uses parent instance variables as compatibility API.
- `DetachedSigningInputIO#read(nil)` now follows the Ruby IO contract and reads to EOF.
- Streaming verification now rejects non-object decoded JOSE headers before consulting `alg`.
- Streaming verification now rejects compact tokens with extra segments.
- One-shot verification rescues only expected verification/input/encoding errors instead of masking all `StandardError`.
- `JWT::JWK::AKP` no longer advertises automatic dispatch for `SecretKey`/`Keypair` until parent seed-export APIs exist.
- Removed a redundant unreachable private-JWK parameter check from `JWT::JWK::AKP`.
- JWKS loader caching no longer relies on `||=`, so falsey JWKS values do not cause repeated reloads.

### Deferred

- Composite / hybrid JOSE signatures.
- ML-KEM / JWE support.
- RBS / Sorbet signatures.
- Macro refactor for the three ML-DSA modules.

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
