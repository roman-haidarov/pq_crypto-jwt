# pq_crypto-jwt

`pq_crypto-jwt` is a small adapter that connects [`pq_crypto`](https://rubygems.org/gems/pq_crypto) to the [`ruby-jwt`](https://rubygems.org/gems/jwt) ecosystem.

This release focuses on the RFC 9964 ML-DSA JWS surface:

- ML-DSA JWS signing and verification for `ruby-jwt`
- AKP JWK/JWKS helpers for ML-DSA verification keys
- seed-based private AKP JWK import and explicit seed export paths
- PEM/DER import helpers for ML-DSA SPKI/PKCS#8 keys through `PQCrypto::Key`
- streaming detached JWS helpers for `ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87`

ML-KEM/JWE is **not included**. Full JWE support needs a separate standards-compatible implementation and interoperability tests.

## Requirements

- Ruby `>= 3.1.0`
- `pq_crypto` `~> 0.6.1`
- `jwt` `>= 3.1`, `< 4.0`

The CI release matrix covers Ruby `3.1`, `3.2`, `3.3`, `3.4`, `4.0` crossed with `jwt ~> 3.1.0` and `jwt ~> 3.2.0` on Linux and macOS. A dedicated Node `jose` interop job runs on Node 24 with `JOSE_INTEROP=1`.

`pq_crypto-jwt` is Ruby-only and does not ship its own native extension. Native ML-DSA work, seed-aware keys, PKCS#8/SPKI parsing, and streaming signing/verification are delegated to `pq_crypto`.

## Install

```ruby
gem "pq_crypto-jwt", "~> 0.2"
```

## Register the algorithms

`pq_crypto-jwt` does not register algorithms implicitly. Register once during boot:

```ruby
require "pq_crypto/jwt"

PQCrypto::JWT.register!
```

This registers the following JOSE `alg` values with `ruby-jwt`:

```text
ML-DSA-44
ML-DSA-65
ML-DSA-87
```

## JWS — sign and verify with ML-DSA

```ruby
require "pq_crypto/jwt"

PQCrypto::JWT.register!
keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")

token = JWT.encode({ "sub" => "alice" }, keypair.secret_key, "ML-DSA-65")
payload, header = JWT.decode(token, keypair.public_key, true, algorithm: "ML-DSA-65")
```

The adapter validates both the JOSE algorithm string and the concrete `pq_crypto` key type. A token signed with `ML-DSA-44`, for example, will not verify under `ML-DSA-65`.

For RFC 9964 JOSE algorithms, the FIPS 204 `ctx` value is fixed to the empty string. The adapter passes `context: "".b` explicitly in both one-shot and streaming paths and does not expose a per-token context option for `ML-DSA-44`, `ML-DSA-65`, or `ML-DSA-87`.

## PEM and DER import

SPKI public keys and PKCS#8 secret keys can be imported through the helper API:

```ruby
public_key = PQCrypto::JWT::Keys.public_from_pem(spki_pem)
secret_key = PQCrypto::JWT::Keys.secret_from_pem(pkcs8_pem)

token = JWT.encode({ "sub" => "alice" }, secret_key, "ML-DSA-65")
JWT.decode(token, public_key, true, algorithm: "ML-DSA-65")
```

For stricter dispatch, pass `expect: :signature`:

```ruby
public_key = PQCrypto::JWT::Keys.public_from_pem(spki_pem, expect: :signature)
secret_key = PQCrypto::JWT::Keys.secret_from_pem(pkcs8_pem, expect: :signature)
```

DER helpers are also available:

```ruby
public_key = PQCrypto::JWT::Keys.public_from_der(spki_der)
secret_key = PQCrypto::JWT::Keys.secret_from_der(pkcs8_der, passphrase: passphrase)
```

## JWK and JWKS

Public AKP JWK round-trip:

```ruby
keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key, kid: "signing-key")
public_key = PQCrypto::JWT::JWK.public_key_from_jwk(jwk)
```

Optional public JWK metadata can be supplied directly:

```ruby
jwk = PQCrypto::JWT::JWK.from_public_key(
  keypair.public_key,
  kid: "signing-key",
  use: "sig",
  key_ops: ["verify"]
)
```

Private AKP JWK uses RFC 9964 seed format: `priv` is the 32 raw-byte ML-DSA seed encoded as base64url. It is not the expanded ML-DSA secret key, and helper APIs expect raw seed bytes, not hex or text encodings.

```ruby
secret_key = PQCrypto::JWT::JWK.secret_key_from_jwk(private_jwk)
```

With `pq_crypto 0.6.1`, private import trusts the JWK `pub` field as metadata because the parent gem does not expose public seed derivation yet. `secret_key_from_jwk` without `verify_public: true` is suitable only for trusted private JWK material. It does not prove that `pub` belongs to `priv`. Callers that need a strict `pub`/`priv` consistency check can request it explicitly; this will raise `UnsupportedFeature` until the parent exposes `Signature.public_key_from_seed` or `Signature.keypair_from_seed`:

```ruby
secret_key = PQCrypto::JWT::JWK.secret_key_from_jwk(private_jwk, verify_public: true)
```

Export is intentionally explicit. Current `pq_crypto 0.6.1` can import seed-aware keys but does not expose a stable public seed accessor / public-key-from-seed API, so use `from_seed` and pass the matching public key:

```ruby
jwk = PQCrypto::JWT::JWK.from_seed(seed_32_bytes, alg: "ML-DSA-65", public_key: public_key)
```

`from_seed` also accepts `verify_public: true` for symmetry with private import. On current `pq_crypto 0.6.1` this raises `UnsupportedFeature`; once the parent exposes public seed derivation, it will reject a `public_key:` that does not match the supplied seed. Without `verify_public: true`, the explicitly supplied `public_key:` is trusted.

`from_secret_key` is reserved for a future parent release that exposes a public seed accessor. Expanded-only keys, and current `pq_crypto 0.6.1` keys, raise `UnsupportedFeature` instead of reading parent private state.

JWK thumbprints are available as raw RFC 7638 thumbprints or RFC 9278-style URIs:

```ruby
thumbprint = PQCrypto::JWT::JWK.thumbprint(jwk)
thumbprint_uri = PQCrypto::JWT::JWK.thumbprint_uri(jwk)
```

`thumbprint` validates that `pub` has the expected ML-DSA public-key length for the declared `alg` before hashing the canonical AKP members.

JWKS lookup with `ruby-jwt`:

```ruby
PQCrypto::JWT.register!
keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
jwks = PQCrypto::JWT::JWKS.from_keys([keypair.public_key], kids: ["signing-key"])

token = JWT.encode({ "sub" => "alice" }, keypair.secret_key, "ML-DSA-65", kid: "signing-key")
payload, header = JWT.decode(token, nil, true, algorithms: ["ML-DSA-65"], jwks: jwks)
```

`JWKS.from_keys(kids:)` requires one `kid` per public key. For automatic key IDs, derive them from the AKP thumbprint:

```ruby
jwks = PQCrypto::JWT::JWKS.from_keys([keypair.public_key], kid_strategy: :thumbprint)
jwks = PQCrypto::JWT::JWKS.from_keys([keypair.public_key], kid_strategy: :thumbprint_uri)
```

For rotation, pass `PQCrypto::JWT::JWKS.loader(callable_or_hash)` as the `jwks:` value. The loader is thread-safe and refreshes when `ruby-jwt` calls it with `invalidate: true`.

## Streaming detached JWS

All three ML-DSA JOSE algorithms support the streaming detached JWS helper when backed by `pq_crypto ~> 0.6.1`. The compact form is `header..signature`; callers must supply the same payload stream separately for verification.

```ruby
File.open("payload.bin", "rb") do |payload_io|
  token = PQCrypto::JWT::JWA::MLDSA65.sign_io(
    signing_key: keypair.secret_key,
    payload_io: payload_io
  )
end

File.open("payload.bin", "rb") do |payload_io|
  PQCrypto::JWT::JWA::MLDSA65.verify_io!(
    verification_key: keypair.public_key,
    token: token,
    payload_io: payload_io
  )
end
```

Equivalent helpers exist on:

```text
PQCrypto::JWT::JWA::MLDSA44
PQCrypto::JWT::JWA::MLDSA65
PQCrypto::JWT::JWA::MLDSA87
```

`verify_io` returns `[payload_position, header]` on success. `payload_position` is `nil` for non-seekable streams that do not respond to `#pos`.

By default, streaming verification fails closed and returns `false` for malformed tokens or failed signatures. Use `strict: true` when callers need error classification: structural/token errors raise `JWT::DecodeError`, and cryptographic verification failures raise `JWT::VerificationError`.

```ruby
PQCrypto::JWT::JWA::MLDSA65.verify_io(
  verification_key: keypair.public_key,
  token: token,
  payload_io: payload_io,
  strict: true
)
```

The streaming helper signs the regular compact JWS signing input with a base64url-encoded payload. It does not implement RFC 7797 unencoded payload mode. `sign_io` rejects protected `b64` and `crit` header fields, and `verify_io` fails closed for critical headers or `b64: false`. `chunk_size` must be a positive integer.

## Non-goals

This adapter deliberately does **not** expose:

- ML-KEM JWE key agreement
- JWE compact or JSON serialization
- JWE content encryption, AAD, IV, or authentication tag handling
- composite / hybrid JOSE signatures
- custom ML-DSA JOSE `ctx` values
- general-purpose JWT claims policy beyond what `ruby-jwt` already provides

This keeps the public API small and avoids publishing speculative JWE or composite-signature behavior before the relevant JOSE work is stable.

## Security status

```text
unaudited; implements the RFC 9964 ML-DSA JOSE algorithm identifiers and AKP
JWK seed encoding; backed by pq_crypto, which should also be reviewed before
production use.
```

Use in production only after your own security review and interoperability testing. The repository includes an optional Node `jose` interop test (`JOSE_INTEROP=1 bundle exec ruby test/test_jose_interop.rb`) for the ML-DSA-65 JWS/JWK path.

## License

MIT.
