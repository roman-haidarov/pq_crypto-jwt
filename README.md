# pq_crypto-jwt

`pq_crypto-jwt` is a small adapter that connects [`pq_crypto`](https://rubygems.org/gems/pq_crypto) to the [`ruby-jwt`](https://rubygems.org/gems/jwt) ecosystem.

The first public release intentionally focuses on one stable surface:

- ML-DSA JWS signing and verification for `ruby-jwt`
- public AKP JWK/JWKS helpers for ML-DSA verification keys
- PEM import helpers for ML-DSA SPKI/PKCS#8 keys
- ML-DSA-65 streaming detached JWS helper

ML-KEM/JWE is **not included** in this first release. Full JWE support needs a separate standards-compatible implementation and interoperability tests.

## Install

```ruby
gem "pq_crypto-jwt", "~> 0.1"
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

The adapter validates both the JOSE algorithm string and the concrete pq_crypto key type. A token signed with `ML-DSA-44`, for example, will not verify under `ML-DSA-65`.

## PEM import

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

## JWK and JWKS

Public AKP JWK round-trip:

```ruby
keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
jwk = PQCrypto::JWT::JWK.from_public_key(keypair.public_key, kid: "signing-key")
public_key = PQCrypto::JWT::JWK.public_key_from_jwk(jwk)
```

JWKS lookup with `ruby-jwt`:

```ruby
PQCrypto::JWT.register!
keypair = PQCrypto::JWT::Keys.generate("ML-DSA-65")
jwks = PQCrypto::JWT::JWKS.from_keys([keypair.public_key], kids: ["signing-key"])

token = JWT.encode({ "sub" => "alice" }, keypair.secret_key, "ML-DSA-65", kid: "signing-key")
payload, header = JWT.decode(token, nil, true, algorithms: ["ML-DSA-65"], jwks: jwks)
```

For rotation, pass `PQCrypto::JWT::JWKS.loader(callable_or_hash)` as the `jwks:` value.

## Streaming detached JWS

`ML-DSA-65` also supports a streaming detached JWS helper. The compact form is `header..signature`; callers must supply the same payload stream separately for verification.

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

## Non-goals for the first release

The first release deliberately does **not** expose:

- ML-KEM JWE key agreement
- JWE compact or JSON serialization
- JWE content encryption, AAD, IV, or authentication tag handling
- private AKP JWK import/export; use PEM/PKCS#8 for signing keys
- general-purpose JWT claims policy beyond what `ruby-jwt` already provides

This keeps the public API small and avoids publishing draft-incompatible JWE behavior.

## Security status

```text
unaudited; tracks draft-ietf-cose-dilithium for ML-DSA JOSE identifiers;
identifiers and wire formats may change before RFC publication; backed by
pq_crypto, which should also be reviewed before production use.
```

Use in production only after your own security review and interoperability testing.

## License

MIT.
