import { readFileSync } from 'node:fs'
import { importJWK, exportJWK, generateKeyPair, jwtVerify, SignJWT } from 'jose'

const input = JSON.parse(readFileSync(process.argv[2], 'utf8'))
const alg = input.public_jwk.alg

const rubyPublicKey = await importJWK(input.public_jwk, alg)
const { payload, protectedHeader } = await jwtVerify(input.token, rubyPublicKey, {
  algorithms: [alg],
})

if (payload.pay !== 'load' || protectedHeader.alg !== alg) {
  throw new Error('Ruby-generated token verification returned unexpected payload/header')
}

const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true })
const nodePublicJwk = await exportJWK(publicKey)
nodePublicJwk.kty = 'AKP'
nodePublicJwk.alg = alg
nodePublicJwk.kid = 'node-jose'

const nodeToken = await new SignJWT({ pay: 'load' })
  .setProtectedHeader({ alg, kid: 'node-jose' })
  .sign(privateKey)

process.stdout.write(JSON.stringify({ public_jwk: nodePublicJwk, token: nodeToken }))
