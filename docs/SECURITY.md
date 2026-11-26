# K.C.H. security notes

## Non-negotiable rule

The server must receive and store ciphertext only. It must not receive message plaintext, encryption keys, recovery phrases, or private identity keys.

## What exists now

- Passwords are not stored in plaintext. The Worker derives a PBKDF2-HMAC-SHA-256 verifier with a per-user random salt and 310,000 iterations.
- Session tokens are generated from a cryptographically secure random source. Only their SHA-256 hashes are stored in D1.
- Sessions expire after 30 days.
- Authenticated conversation reads and writes check conversation membership.
- D1 stores message payloads in a field named `ciphertext`.

## What this does not prove

- A ciphertext field does not itself provide end-to-end encryption.
- There is no implemented client-side key generation, key exchange, authenticated encryption, identity verification, or multi-device protocol.
- The current cryptographic design has not been independently audited.
- Password hashing does not protect a compromised unlocked device or a compromised account.

## Required before real-world use

1. Choose a maintained, reviewed E2EE protocol/library; do not invent a custom protocol.
2. Implement client-side encryption and decryption. Keys must remain on user devices.
3. Define identity keys, device enrollment, key changes, and safety-number/fingerprint verification.
4. Add rate limiting and abuse controls to registration and login.
5. Add session revocation and device/session management.
6. Review authorization for direct chats, groups, and private channels.
7. Add tests for authentication, membership boundaries, malformed requests, and ciphertext limits.
8. Complete a security review before describing the messenger as secure or private.

## Operational rules

- Never commit API tokens, passwords, production secrets, private keys, or keystores.
- Keep Cloudflare credentials in local secret storage.
- Do not enable plaintext message logging.
- Do not use this development build for sensitive conversations.
