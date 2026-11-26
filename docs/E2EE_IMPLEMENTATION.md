# K.C.H. end-to-end encryption implementation plan

## Security boundary

The API and database are untrusted storage/transport. They may see account identifiers, routing metadata, ciphertext sizes and timing. They must never receive message plaintext, blob plaintext, content keys, private identity keys, or unwrapped avatar keys.

The existing `Aes256Gcm` helper protects one installation's session token with Android Keystore. It is not a user-to-user encryption mechanism. The existing `avatar_data` field currently stores plaintext Base64 image bytes and MUST NOT be described as encrypted. Existing message `ciphertext` values are only opaque strings; the server does not prove that they were encrypted.

## Protocol direction: platform primitives, not a finished protocol

Project decision: first investigate a no-third-party-library implementation using Android/JCA cryptographic providers. This avoids bundling libsignal/AGPLv3, but it does NOT make a custom protocol equivalent to Signal and does not remove the need for security review.

The current app targets Android API 23. Android documents ECDH as available from API 11, while XDH (the JCA name used for X25519) is only available from API 33. Therefore the first compatibility prototype uses ECDH over NIST P-256 (`secp256r1`) plus HKDF-SHA-256. This is a compatibility choice for a prototype, not a claim that it is the best protocol suite for every future device.

`CryptoPrimitives.java` currently provides only:
- ephemeral P-256 ECDH key-pair generation;
- X.509 public-key encoding/decoding;
- HKDF-SHA-256 key derivation with a caller-supplied context.

These primitives are NOT a messaging protocol. They do not authenticate public keys, establish trust in a contact, prevent replay, implement a Double Ratchet, provide forward secrecy across individual messages, manage multi-device identity, or solve group/channel key rotation. Do not connect them to live message sending yet. Never fall back to plaintext if a future crypto setup fails.

Before using these primitives for real conversations, the protocol design must define and test identity authentication/signatures, signed prekeys or an equivalent asynchronous setup, replay protection, message ordering, ratchet state, key-change handling, multi-device behavior, group membership changes, and recovery after device loss. If we cannot implement and independently review these correctly, we must use a maintained audited protocol implementation instead of shipping a home-grown ratchet.

Official Android API reference: https://developer.android.com/reference/javax/crypto/KeyAgreement (ECDH API 11+, XDH API 33+).

## Blob encryption: first building block

`EncryptedBlob.java` supplies AES-256-GCM for binary avatars and attachments:
- generate a fresh random 32-byte content key for each blob;
- encrypt on the sender's device before upload;
- bind ciphertext to a stable non-secret context string using GCM AAD;
- send the content key only inside an authenticated protocol session to each authorized device;
- store ciphertext and wrapped-key envelopes separately;
- decrypt only after the receiving device authenticates and unwraps the content key.

The helper alone does NOT provide E2EE. Key distribution, identity authentication, membership changes, revocation and secure persistence are still required. Never reuse a content key with a new nonce scheme or upload the raw content key.

For an avatar, use a random per-avatar content key and distribute it to authorized contacts through established E2EE sessions. Keep the server-side avatar record opaque: owner ID, ciphertext object, version and non-secret metadata only. Do not store the image as Base64 plaintext in `users.avatar_data`. A profile update should upload ciphertext, and clients should decrypt locally. Group/channel avatars should distribute the key only to current members and rotate it when membership changes.

## Message envelope

Message plaintext must be encrypted by the established Signal session. The API should accept a versioned opaque envelope and enforce size limits, but must not parse or decrypt it. Bind conversation ID and message ID/type into authenticated protocol metadata where supported. Message edits and deletes are authenticated events, not server-side plaintext mutations.

## Required rollout order

1. Add and test the pinned libsignal dependency on the actual Android/Termux toolchain.
2. Implement device identity and prekey registration endpoints. Store public key material only; authenticate uploads and prevent prekey exhaustion.
3. Implement client-side session establishment and identity/fingerprint verification UI. Do not silently trust key changes.
4. Add end-to-end encrypted direct messages and decrypt/render locally.
5. Add per-blob content-key encryption and key envelopes for avatars and attachments.
6. Add group membership/key rotation and channel permissions.
7. Remove plaintext avatar storage and reject legacy plaintext message/blob uploads.
8. Add interoperability, tamper, replay, key-change, multi-device and authorization tests; obtain independent security review.

## Current implementation status

- Implemented in this branch: AES-256-GCM binary blob primitive with random 96-bit nonce, 128-bit tag, context AAD, strict key length and versioned envelope.
- Not implemented: Signal/libsignal sessions, identity/prekeys, key verification, server key endpoints, blob upload/download, avatar key distribution, encrypted message UI, group key management.
- Do not use this branch for sensitive communication or claim that K.C.H. is E2EE yet.

## Data lifecycle

See [DATA_RETENTION.md](DATA_RETENTION.md). Deleted messages are physically removed from the active SQLite database by the new message-specific DELETE endpoint. Expired sessions are pruned periodically. Legacy plaintext avatar fields are cleared and plaintext avatar writes are rejected. SQLite secure-delete and WAL checkpoints reduce retained database copies but cannot guarantee erasure from flash storage, provider snapshots or downloaded client copies.
