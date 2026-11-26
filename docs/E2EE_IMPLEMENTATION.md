# K.C.H. end-to-end encryption implementation plan

## Security boundary

The API and database are untrusted storage/transport. They may see account identifiers, routing metadata, ciphertext sizes and timing. They must never receive message plaintext, blob plaintext, content keys, private identity keys, or unwrapped avatar keys.

The existing `Aes256Gcm` helper protects one installation's session token with Android Keystore. It is not a user-to-user encryption mechanism. The existing `avatar_data` field currently stores plaintext Base64 image bytes and MUST NOT be described as encrypted. Existing message `ciphertext` values are only opaque strings; the server does not prove that they were encrypted.

## Protocol choice

Do not invent a key exchange, ratchet, group protocol, or identity format. Integrate a maintained Signal Protocol implementation (libsignal) after confirming:
- a supported Android/JVM artifact and its exact pinned version;
- Android API 23 compatibility and Termux build feasibility;
- upstream license and redistribution requirements;
- reproducible build and known test vectors.

Use the protocol implementation for one-to-one message sessions, authenticated prekey/session establishment, identity keys, signed prekeys, one-time prekeys, and ratcheting. Group messaging must use a protocol-supported group design (for example, the implementation's Sender Keys support) rather than a home-grown shared AES key. Never fall back to plaintext if crypto setup fails.

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
