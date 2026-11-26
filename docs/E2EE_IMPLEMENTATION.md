# K.C.H. end-to-end encryption implementation plan

## Security boundary

The API and database are untrusted storage and transport. They may see account identifiers, routing metadata, ciphertext sizes and timing. They must never receive message plaintext, blob plaintext, content keys, private identity keys, or unwrapped avatar keys.

The existing Aes256Gcm helper protects one installation's session token with Android Keystore. It is not user-to-user encryption. Message fields named ciphertext are not proof that their contents are encrypted.

## Project constraints

- No libsignal dependency and no third-party cryptography library in the current prototype.
- Use Android/JCA cryptographic providers available on the app's API 23 baseline.
- Keep private identity and session keys on user devices; the server stores public key material and opaque ciphertext only.
- No cloud backup or cloud restore of chat history.
- Do not silently fall back to plaintext if encryption setup or decryption fails.
- Do not describe the app as E2EE until the full protocol is implemented, tested and independently reviewed.

A custom protocol is substantially harder to secure than using a maintained, audited implementation. Passing primitive tests does not make a custom protocol equivalent to Signal. If we cannot implement and independently review the protocol correctly, the safe choice is not to ship custom E2EE.

## Current cryptographic building blocks

The app targets Android API 23. The first compatibility prototype uses:
- ECDH over NIST P-256 (secp256r1);
- HKDF-SHA-256 (RFC 5869);
- AES-256-GCM for blob encryption.

CryptoPrimitives.java currently provides ephemeral P-256 key generation, X.509 public-key encoding/decoding, ECDH and HKDF-SHA-256. DeviceIdentity.java adds a per-installation P-256 ECDSA signing identity backed by Android Keystore, with public-key export, domain-separated signatures, signature verification and SHA-256 fingerprints. EncryptedBlob.java provides a versioned AES-GCM envelope with a random 96-bit nonce, 128-bit authentication tag and context-bound AAD.

The standalone JVM tests were run by the project owner in Termux and passed:
- RFC 5869 HKDF test case 1;
- ECDH shared-key agreement;
- P-256 public-key encode/decode;
- rejection of a non-P-256 curve.

These are primitive-level tests only. They do not validate a session protocol, identity authentication, replay protection, ratcheting, multi-device behavior or group security.

## Protocol design required before live messaging

The following is a design target, not implemented functionality.

### Device identity and trust

- Each installation generates its own long-term identity key pair.
- The private identity key is protected by Android Keystore and is never uploaded.
- The server stores only the public identity key and its version.
- Each device has a visible identity fingerprint. Contacts must be able to compare/verify it; an unverified server-provided key is vulnerable to server substitution.
- Each device is a separate cryptographic endpoint. Adding or removing a device must be an explicit, visible account event.

The exact signing algorithm and Android Keystore compatibility must be validated on the minimum supported Android version before committing to a wire format.

### Asynchronous session setup

A future session setup needs:
- a device identity key;
- a signed prekey authenticated by that identity;
- a bounded pool of one-time prekeys;
- server endpoints that publish and consume public prekeys without ever receiving private keys;
- signatures and transcript binding that cover protocol version, sender device, recipient device, public keys and relevant context;
- replay protection, duplicate-request handling and prekey replenishment.

The exact handshake transcript, key schedule, failure handling and test vectors must be specified before implementation. Never trust an uploaded prekey merely because it came from the API.


### Signed prekey bundle primitive (prototype)

`SignedPreKeyBundle.java` adds an isolated building block for asynchronous session setup:
- a P-256 public prekey is encoded in X.509 form;
- a canonical, length-prefixed transcript binds protocol version, account ID, device ID, key ID, expiry and the exact public-key bytes;
- the device identity key signs that transcript with the dedicated `SIGNED-PREKEY-V1` purpose;
- verification checks expiry, P-256 encoding and the signature against a caller-supplied trusted identity public key.

This does **not** provide a usable asynchronous handshake. The matching private prekey is not persisted by this class, the server has no prekey publication/consumption endpoints, no one-time prekeys are implemented, and identity trust still requires fingerprint verification. Do not upload or rely on these bundles in live chats yet. Before use, the API must enforce uniqueness, expiry, replacement and atomic one-time-prekey consumption.

### Per-message protection

A live messaging protocol still needs a reviewed state machine for:
- sending and receiving chain keys;
- message counters and skipped-message limits;
- authenticated associated data binding conversation, sender device, message type and protocol version;
- replay and out-of-order handling;
- ratchet key rotation and deletion of obsolete secrets;
- session reset and identity-key-change handling;
- concurrent sends and crash-safe state persistence.

Do not improvise a Double Ratchet implementation directly inside the message UI. First write the state-machine specification and deterministic test vectors, then implement it as an isolated module with tamper, replay, reordering, restart and interoperability tests.

### Groups and channels

Group and channel encryption requires explicit membership epochs and key rotation. When a member is removed, future content must use a new key that is not available to that member. Device additions/removals, role changes, channel membership changes and message history access all need defined behavior. A single shared group key that never rotates is not acceptable.

### Avatars and attachments

- Encrypt each image/file on the sender's device with a fresh random content key using AES-256-GCM.
- Upload ciphertext only.
- Distribute the content key to each authorized device only through an authenticated E2EE session.
- Bind stable object metadata (object type, owner/conversation, version) as authenticated context.
- On replacement or membership changes, update key envelopes and access policy.
- Never upload a raw content key or plaintext thumbnail.
- The server may store ciphertext, version, size and non-secret MIME hints, but cannot decrypt or generate plaintext previews.

EncryptedBlob.java is only the local encryption primitive. Key distribution and recipient authorization are not implemented.

## Data and recovery implications

The server can still observe account identifiers, conversation membership, timestamps, message sizes and network metadata. E2EE does not hide this routing metadata.

There is no cloud chat-history restore. If a user loses every device holding the relevant private keys, old encrypted history and blob keys may become permanently inaccessible. Account password reset must not silently recreate old cryptographic identity or pretend to recover old messages. Any future encrypted export/recovery feature requires a separate explicit design and user-controlled secret.

See DATA_RETENTION.md for server-side deletion behavior and its limitations.

## Rollout order

1. Freeze protocol requirements, threat model, key lifecycle, identity verification UX and versioned wire format.
2. Run the Settings device-identity diagnostic on a real Android device; then validate Android Keystore key-generation/signature capabilities on the minimum supported API and add automated device identity storage tests.
3. Specify the asynchronous handshake in detail; publish only public identity/prekey material on the server.
4. Implement the handshake as an isolated module with deterministic test vectors, signature/tamper/replay tests and independent review.
5. Specify and implement the per-message ratchet and crash-safe state persistence; test reordering, replay, skipped messages, restarts and key changes.
6. Integrate encrypted direct messages. Fail closed: never send plaintext when crypto is unavailable.
7. Integrate encrypted avatars and attachments with per-object keys and authenticated recipient envelopes.
8. Add group/channel membership epochs and key rotation.
9. Perform independent security review and only then consider enabling E2EE for real users.

## Current implementation status

Implemented in this branch:
- AES-256-GCM binary blob primitive;
- P-256 ECDH and HKDF-SHA-256 platform primitives;
- local P-256 ECDSA device identity key generation/signing through Android Keystore;
- a manual Settings diagnostic that checks key creation/readback, valid signature verification and rejection of a modified signature. This diagnostic must still be run on a real device; source compilation alone is not a runtime test;
- standalone primitive self-tests, successfully run in the owner's Termux environment;
- server-side groundwork for opaque encrypted avatar ciphertext and recipient key-envelope records;
- data-retention documentation and legacy plaintext-avatar rejection.

Not implemented:
- contact identity verification UX or a trusted key directory;
- signed/one-time prekeys or handshake endpoints;
- authenticated sessions or a message ratchet;
- encrypted chat UI or message send/receive integration;
- avatar key wrapping/unwrapping in the client;
- encrypted attachment upload/download;
- group/channel key management.

**K.C.H. is not currently an end-to-end encrypted messenger. Do not use this build for sensitive communications.**
