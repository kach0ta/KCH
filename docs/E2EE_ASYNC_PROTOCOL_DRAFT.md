# K.C.H. asynchronous E2EE protocol design draft

Status: design document only. This is not a reviewed cryptographic protocol and must not be enabled for real conversations.

## 1. Offline delivery requirement

A recipient does not need to be online when a message is composed or sent. The recipient device publishes public prekey material while it is online. A sender can later download that public material, establish an initial encrypted session locally, and upload an encrypted message to the server. The server queues the ciphertext until the recipient reconnects.

The server never needs the recipient's private keys and never needs both participants online at once.

This depends on the recipient having registered the device and published a non-expired signed prekey before going offline. If no usable prekey is available, the sender must wait or ask the recipient to reconnect; there is no plaintext fallback.

## 2. Device model and trust

- Every app installation is a distinct cryptographic device with a stable random device ID.
- Each device has one long-term P-256 ECDSA identity key generated and held by Android Keystore.
- Each account may have multiple devices. A message addressed to an account must eventually be encrypted separately for each authorized recipient device.
- A server-returned identity key is untrusted until the user verifies its fingerprint through a trusted out-of-band channel. HTTPS and account authentication do not prevent a compromised server from substituting identity keys.
- Replacing an identity key is a visible identity-change event. It must never happen silently.
- Removing a device revokes future key publication and message delivery to that device. Previously received plaintext or keys cannot be remotely erased.

## 3. Public material and private material

The device may publish:
- device ID;
- encoded identity public key;
- signed-prekey ID, encoded P-256 public key, expiry and identity signature;
- a bounded batch of one-time prekey IDs, encoded P-256 public keys and identity signatures;
- protocol version and publication timestamp.

The device must never publish:
- identity private key;
- signed-prekey private key;
- one-time-prekey private keys;
- session secrets, chain keys or message keys;
- decrypted message or attachment content.

The current SignedPreKeyBundle signature transcript binds protocol version, account ID, device ID, prekey ID, expiry and exact encoded public-key bytes. Server-side validation must reproduce this transcript exactly and verify the signature against the registered device identity key.

Each one-time prekey needs its own canonical, length-prefixed transcript binding protocol version, account ID, device ID, one-time-prekey ID and exact public-key bytes. Each is signed with a separate domain string such as ONE-TIME-PREKEY-V1. The server must verify these signatures before storing keys.

## 4. Proposed server API contract

These are design contracts, not implemented endpoints.

### Register a device

POST /v1/me/devices

Authenticated account session required. Request contains a stable device ID, identity public key and proof-of-possession signature over a canonical registration transcript. The server associates the identity key with the authenticated account.

- A device ID already registered to the same account cannot silently change its identity key.
- Re-registering the same device with the same key is idempotent.
- A new device ID is a new cryptographic identity and should trigger a visible new-device event.
- Device identity rotation requires a separate explicit flow; do not overwrite the old key.

### Publish public prekeys

PUT /v1/me/devices/:deviceId/prekeys

Authenticated owner only. Request contains one signed prekey and a bounded batch of signed one-time prekeys. The server verifies every signature and public-key encoding against the registered identity key before writing anything.

- A signed-prekey ID is immutable. Rotation uses a new ID.
- Expired signed prekeys cannot be published or returned.
- Duplicate one-time-prekey IDs are rejected.
- Publication is transactional: either the whole valid batch is accepted or none is.
- Private key bytes are rejected by schema and never stored.

### Fetch and atomically claim a bundle

POST /v1/users/:userId/devices/:deviceId/prekey-bundle

Authenticated sender required. Request includes a random client-generated request ID. The server returns the registered identity key, current signed prekey and at most one one-time prekey.

The one-time-prekey claim must be atomic. Two senders must never receive the same one-time prekey. A retry with the same request ID by the same requester must return the same already-claimed response, not consume a second key. A different requester or target device must not be able to replay that request ID.

If the device has no one-time prekeys, the server may return the signed prekey alone and mark the response accordingly. The client protocol must explicitly support and test that case; it must not invent or reuse a one-time key.

The response is only a delivery mechanism. The client must verify the identity fingerprint and signed-prekey signature locally before using any returned key.

### Replenishment and revocation

Devices replenish one-time prekeys when their local inventory falls below a threshold. The server exposes only counts, not private material. A device can revoke itself; account-level device removal must be authenticated and produce a visible security event. Unclaimed one-time prekeys for a revoked device are deleted.

## 5. Offline message flow

1. Recipient device registers its identity and publishes a signed prekey plus one-time prekeys.
2. Recipient goes offline.
3. Sender requests a bundle for each recipient device. The server atomically claims a one-time prekey where available.
4. Sender verifies the recipient identity fingerprint and signed-prekey signature. If trust is not established, the UI must clearly require identity verification or warn that the first contact is not authenticated.
5. Sender and recipient clients run the separately specified, reviewed asynchronous handshake. The exact KDF inputs, transcript, roles, nonce handling, replay behavior and key schedule are not yet specified here and must not be guessed during implementation.
6. Sender encrypts the initial message locally and uploads ciphertext plus the minimum routing envelope.
7. Server stores and queues ciphertext. It cannot decrypt it.
8. Recipient reconnects, downloads ciphertext, performs the matching local handshake step and decrypts.
9. Both devices persist protocol state safely. Retries and duplicate delivery must not reuse message nonces or roll back ratchet state.

## 6. Reliability and security requirements

- Message delivery is at-least-once; clients deduplicate by immutable message ID.
- A network retry must not create a new session or consume another one-time prekey if the original claim already succeeded.
- Message encryption fails closed. Never downgrade to plaintext.
- The server must enforce membership and authorization before storing or returning ciphertext.
- The server must not expose one-time private keys (which it never receives), reuse claimed one-time public keys, or silently replace device identities.
- Rate limits and bounded request/body sizes are required for device registration, key publication and bundle claims.
- Expired signed prekeys are not returned. Expired unclaimed one-time prekeys are removed; already claimed keys remain the responsibility of the recipient device until the protocol's retention rules permit deletion.
- A sender may be offline too: messages remain in the sender's local outbox until upload succeeds.
- E2EE does not hide account IDs, device IDs, conversation membership, message timing, message sizes or network metadata from the service.

## 7. Cryptographic implementation gate

The current project has P-256 ECDH, HKDF-SHA-256, AES-256-GCM, a device signing identity, signed-prekey bundles and encrypted local signed-prekey persistence. These are building blocks only.

Before a live handshake is implemented, a complete protocol specification must define:
- exact ordered ECDH terms and key schedule;
- transcript and context binding for both identities, accounts, devices, roles, protocol version, key IDs, ephemeral keys and nonces;
- identity-change and first-contact behavior;
- one-time-prekey claim/retry semantics;
- replay and downgrade protection;
- duplicate, concurrent and out-of-order message handling;
- crash-safe state transitions and rollback resistance;
- deterministic test vectors and interoperability tests.

A custom protocol is not equivalent to Signal merely because it uses ECDH, HKDF and AES-GCM. The design must receive independent cryptographic review before release. If that review cannot be obtained, do not ship the custom protocol for sensitive communications.

## 8. Current status

Implemented prototypes: device identity, signed-prekey bundle verification, local encrypted signed-prekey persistence and low-level cryptographic primitives.

Not implemented: device registration, server prekey publication/claim endpoints, one-time prekeys, asynchronous handshake, message ratchet, encrypted message integration, trusted identity UI, and offline queue delivery guarantees.

K.C.H. is not currently an end-to-end encrypted messenger. This draft does not change that status.
