# K.C.H. architecture

## Intended shape
- Android client: native application.
- API: Cloudflare Worker.
- Realtime: Durable Objects / WebSocket, to be implemented after defining the API contract.
- Metadata: Cloudflare D1.
- Attachments: Cloudflare R2, encrypted on the client before upload.

## Trust boundaries
1. Plaintext exists only on client devices.
2. Server routes and temporarily queues ciphertext for offline delivery.
3. Server never receives private identity/session keys.
4. A new device does not restore old chat history from cloud.
5. Removing a member/device requires key rotation so it cannot decrypt future content.

## Cryptography
Do not implement cryptographic primitives or a ratchet protocol from scratch. Select a maintained, reviewed E2EE implementation with a compatible license and document its version before real messaging is enabled. The current Android foundation has no cryptography and must not be described as encrypted.

## Delivery lifecycle
Offline delivery is a temporary queue, not a backup. Queue records need strict expiry and deletion after confirmed delivery or expiry. The schema is a starting point; authenticated delivery endpoints and cleanup are not implemented.

## Release gates
- Authentication and account recovery threat model.
- Audited E2EE integration and test vectors.
- Device linking and revocation.
- Authorization checks for all conversation operations.
- Rate limits, abuse controls, secure attachments.
- Android backup, notification, and permission review.
- Automated tests and real-device testing.
