# K.C.H. API — development foundation

Protected endpoints require `Authorization: Bearer <token>`.

## Authentication and profile

- `POST /v1/auth/register`: `{ username, password }`. Current backend rules: username 4–24 ASCII letters/digits/underscore; password 6–8 ASCII letters/digits/underscore.
- `POST /v1/auth/login`: `{ username, password }`.
- `GET /v1/me`: returns account metadata and the current opaque avatar ciphertext envelope, if any.
- `POST /v1/me/profile`: updates `username` and/or `displayName`; encrypted avatar updates use `{ avatarCiphertext, avatarMime }`. To clear an avatar use `{ clearAvatar: true }`. The legacy plaintext `avatar` field is rejected.
- `POST /v1/me/avatar-keys/:recipientId`: stores an opaque per-recipient encrypted avatar-key envelope: `{ avatarVersion, envelopeCiphertext }`. The recipient must share at least one conversation with the owner.
- `GET /v1/users/:id/profile`: returns profile/avatar ciphertext and only the requesting user's avatar-key envelope, provided both users share a conversation.

Avatar ciphertext is opaque to the server. The server does not receive the blob content key. Key delivery to authorized contacts through E2EE sessions is not implemented yet, so this endpoint alone does not make avatars fully shareable E2EE.

## Conversations and messages

- `GET /v1/conversations`.
- `POST /v1/conversations`: `{ kind: "direct"|"group"|"channel", members: [user IDs], title? }`.
- `POST /v1/conversations` with `{ kind: "direct", self: true }` creates/reuses the personal Favorites conversation.
- `GET /v1/conversations/:id/messages`.
- `POST /v1/conversations/:id/messages`: `{ ciphertext }`. The API treats this field as opaque but does not prove that clients encrypted it.
- `DELETE /v1/conversations/:id/messages/:messageId`: physically removes a message row. Currently only the message sender may delete it.

## Security and retention status

Passwords are salted and PBKDF2-HMAC-SHA-256 hashed. Session tokens are random; only SHA-256 token hashes are stored. Expired sessions are pruned periodically. Legacy plaintext avatar values are cleared, plaintext avatar writes are rejected, and message deletion triggers a SQLite WAL checkpoint request.

See [E2EE_IMPLEMENTATION.md](E2EE_IMPLEMENTATION.md) and [DATA_RETENTION.md](DATA_RETENTION.md).

IMPORTANT: full client-side E2EE is not implemented yet. Signal Protocol sessions, identity/prekey management, identity verification, message encryption/decryption, avatar-key distribution, attachment transfer, and group key management remain unfinished. Never send sensitive plaintext or claim K.C.H. is end-to-end encrypted until those pieces are implemented and reviewed.
