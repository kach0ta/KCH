# K.C.H. architecture

## Current components

- Android client: native Java Activity, currently an interface shell.
- API: Cloudflare Worker in `backend/src/index.ts`.
- Database: Cloudflare D1 (SQLite-compatible).
- Build: `scripts/build-android.sh`, intended for Termux.

## Request flow

1. The Android client sends HTTPS requests to the Worker.
2. Registration creates a user record and returns a random session token.
3. The client sends that token as a Bearer token on authenticated requests.
4. The Worker stores only a SHA-256 hash of each session token.
5. Conversation membership is checked before listing or submitting messages.
6. Message payloads are stored as ciphertext strings; the server must never receive plaintext message content.

## Database

The initial schema is in `backend/migrations/0001_initial.sql`.

- `users`: usernames and password verifier data.
- `sessions`: hashed bearer tokens and expiry.
- `conversations`: direct, group, and private-channel containers.
- `conversation_members`: membership and role.
- `messages`: ciphertext-only message records.

## Current limitations

- The Android client is not yet connected to the API.
- No Cloudflare D1 instance or deployed Worker is configured.
- Client-side end-to-end encryption is not implemented or audited.
- Favorites, message editing/deletion, delivery/read receipts, attachments, and typing indicators are not implemented in the backend.
- The current API has no rate limiting, account recovery, session revocation endpoint, or device/session management.
- The server does not yet enforce channel-specific posting permissions or group administration rules.

Do not use this build for real private conversations. Treat the API as development scaffolding until the security work and client integration are complete.
