# K.C.H. API — development foundation
Protected endpoints require Authorization: Bearer <token>.
- POST /v1/auth/register: { username, password }; username 3-24 letters/digits/underscore; password 10-128 chars.
- POST /v1/auth/login: { username, password }.
- GET /v1/me.
- GET /v1/conversations.
- POST /v1/conversations: { kind: direct|group|channel, members: [user IDs], title? }.
- GET /v1/conversations/:id/messages.
- POST /v1/conversations/:id/messages: { ciphertext }.

Passwords are salted and PBKDF2-HMAC-SHA-256 hashed. Session tokens are random; only SHA-256 token hashes are stored. D1 statements use bound parameters.

IMPORTANT: the API stores a ciphertext field, but this repo does not yet contain client-side E2EE. Never send real plaintext messages to this endpoint or claim chats are end-to-end encrypted. Before real users: integrate a reviewed E2EE protocol, add rate limits, session revocation, authorization tests, and operational monitoring.
