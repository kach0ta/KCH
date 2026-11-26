# K.C.H. — Kach0ta's Communication Hideout

Android-first private messenger project.

**Current state:** the Android app is an early native interface shell. The current screen is in Russian and lists the planned personal spaces. The developers are credited in the app: kach0ta, vo1dka, r3z0n, and a1r1s. The existing footer signature is intentionally kept unchanged.

This is not yet a working messaging service. The Worker API has registration, login, conversation, and ciphertext-message endpoint foundations. The initial D1 schema is present, but the database and Worker still need to be configured and deployed. The Android client is not yet connected to those endpoints. Do not use it for real private conversations.

## Product decisions
- Android first; current interface language: Russian.
- Black, purple, and acid-green visual identity.
- Username + password accounts; no email registration.
- 1:1 chats, groups, Favorites, and private channels.
- No cloud backup or cloud restoration of chat history.
- New devices do not receive old chat history.
- E2EE is mandatory. Server-side message payloads must be ciphertext only.
- Calls, voice messages, reactions, and public channels are out of the first release.
- Offline delivery may use a temporary ciphertext queue, never a chat archive.

## Layout
- `app/` native Android client
- `backend/` Cloudflare Worker and D1 schema
- `docs/` architecture and security notes
- `scripts/` Termux build helper

## Build Android APK in Termux
Run from the repository root:

```sh
chmod +x scripts/build-android.sh
./scripts/build-android.sh
```

Requires `ANDROID_JAR` (defaults to the Termux android-34 path), `aapt`, `javac`, `d8`, `zip`, `zipalign`, `apksigner`, and `keytool` on PATH. Output: `dist/KCH-debug.apk`.

The signing key is kept at `~/.config/kch/debug.keystore` so subsequent builds can update the installed app without changing its Android signing identity. Back up this file securely. If it is lost, a newly generated key will not be able to update an app signed with the old key. Never commit the keystore.

## Server setup
The initial D1 schema is in `backend/migrations/0001_initial.sql`. After creating the D1 database, put its real database ID in `backend/wrangler.toml`, apply the migration with Wrangler, then deploy the Worker. These account-specific steps require the project owner to sign in and authorize access. Never commit API tokens or passwords.

## Security
The current API is development scaffolding, not a secure messaging service. A ciphertext database column does not implement end-to-end encryption. Client-side encryption, key management, authorization hardening, rate limiting, and security review are still required. See `docs/SECURITY.md` and `docs/ARCHITECTURE.md`.

Never commit passwords, API tokens, private keys, keystores, production secrets, or real user data. A public repository is not a substitute for secret management. Do not invent cryptography; select a maintained, audited E2EE implementation before sending real messages.
