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

The Node.js API for Netrun is in `backend/server.mjs`; `backend/package.json` defines its runtime. Import the GitHub repository into Netrun using branch `work/initial-messenger-foundation` and root directory `/backend`. Netrun should start it with `npm start`. The service listens on the `PORT` environment variable and stores SQLite data at `/data/kch.sqlite` (persistent storage). Use the public HTTPS project URL as the Android API base URL. On the free plan the service sleeps after inactivity and wakes on the next request.

The original Cloudflare Worker remains in `backend/src/index.ts` with its `wrangler.toml` for reference; it is no longer the intended API host for the Russian deployment. Do not delete the Cloudflare project until the Netrun `/health` endpoint and Android login flow have been tested. Never commit API tokens or passwords.

## Security
The current API is development scaffolding, not a secure messaging service. A ciphertext database column does not implement end-to-end encryption. Client-side encryption, key management, authorization hardening, rate limiting, and security review are still required. See `docs/SECURITY.md` and `docs/ARCHITECTURE.md`.

Never commit passwords, API tokens, private keys, keystores, production secrets, or real user data. A public repository is not a substitute for secret management. Do not invent cryptography; select a maintained, audited E2EE implementation before sending real messages.
