# K.C.H. — Kach0ta's Communication Hideout

Android-first private messenger project.

**Current state:** the Android app is an early native interface shell. The current screen is in Russian and lists the planned personal spaces. The developers are credited in the app: kach0ta, vo1dka, r3z0n, and a1r1s. The existing footer signature is intentionally kept unchanged.

This is not yet a working messaging service. The Worker API has registration, login, conversation, and ciphertext-message endpoint foundations, but it still needs a configured Cloudflare D1 database and deployment. The Android client is not yet connected to those endpoints. Do not use it for real private conversations.

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

Requires `ANDROID_JAR` (defaults to the Termux android-34 path), `aapt`, `javac`, `d8`, `zip`, `zipalign`, `apksigner`, and `keytool` on PATH. Output: `dist/KCH-debug.apk`. The debug key is generated under ignored build output and must never be used as a production signing key.

## Server boundary
The backend cannot be used until a Cloudflare account is configured, a D1 database is created, its real database ID is placed in `backend/wrangler.toml`, migrations are applied, and the Worker is deployed. Those account-specific steps require the project owner to sign in and authorize access. Never commit API tokens or passwords.

## Security
Never commit passwords, API tokens, private keys, keystores, production secrets, or real user data. A public repository is not a substitute for secret management. Do not invent cryptography; select a maintained, audited E2EE implementation before sending real messages.
