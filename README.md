# K.C.H. — Kach0ta's Communication Hideout

Android-first private messenger project.

**Current state:** first foundation commit. The Android app is a native UI shell and the Cloudflare Worker is a health-check stub. This is not yet a working messaging service: authentication, end-to-end encryption, realtime delivery, attachments, and push notifications remain unimplemented.

## Product decisions
- Android first; Russian and English planned.
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
The script targets the lightweight Android SDK toolchain used in the project. It has not yet been verified on every device.

```sh
chmod +x scripts/build-android.sh
./scripts/build-android.sh
```

Requires `ANDROID_JAR` (defaults to the Termux android-34 path), `aapt`, `javac`, `d8`, `zip`, `zipalign`, `apksigner`, and `keytool` on PATH. Output: `dist/KCH-debug.apk`. The debug key is generated under ignored build output and must never be used as a production signing key.

## Security
Never commit passwords, API tokens, private keys, keystores, production secrets, or real user data. A private repository is not a substitute for secret management. Do not invent cryptography; select a maintained, audited E2EE implementation before sending real messages.
