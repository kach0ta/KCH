# K.C.H. data retention and cleanup policy

## Rules

K.C.H. must retain only data needed to operate the service. Cleanup must never silently erase chat history: timed auto-delete was intentionally excluded from the product.

## Implemented on the E2EE foundation branch

- **Legacy avatars:** on backend startup, old plaintext `users.avatar_data` values are set to NULL. The API rejects new plaintext avatar uploads with `plaintext_avatar_disabled`.
- **Encrypted avatars:** the profile record stores only an opaque ciphertext envelope, MIME hint, version and update timestamp. Replacing or clearing an avatar overwrites the previous database value; no avatar history is kept.
- **Message deletion:** `DELETE /v1/conversations/:conversationId/messages/:messageId` physically removes the message row. Only its sender may currently delete it. The conversation membership check is required first.
- **Expired sessions:** expired authentication sessions are pruned every six hours.
- **SQLite cleanup:** `secure_delete=ON` is enabled and a WAL truncate checkpoint is requested after destructive changes and scheduled cleanup.

## Not yet implemented

- Attachment upload/storage does not exist yet. When introduced, each blob must have a database record and an opaque storage object key. Deleting a message must remove its attachment references; a background orphan collector should delete unreferenced blobs after a short safety grace period. Replacing a file must enqueue the old blob for deletion.
- Device/prekey cleanup will be added with the E2EE identity service. Expired one-time public prekeys can be pruned, but private keys must never be uploaded.
- Group/channel membership changes must revoke access to future content and trigger key rotation. Previously received plaintext cannot be remotely erased from members' devices.

## Important limits

SQLite row deletion is not a guarantee of forensic erasure on flash storage. WAL checkpoints and `secure_delete` reduce retained copies in the active database, but provider snapshots, filesystem backups, storage wear-leveling and copies already downloaded by clients are outside this application's control. Production hosting must have an explicit volume-backup retention policy.

The server will continue to see routing metadata such as account IDs, conversation membership, timestamps, message sizes and network information. E2EE protects message and media content, not all metadata.

## API behavior

- Profile update accepts `avatarCiphertext` and `avatarMime`; it rejects the legacy plaintext `avatar` field.
- Set `clearAvatar: true` to remove the current avatar.
- Message deletion is an authenticated HTTP DELETE to the message-specific route.
- There is deliberately no automatic age-based message deletion.
