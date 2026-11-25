ALTER TABLE users ADD COLUMN password_salt TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS sessions (
 id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 token_hash TEXT NOT NULL UNIQUE,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS messages (
 id TEXT PRIMARY KEY,conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
 sender_user_id TEXT NOT NULL REFERENCES users(id),ciphertext TEXT NOT NULL,created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_conversation_time ON messages(conversation_id,created_at);
