PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY NOT NULL,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  display_name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  disabled_at INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_expires
  ON sessions(user_id, expires_at);

CREATE TABLE IF NOT EXISTS conversations (
  id TEXT PRIMARY KEY NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('direct', 'group', 'channel')),
  title TEXT,
  owner_user_id TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS conversation_members (
  conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
  joined_at INTEGER NOT NULL,
  PRIMARY KEY (conversation_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_conversation_members_user
  ON conversation_members(user_id, conversation_id);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY NOT NULL,
  conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  sender_user_id TEXT NOT NULL REFERENCES users(id),
  ciphertext TEXT NOT NULL CHECK (length(ciphertext) BETWEEN 16 AND 20000),
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_conversation_created
  ON messages(conversation_id, created_at);
