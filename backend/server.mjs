import { createServer } from "node:http";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomBytes, randomUUID, createHash, pbkdf2, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import Database from "better-sqlite3";

const pbkdf2Async = promisify(pbkdf2);
const DB_PATH = process.env.KCH_DB_PATH || "/data/kch.sqlite";
mkdirSync(dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma("foreign_keys = ON");
db.pragma("journal_mode = WAL");
db.pragma("busy_timeout = 5000");

db.exec(`
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
CREATE INDEX IF NOT EXISTS idx_sessions_user_expires ON sessions(user_id, expires_at);
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
CREATE INDEX IF NOT EXISTS idx_conversation_members_user ON conversation_members(user_id, conversation_id);
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY NOT NULL,
  conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  sender_user_id TEXT NOT NULL REFERENCES users(id),
  ciphertext TEXT NOT NULL CHECK (length(ciphertext) BETWEEN 16 AND 20000),
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_conversation_created ON messages(conversation_id, created_at);
`);

const now = () => Math.floor(Date.now() / 1000);
const token = (n = 32) => randomBytes(n).toString("base64url");
const sha = (s) => createHash("sha256").update(s).digest("hex");
const passHash = async (password, salt) =>
  (await pbkdf2Async(password, salt, 310000, 32, "sha256")).toString("hex");

const headers = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "Content-Type, Authorization"
};
function reply(res, value, status = 200) {
  res.writeHead(status, headers);
  res.end(JSON.stringify(value));
}
function error(res, code, status = 400) {
  reply(res, { error: code }, status);
}
async function readJson(req) {
  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 65536) throw new Error("body_too_large");
  }
  try { return JSON.parse(body || "null"); } catch { return null; }
}
function currentUser(req) {
  const raw = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  if (!raw) return null;
  return db.prepare(`
    SELECT u.id, u.username, u.display_name
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled_at IS NULL
  `).get(sha(raw), now()) || null;
}
function createSession(userId) {
  const value = token();
  db.prepare("INSERT INTO sessions(id,user_id,token_hash,created_at,expires_at) VALUES(?,?,?,?,?)")
    .run(randomUUID(), userId, sha(value), now(), now() + 2592000);
  return value;
}

const server = createServer(async (req, res) => {
  if (req.method === "OPTIONS") {
    res.writeHead(204, headers);
    return res.end();
  }
  const url = new URL(req.url || "/", "http://localhost");
  const path = url.pathname;
  try {
    if (req.method === "GET" && path === "/health") {
      return reply(res, { ok: true, service: "kch-api", public: true });
    }

    if (req.method === "POST" && path === "/v1/auth/register") {
      const d = await readJson(req);
      if (!d || typeof d.username !== "string" || typeof d.password !== "string") {
        return error(res, "credentials_required");
      }
      const rawUsername = d.username;
      const rawPassword = d.password;
      if (!rawUsername.length) return error(res, "username_required");
      if (rawUsername.length < 4) return error(res, "username_too_short");
      if (rawUsername.length > 24) return error(res, "username_too_long");
      if (!/^[A-Za-z0-9_]+$/.test(rawUsername)) return error(res, "username_invalid_characters");
      if (!rawPassword.length) return error(res, "password_required");
      if (rawPassword.length < 6) return error(res, "password_too_short");
      if (rawPassword.length > 8) return error(res, "password_too_long");
      if (!/^[A-Za-z0-9_]+$/.test(rawPassword)) return error(res, "password_invalid_characters");
      const username = rawUsername.toLowerCase();
      if (db.prepare("SELECT id FROM users WHERE username = ?").get(username)) {
        return error(res, "username_taken", 409);
      }
      const id = randomUUID();
      const salt = token(16);
      const hash = await passHash(d.password, salt);
      try {
        db.prepare("INSERT INTO users(id,username,password_hash,password_salt,display_name,created_at) VALUES(?,?,?,?,?,?)")
          .run(id, username, hash, salt, username, now());
      } catch {
        return error(res, "could_not_create_account", 409);
      }
      return reply(res, { token: createSession(id), user: { id, username, displayName: username } }, 201);
    }

    if (req.method === "POST" && path === "/v1/auth/login") {
      const d = await readJson(req);
      if (!d || typeof d.username !== "string" || typeof d.password !== "string") {
        return error(res, "credentials_required");
      }
      const user = db.prepare("SELECT id,username,display_name,password_hash,password_salt FROM users WHERE username = ? AND disabled_at IS NULL")
        .get(d.username.toLowerCase());
      if (!user) return error(res, "invalid_credentials", 401);
      const actual = Buffer.from(await passHash(d.password, user.password_salt), "hex");
      const expected = Buffer.from(user.password_hash, "hex");
      if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
        return error(res, "invalid_credentials", 401);
      }
      return reply(res, {
        token: createSession(user.id),
        user: { id: user.id, username: user.username, displayName: user.display_name }
      });
    }

    const me = currentUser(req);
    if (!me) return error(res, "unauthorized", 401);

    if (req.method === "GET" && path === "/v1/me") {
      return reply(res, { id: me.id, username: me.username, displayName: me.display_name });
    }

    if (req.method === "GET" && path === "/v1/conversations") {
      const rows = db.prepare(`
        SELECT c.id,c.kind,c.title,c.created_at,m.role
        FROM conversation_members m JOIN conversations c ON c.id = m.conversation_id
        WHERE m.user_id = ? ORDER BY c.created_at DESC LIMIT 100
      `).all(me.id);
      return reply(res, { conversations: rows });
    }

    if (req.method === "POST" && path === "/v1/conversations") {
      const d = await readJson(req);
      if (!d || !["direct", "group", "channel"].includes(d.kind)) return error(res, "invalid_kind");
      const raw = Array.isArray(d.members) ? d.members.filter(x => typeof x === "string").slice(0, 49) : [];
      const members = [...new Set([me.id, ...raw])];
      if (d.kind === "direct" && members.length !== 2) return error(res, "direct_chat_requires_two_members");
      const placeholders = members.map(() => "?").join(",");
      const found = db.prepare(`SELECT id FROM users WHERE disabled_at IS NULL AND id IN (${placeholders})`).all(...members);
      if (found.length !== members.length) return error(res, "unknown_member", 404);
      const id = randomUUID();
      const title = typeof d.title === "string" ? d.title.slice(0, 80) : null;
      const create = db.transaction(() => {
        db.prepare("INSERT INTO conversations(id,kind,title,owner_user_id,created_at) VALUES(?,?,?,?,?)")
          .run(id, d.kind, title, me.id, now());
        const add = db.prepare("INSERT INTO conversation_members(conversation_id,user_id,role,joined_at) VALUES(?,?,?,?)");
        for (const uid of members) add.run(id, uid, uid === me.id ? "owner" : "member", now());
      });
      create();
      return reply(res, { id, kind: d.kind, title }, 201);
    }

    const match = path.match(/^\/v1\/conversations\/([0-9a-f-]+)\/messages$/i);
    if (match) {
      const conversationId = match[1];
      const member = db.prepare("SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ?")
        .get(conversationId, me.id);
      if (!member) return error(res, "not_found", 404);
      if (req.method === "GET") {
        const rows = db.prepare("SELECT id,sender_user_id,ciphertext,created_at FROM messages WHERE conversation_id = ? ORDER BY created_at DESC LIMIT 100")
          .all(conversationId).reverse();
        return reply(res, { messages: rows });
      }
      if (req.method === "POST") {
        const d = await readJson(req);
        if (!d || typeof d.ciphertext !== "string" || d.ciphertext.length < 16 || d.ciphertext.length > 20000) {
          return error(res, "ciphertext_required");
        }
        const id = randomUUID();
        const createdAt = now();
        db.prepare("INSERT INTO messages(id,conversation_id,sender_user_id,ciphertext,created_at) VALUES(?,?,?,?,?)")
          .run(id, conversationId, me.id, d.ciphertext, createdAt);
        return reply(res, { id, createdAt }, 201);
      }
    }
    return error(res, "not_found", 404);
  } catch (e) {
    if (e?.message === "body_too_large") return error(res, "request_too_large", 413);
    console.error("KCH API error:", e);
    return error(res, "server_error", 500);
  }
});

const port = Number(process.env.PORT || 3000);
server.listen(port, "0.0.0.0", () => {
  console.log(`K.C.H. API listening on 0.0.0.0:${port}; database: ${DB_PATH}`);
});
