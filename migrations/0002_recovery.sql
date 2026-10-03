CREATE TABLE IF NOT EXISTS recovery_tokens(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),expires INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS recovery_owner ON recovery_tokens(user_id);
CREATE TABLE IF NOT EXISTS recovery_attempts(key TEXT PRIMARY KEY,window INTEGER NOT NULL,attempts INTEGER NOT NULL);
