import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export function openVaultDatabase(dbPath: string): DatabaseSync {
  if (dbPath !== ':memory:') {
    const dir = path.dirname(dbPath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  const db = new DatabaseSync(dbPath);

  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
    PRAGMA temp_store = MEMORY;
  `);

  runMigrations(db);
  return db;
}

function runMigrations(db: DatabaseSync): void {
  db.exec(`
    -- Single-row table enforcing that ONLY ONE administrator user can ever exist (CHECK id = 1)
    CREATE TABLE IF NOT EXISTS admin_config (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      vault_name TEXT NOT NULL DEFAULT 'PrivateSpace',
      kdf_salt BLOB NOT NULL,
      kdf_params TEXT NOT NULL,
      auth_verifier BLOB NOT NULL,
      wrapped_dek_iv BLOB NOT NULL,
      wrapped_dek_tag BLOB NOT NULL,
      wrapped_dek_ciphertext BLOB NOT NULL,
      key_fingerprint TEXT NOT NULL,
      sync_seq INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      password_updated_at TEXT NOT NULL
    );

    -- Active multi-device sessions (Web, iOS, Android, API)
    -- Stores session DEK wrapped with ephemeral runtime secret + client token secret
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      token_hash BLOB NOT NULL,
      device_name TEXT NOT NULL,
      platform TEXT NOT NULL DEFAULT 'web',
      ip_address TEXT NOT NULL DEFAULT '',
      wrapped_dek_iv BLOB NOT NULL,
      wrapped_dek_tag BLOB NOT NULL,
      wrapped_dek_ciphertext BLOB NOT NULL,
      created_at TEXT NOT NULL,
      last_active_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

    -- Unified encrypted vault items table ('note' | 'password' | 'image' | 'video')
    -- Sensitive fields (titles, passwords, TOTP secrets, filenames, tags, media metadata)
    -- exist ONLY inside AES-256-GCM ciphertext
    CREATE TABLE IF NOT EXISTS vault_items (
      id TEXT PRIMARY KEY,
      item_type TEXT NOT NULL DEFAULT 'note',
      is_pinned INTEGER NOT NULL DEFAULT 0,
      is_archived INTEGER NOT NULL DEFAULT 0,
      is_trashed INTEGER NOT NULL DEFAULT 0,
      revision INTEGER NOT NULL DEFAULT 1,
      sync_seq INTEGER NOT NULL,
      cipher_version INTEGER NOT NULL DEFAULT 1,
      item_salt BLOB NOT NULL,
      nonce BLOB NOT NULL,
      auth_tag BLOB NOT NULL,
      ciphertext BLOB NOT NULL,
      byte_size INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      trashed_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_vault_items_type_updated
      ON vault_items(item_type, is_trashed, is_pinned DESC, updated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_vault_items_sync_seq
      ON vault_items(sync_seq);

    -- Encrypted chunked media blob key envelopes (.psenc files on disk)
    -- Contains zero cleartext filenames, titles, dimensions, or user tags
    CREATE TABLE IF NOT EXISTS media_blobs (
      item_id TEXT PRIMARY KEY REFERENCES vault_items(id) ON DELETE CASCADE,
      blob_id TEXT NOT NULL,
      fek_salt BLOB NOT NULL,
      fek_nonce BLOB NOT NULL,
      fek_tag BLOB NOT NULL,
      wrapped_fek BLOB NOT NULL,
      base_nonce BLOB NOT NULL,
      chunk_size INTEGER NOT NULL,
      chunk_count INTEGER NOT NULL,
      plain_size INTEGER NOT NULL,
      encrypted_size INTEGER NOT NULL,
      sha256_hex TEXT NOT NULL,
      thumb_blob_id TEXT,
      thumb_fek_salt BLOB,
      thumb_fek_nonce BLOB,
      thumb_fek_tag BLOB,
      thumb_wrapped_fek BLOB,
      thumb_base_nonce BLOB,
      thumb_chunk_size INTEGER,
      thumb_chunk_count INTEGER,
      thumb_plain_size INTEGER,
      thumb_encrypted_size INTEGER
    );

    -- Encrypted albums / collections for images and videos
    CREATE TABLE IF NOT EXISTS media_albums (
      id TEXT PRIMARY KEY,
      revision INTEGER NOT NULL DEFAULT 1,
      sync_seq INTEGER NOT NULL,
      cipher_version INTEGER NOT NULL DEFAULT 1,
      item_salt BLOB NOT NULL,
      nonce BLOB NOT NULL,
      auth_tag BLOB NOT NULL,
      ciphertext BLOB NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_media_albums_sync_seq ON media_albums(sync_seq);

    -- Resumable chunked upload sessions for large 4K/1080p videos & high-res photos
    CREATE TABLE IF NOT EXISTS upload_sessions (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL,
      chunk_bytes INTEGER NOT NULL,
      total_bytes INTEGER NOT NULL,
      total_chunks INTEGER NOT NULL,
      received_chunks_json TEXT NOT NULL DEFAULT '[]',
      meta_salt BLOB NOT NULL,
      meta_nonce BLOB NOT NULL,
      meta_tag BLOB NOT NULL,
      meta_ciphertext BLOB NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );

    -- Tombstone log so mobile/web clients doing incremental delta sync know which items were permanently shredded
    CREATE TABLE IF NOT EXISTS sync_tombstones (
      id TEXT PRIMARY KEY,
      item_type TEXT NOT NULL,
      sync_seq INTEGER NOT NULL,
      deleted_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_sync_tombstones_seq ON sync_tombstones(sync_seq);
  `);
}
