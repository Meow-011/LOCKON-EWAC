-- LOCKON EWAC — Credential vault encryption at rest
--
-- The vault stored recovered passwords in cleartext. The PDF masked them, but
-- the database file did not, so a laptop that left the engagement carried every
-- credential the audit recovered in a file anyone could open with sqlite3.
--
-- Secrets now live in `password_cipher` (AES-256-GCM) with a per-row nonce in
-- `password_iv`. The key is derived from an operator passphrase via PBKDF2 and
-- is only ever held in memory — nothing in this schema can recover a password
-- without it, by design.
--
-- `password` is made nullable because "the secret is not stored in the clear"
-- has to be representable. Legacy rows written before this migration keep their
-- cleartext and are marked `enc_version = 0`: the vault reports them as
-- unprotected rather than implying the whole store is encrypted, and sealing
-- them is a one-time operator action once a passphrase exists.
--
-- SQLite cannot drop a NOT NULL constraint in place, so the table is rebuilt.

CREATE TABLE credentials_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    service TEXT NOT NULL,
    username TEXT NOT NULL,
    -- Cleartext. NULL for any row written after this migration.
    password TEXT,
    -- base64(AES-256-GCM ciphertext || 128-bit tag)
    password_cipher TEXT,
    -- base64(96-bit nonce), unique per row
    password_iv TEXT,
    -- 0 = cleartext legacy row, 1 = AES-256-GCM
    enc_version INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT 'manual',  -- 'bruteforce' | 'default_check' | 'spray' | 'manual'
    session_id TEXT,
    hostname TEXT,
    notes TEXT,
    discovered_at TEXT DEFAULT (datetime('now'))
);

INSERT INTO credentials_new (
    id, target_ip, port, service, username, password, enc_version,
    source, session_id, hostname, notes, discovered_at
)
SELECT
    id, target_ip, port, service, username, password, 0,
    source, session_id, hostname, notes, discovered_at
FROM credentials;

DROP TABLE credentials;
ALTER TABLE credentials_new RENAME TO credentials;

CREATE INDEX IF NOT EXISTS idx_credentials_target ON credentials(target_ip, port);
CREATE INDEX IF NOT EXISTS idx_credentials_session ON credentials(session_id);
-- The vault banner counts unprotected rows on every open.
CREATE INDEX IF NOT EXISTS idx_credentials_enc ON credentials(enc_version);

-- One row, id forced to 1. The KDF parameters are stored rather than hardcoded
-- so a future iteration-count increase does not lock the operator out of a vault
-- created under the old cost.
--
-- `verifier_cipher` is a known constant encrypted under the derived key. Without
-- it a wrong passphrase would simply produce garbage plaintext, and the operator
-- would be told their credentials were corrupted rather than that they mistyped.
CREATE TABLE IF NOT EXISTS vault_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    kdf TEXT NOT NULL,                  -- e.g. 'PBKDF2-SHA256'
    iterations INTEGER NOT NULL,
    salt TEXT NOT NULL,                 -- base64, 128-bit
    verifier_cipher TEXT NOT NULL,      -- base64, encrypted known constant
    verifier_iv TEXT NOT NULL,          -- base64, 96-bit nonce
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    legacy_sealed_at TEXT               -- when pre-existing cleartext rows were encrypted
);
