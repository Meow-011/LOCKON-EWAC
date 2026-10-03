-- 017 — Bring cracked WPA passphrases under the credential vault.
--
-- Migration 012 moved every recovered credential in `credentials` behind
-- AES-256-GCM, and `database.ts` added the VACUUM that makes that real rather
-- than nominal — measured before the fix at 300 of 300 passwords still
-- readable from the file after sealing.
--
-- `cracking_history.cracked_password` was left out, and it holds exactly the
-- same kind of secret: the WPA passphrase hashcat recovered for a network the
-- organisation owns. It is written in cleartext, it is displayed in the
-- Decryptor's history table, and no amount of sealing the vault touched it. So
-- the vault's own banner — "no unprotected rows" — was true of one table and
-- false of the database, and an operator who sealed the vault and carried the
-- laptop off-site still had `strings ewac.db` handing over every cracked
-- passphrase.
--
-- Additive on purpose. `cracked_password` stays so existing rows are not lost;
-- `sealLegacyCrackingHistory()` migrates them under the operator's passphrase
-- the same way `sealLegacyCredentials()` does, because only the operator has
-- the key and a migration cannot.
--
-- enc_version: 0 = cleartext in `cracked_password` (legacy), 1 = AES-256-GCM in
-- `password_cipher`/`password_iv`. The same numbering as `credentials`, so one
-- meaning of "unprotected" applies across both tables.

ALTER TABLE cracking_history ADD COLUMN password_cipher TEXT;
ALTER TABLE cracking_history ADD COLUMN password_iv     TEXT;
ALTER TABLE cracking_history ADD COLUMN enc_version     INTEGER NOT NULL DEFAULT 0;

-- A run that recovered nothing has no secret to protect, and counting it as an
-- unprotected row would make the vault banner permanently alarming for the
-- normal case. Marked sealed up front so "unprotected" means what it says.
UPDATE cracking_history
   SET enc_version = 1
 WHERE cracked_password IS NULL OR cracked_password = '';

CREATE INDEX IF NOT EXISTS idx_cracking_enc ON cracking_history(enc_version);
