-- Cracking History: persist all decryption attempts
CREATE TABLE IF NOT EXISTS cracking_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pcap_file TEXT NOT NULL,
    ssid TEXT,
    bssid TEXT,
    encryption TEXT,
    wordlist TEXT NOT NULL,
    mangling_keywords TEXT,
    result TEXT NOT NULL CHECK (result IN ('SUCCESS', 'FAILED', 'ABORTED')),
    cracked_password TEXT,
    passwords_tested INTEGER DEFAULT 0,
    passwords_total INTEGER DEFAULT 0,
    duration_seconds REAL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
