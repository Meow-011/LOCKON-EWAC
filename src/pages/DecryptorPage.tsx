import { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { open as openFileDialog } from '@tauri-apps/plugin-dialog';
import { engineIPC } from '../lib/ipc';
import { useUIStore } from '../stores/uiStore';
import { useEngineStore } from '../stores/engineStore';
import { saveCrackingRecord, getCrackingHistory, deleteCrackingRecord,
         revealCrackedPassword, type CrackingRecord } from '../lib/crackingDB';
import { isUnlocked, onVaultLockChange, VaultLockedError } from '../lib/vaultCrypto';

type CrackingState = 'IDLE' | 'CRACKING' | 'SUCCESS' | 'FAILED' | 'ABORTED';

/** Placeholder for a value the engine did not report. Never a fake number. */
const NA = '—';

/** One hashcat target line as reported in `decrypt_started.targets`. */
interface DecryptTarget {
  hash_mode: string;
  bssid?: string;
  client?: string;
  essid?: string;
}

/**
 * Everything the engine told us about the run, captured from `decrypt_started`.
 * `decrypt_started` is only emitted once every precondition passed, so a null
 * value here means hashcat never ran — nothing about the target is known.
 */
interface StartedInfo {
  file: string;
  simulated: boolean;
  wordlist: string;
  wordlist_path: string;
  hash_count?: number;
  essid: string | null;
  bssid: string | null;
  hash_mode: string | null;
  targets: DecryptTarget[];
  hashcat_path?: string;
  hashcat_version?: string;
  command: string[];
  mangling?: string;
  mangling_applied?: boolean;
  mangling_note?: string;
}

/**
 * A single `decrypt_progress` tick. EVERY field is optional — hashcat omits
 * what it has not measured (no hash rate while autotuning, no temperature on
 * a CPU-only device). Absent fields render as a dash; they are never filled in.
 */
interface ProgressStats {
  progress?: number;
  tested?: number;
  total?: number;
  hashes_per_sec?: number;
  device?: string;
  temperature_c?: number;
  eta_seconds?: number;
  eta?: string;
  recovered?: number;
  hashes_total?: number;
  status?: string;
}

interface HashcatStatus {
  installed: boolean;
  version?: string;
  path?: string;
  error?: string;
}

interface RunError {
  reason: string;
  message: string;
  searched?: string[];
  file?: string;
  exit_code?: number;
  output?: string;
}

const BSSID_RE = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;

const asNumber = (v: unknown): number | undefined =>
  typeof v === 'number' && Number.isFinite(v) ? v : undefined;

const asString = (v: unknown): string | undefined =>
  typeof v === 'string' && v.length > 0 ? v : undefined;

const asStringOrNull = (v: unknown): string | null =>
  typeof v === 'string' && v.length > 0 ? v : null;

/** Format a raw H/s figure. Only ever called with a number hashcat reported. */
function formatRate(hs: number): string {
  if (hs >= 1_000_000_000) return `${(hs / 1_000_000_000).toFixed(2)} GH/s`;
  if (hs >= 1_000_000) return `${(hs / 1_000_000).toFixed(2)} MH/s`;
  if (hs >= 1_000) return `${(hs / 1_000).toFixed(1)} kH/s`;
  return `${hs} H/s`;
}

export function DecryptorPage() {
  const navigate = useNavigate();
  const { capturedPcapFile } = useUIStore();
  const { wordlists } = useEngineStore();
  const [crackingState, setCrackingState] = useState<CrackingState>('IDLE');

  /**
   * FULL filesystem path of the capture — the engine opens this path directly,
   * so a bare basename (all a browser <input type="file"> can expose) will come
   * straight back as a `pcap_missing` error.
   *
   * The picker uses `open()` from `@tauri-apps/plugin-dialog`, which returns a
   * real absolute path. A browser `<input type="file">` cannot: it exposes only
   * the basename, which came straight back as `pcap_missing` and left the
   * operator hand-typing the directory on the one path that turns a captured
   * handshake into evidence.
   */
  const [pcapPath, setPcapPath] = useState<string>(capturedPcapFile ?? '');
  /** Set when the native picker itself failed, so the operator is not left guessing. */
  const [pickError, setPickError] = useState<string | null>(null);

  const [wordlist, setWordlist] = useState<string>('default-passwords.txt');
  const [logs, setLogs] = useState<string[]>([]);
  const terminalRef = useRef<HTMLDivElement>(null);

  // Custom Dropdown State
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Mangling keywords — kept as an operator note; the hashcat backend does NOT
  // apply them (see `mangling_applied` / `mangling_note` from the engine).
  const [targetKeywords, setTargetKeywords] = useState('');
  const [manglingEnabled, setManglingEnabled] = useState(false);

  // PMKID target (inline input — window.prompt is not reliable in Tauri webviews)
  const [pmkidBssid, setPmkidBssid] = useState('');
  /**
   * Whether a PMKID capture is listening.
   *
   * There was no way to stop one. The button fired a 30-second listen and the
   * engine supported `stop_pmkid` all along — the command was simply never
   * sent, so an operator who realised they had typed the wrong BSSID had to
   * wait it out.
   */
  const [pmkidListening, setPmkidListening] = useState(false);
  const pmkidBssidValid = BSSID_RE.test(pmkidBssid.trim());

  /** Live stats, replaced wholesale on every tick so a stale value is never shown. */
  const [stats, setStats] = useState<ProgressStats>({});
  const [started, setStarted] = useState<StartedInfo | null>(null);
  const [runError, setRunError] = useState<RunError | null>(null);
  const [crackedPassword, setCrackedPassword] = useState<string | null>(null);
  const [failureMessage, setFailureMessage] = useState<string | null>(null);

  /** null = not checked yet (engine may still be connecting). */
  const [hashcatStatus, setHashcatStatus] = useState<HashcatStatus | null>(null);

  // Cracking History
  const [history, setHistory] = useState<CrackingRecord[]>([]);
  /*
    Decrypted passphrases, held only in component state.

    Keyed by row id, and rebuilt whenever the history reloads or the vault is
    locked or unlocked. A row with no entry renders as withheld rather than as
    an empty password: "the run recovered nothing" and "the vault is locked"
    are opposite statements about the same network.
  */
  const [revealed, setRevealed] = useState<Record<number, { password: string | null; reason: string }>>({});
  const [showHistory, setShowHistory] = useState(false);

  const startedRef = useRef<StartedInfo | null>(null);
  const startTimeRef = useRef<number>(0);
  const testedRef = useRef(0);
  const totalRef = useRef(0);
  const lastProgressLogRef = useRef(0);
  const hashcatCheckTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Close dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  useEffect(() => {
    if (capturedPcapFile && !pcapPath) {
      setPcapPath(capturedPcapFile);
    }
  }, [capturedPcapFile]);

  const addLog = useCallback((msg: string) => {
    setLogs(prev => [...prev.slice(-199), msg]); // Keep last 200 lines
  }, []);

  const handlePickFile = async () => {
    setPickError(null);
    try {
      const picked = await openFileDialog({
        multiple: false,
        directory: false,
        title: 'Select a capture containing the handshake',
        filters: [{ name: 'Capture', extensions: ['pcap', 'cap', 'pcapng', 'hccapx'] }],
      });
      // `null` is a cancelled dialog, not a failure — leave the field alone.
      if (typeof picked === 'string') setPcapPath(picked);
    } catch (e) {
      setPickError(e instanceof Error ? e.message : String(e));
    }
  };

  // Load history on mount
  useEffect(() => {
    getCrackingHistory().then(setHistory).catch(console.error);
  }, []);

  /*
    Decrypt the passphrases for whatever history is on screen.

    Re-runs when the history changes and when the vault is locked or unlocked,
    so locking the vault blanks the column immediately rather than leaving
    already-decrypted secrets rendered until the next reload. The plaintext
    never leaves this component's state.
  */
  useEffect(() => {
    let cancelled = false;

    const refresh = async () => {
      const next: Record<number, { password: string | null; reason: string }> = {};
      for (const row of history) {
        try {
          next[row.id] = await revealCrackedPassword(row);
        } catch (err) {
          console.error('[Vault] could not read a stored passphrase:', err);
          next[row.id] = { password: null, reason: 'undecryptable' };
        }
      }
      if (!cancelled) setRevealed(next);
    };

    refresh();
    const unsubscribe = onVaultLockChange(() => { refresh(); });
    return () => { cancelled = true; unsubscribe(); };
  }, [history]);

  // hashcat availability gate — ask the engine on mount.
  useEffect(() => {
    let attempt = 0;
    let cancelled = false;

    const ask = () => {
      engineIPC.send('check_hashcat').catch(() => {
        // Engine sidecar may not be connected yet; retry a couple of times.
        if (cancelled || attempt >= 3) return;
        attempt += 1;
        hashcatCheckTimerRef.current = setTimeout(ask, 1500 * attempt);
      });
    };
    ask();

    return () => {
      cancelled = true;
      if (hashcatCheckTimerRef.current) {
        clearTimeout(hashcatCheckTimerRef.current);
        hashcatCheckTimerRef.current = null;
      }
    };
  }, []);

  /**
   * Persist a finished run. Only ever called with values the engine reported.
   * Runs that never reached `decrypt_started` (no real hash, hashcat missing,
   * bad path...) are NOT written — there is no observed target to record.
   */
  const saveHistory = useCallback(async (
    result: 'SUCCESS' | 'FAILED' | 'ABORTED',
    opts: { password?: string | null; tested?: number; total?: number; duration?: number } = {}
  ) => {
    const info = startedRef.current;
    if (!info) return;

    // Prefer the engine's own duration; otherwise measure the wall clock since
    // `decrypt_started` (real elapsed time, not an estimate).
    const duration = opts.duration ?? (startTimeRef.current
      ? (Date.now() - startTimeRef.current) / 1000
      : 0);

    try {
      await saveCrackingRecord({
        pcap_file: info.file,
        ssid: info.essid,
        bssid: info.bssid,
        encryption: info.hash_mode,
        wordlist: info.wordlist,
        // Mangling is reported as not applied by the engine, so it is not
        // recorded as if it had shaped the attack.
        mangling_keywords: info.mangling_applied ? (info.mangling ?? null) : null,
        result,
        cracked_password: opts.password ?? null,
        passwords_tested: opts.tested ?? testedRef.current,
        passwords_total: opts.total ?? totalRef.current,
        duration_seconds: Math.round(duration),
        is_simulated: info.simulated ? 1 : 0
      });
      const updated = await getCrackingHistory();
      setHistory(updated);
    } catch (err) {
      console.error('[DB] save cracking record error:', err);
      /*
        A locked vault is not a storage error to log and move past.

        The passphrase exists right now, in this process, and nowhere else.
        There is deliberately no cleartext fallback, so if the operator does not
        act on this the recovered credential is gone when the page unmounts —
        and a crack that takes hours is not something to lose quietly to a
        `console.error`.
      */
      const locked = err instanceof VaultLockedError;
      window.dispatchEvent(new CustomEvent('lockon:toast', {
        detail: {
          message: locked
            ? 'A passphrase was recovered but the credential vault is LOCKED, so it was not saved. '
              + 'Unlock the vault now — this result is only held in memory.'
            : `The cracking run could not be recorded: ${err instanceof Error ? err.message : String(err)}`,
          type: 'error',
        },
      }));
    }
  }, []);

  // IPC Listeners
  useEffect(() => {
    const unsubHashcatStatus = engineIPC.on('hashcat_status', (msg) => {
      const d = msg.data as Record<string, unknown>;
      const status: HashcatStatus = {
        installed: d.installed === true,
        version: asString(d.version),
        path: asString(d.path),
        error: asString(d.error)
      };
      setHashcatStatus(status);
      addLog(status.installed
        ? `[SYS] HASHCAT AVAILABLE${status.version ? ` — ${status.version.split('\n')[0]}` : ''}${status.path ? ` @ ${status.path}` : ' (on PATH)'}`
        : `[ERROR] HASHCAT NOT FOUND${status.error ? ` — ${status.error}` : ''}`);
    });

    const unsubStart = engineIPC.on('decrypt_started', (msg) => {
      const d = msg.data as Record<string, unknown>;
      const info: StartedInfo = {
        file: asString(d.file) ?? '',
        simulated: d.simulated === true,
        wordlist: asString(d.wordlist) ?? '',
        wordlist_path: asString(d.wordlist_path) ?? '',
        hash_count: asNumber(d.hash_count),
        essid: asStringOrNull(d.essid),
        bssid: asStringOrNull(d.bssid),
        hash_mode: asStringOrNull(d.hash_mode),
        targets: Array.isArray(d.targets) ? (d.targets as DecryptTarget[]) : [],
        hashcat_path: asString(d.hashcat_path),
        hashcat_version: asString(d.hashcat_version),
        command: Array.isArray(d.command) ? (d.command as string[]) : [],
        mangling: asString(d.mangling),
        mangling_applied: typeof d.mangling_applied === 'boolean' ? d.mangling_applied : undefined,
        mangling_note: asString(d.mangling_note)
      };

      startedRef.current = info;
      setStarted(info);
      setCrackingState('CRACKING');
      setStats({});
      setRunError(null);
      setFailureMessage(null);
      setCrackedPassword(null);
      testedRef.current = 0;
      totalRef.current = 0;
      lastProgressLogRef.current = 0;
      startTimeRef.current = Date.now();

      const lines: string[] = [
        `[SYS] TARGET FILE: ${info.file}`,
        `[SYS] HASHES EXTRACTED: ${info.hash_count ?? NA}${info.hash_mode ? ` (${info.hash_mode})` : ''}`,
        `[SYS] TARGET: ESSID=${info.essid ?? NA} BSSID=${info.bssid ?? NA}`,
        `[SYS] DICTIONARY: ${info.wordlist}${info.wordlist_path ? ` (${info.wordlist_path})` : ''}`,
        `[SYS] HASHCAT: ${info.hashcat_path ?? NA}${info.hashcat_version ? ` — ${info.hashcat_version.split('\n')[0]}` : ''}`
      ];
      if (info.command.length) lines.push(`[SYS] CMD: ${info.command.join(' ')}`);
      if (info.mangling && info.mangling_applied === false) {
        lines.push(`[WARN] MANGLING NOT APPLIED: ${info.mangling_note ?? 'unsupported by the hashcat backend'}`);
      }
      lines.push('[SYS] HASHCAT RUNNING.');
      setLogs(prev => [...prev.slice(-100), ...lines]);
    });

    const unsubProgress = engineIPC.on('decrypt_progress', (msg) => {
      const d = msg.data as Record<string, unknown>;
      const next: ProgressStats = {
        progress: asNumber(d.progress),
        tested: asNumber(d.tested),
        total: asNumber(d.total),
        hashes_per_sec: asNumber(d.hashes_per_sec),
        device: asString(d.device),
        temperature_c: asNumber(d.temperature_c),
        eta_seconds: asNumber(d.eta_seconds),
        eta: asString(d.eta),
        recovered: asNumber(d.recovered),
        hashes_total: asNumber(d.hashes_total),
        status: asString(d.status)
      };
      setStats(next);
      if (next.tested !== undefined) testedRef.current = next.tested;
      if (next.total !== undefined) totalRef.current = next.total;

      // Log at most every 5s, and only fields hashcat actually reported.
      const now = Date.now();
      if (now - lastProgressLogRef.current >= 5000) {
        lastProgressLogRef.current = now;
        const parts: string[] = [];
        if (next.status) parts.push(next.status.toUpperCase());
        if (next.progress !== undefined) parts.push(`${next.progress.toFixed(2)}%`);
        if (next.tested !== undefined) {
          parts.push(`tested ${next.tested.toLocaleString()}${next.total ? `/${next.total.toLocaleString()}` : ''}`);
        }
        if (next.hashes_per_sec !== undefined) parts.push(formatRate(next.hashes_per_sec));
        if (next.eta) parts.push(`ETA ${next.eta}`);
        if (parts.length) addLog(`[CRACK] ${parts.join(' | ')}`);
      }
    });

    const unsubSuccess = engineIPC.on('decrypt_success', (msg) => {
      const d = msg.data as Record<string, unknown>;
      const password = asString(d.password) ?? '';
      const tested = asNumber(d.tested);
      const total = asNumber(d.total);
      const duration = asNumber(d.duration_seconds);
      if (tested !== undefined) testedRef.current = tested;
      if (total !== undefined) totalRef.current = total;

      setCrackingState('SUCCESS');
      setCrackedPassword(password);
      setStats(prev => ({
        ...prev,
        status: 'cracked',
        tested: tested ?? prev.tested,
        total: total ?? prev.total,
        progress: prev.progress
      }));
      addLog(`[CRACK] KEY RECOVERED: ${password}`);
      const results = Array.isArray(d.results) ? (d.results as Record<string, unknown>[]) : [];
      results.slice(1).forEach(r => {
        addLog(`[CRACK] ALSO RECOVERED: ${asString(r.password) ?? NA} (ESSID=${asString(r.essid) ?? NA})`);
      });
      if (duration !== undefined) addLog(`[SYS] RUN TIME: ${duration}s`);
      saveHistory('SUCCESS', { password, tested, total, duration });
    });

    const unsubFailed = engineIPC.on('decrypt_failed', (msg) => {
      const d = msg.data as Record<string, unknown>;
      const reason = asString(d.reason) ?? 'unknown';
      const message = asString(d.message) ?? 'Key recovery failed.';
      const tested = asNumber(d.tested);
      const total = asNumber(d.total);
      const duration = asNumber(d.duration_seconds);
      if (tested !== undefined) testedRef.current = tested;
      if (total !== undefined) totalRef.current = total;

      setCrackingState('FAILED');
      setFailureMessage(message);
      setStats(prev => ({ ...prev, tested: tested ?? prev.tested, total: total ?? prev.total, status: reason }));
      addLog(`[FAILED] ${message}`);
      // `no_hash_in_capture` fails before `decrypt_started`; saveHistory then
      // writes nothing, which is correct — no target was ever observed.
      saveHistory('FAILED', { tested, total, duration });
    });

    const unsubAborted = engineIPC.on('decrypt_aborted', (msg) => {
      const d = msg.data as Record<string, unknown>;
      const tested = asNumber(d.tested);
      const total = asNumber(d.total);
      const duration = asNumber(d.duration_seconds);
      if (tested !== undefined) testedRef.current = tested;
      if (total !== undefined) totalRef.current = total;

      setCrackingState('ABORTED');
      setFailureMessage(asString(d.message) ?? 'Aborted by operator.');
      setStats(prev => ({ ...prev, tested: tested ?? prev.tested, total: total ?? prev.total, status: 'aborted' }));
      addLog(`[SYS] ${asString(d.message) ?? 'OPERATION ABORTED BY OPERATOR.'}`);
      saveHistory('ABORTED', { tested, total, duration });
    });

    const unsubError = engineIPC.on('decrypt_error', (msg) => {
      const d = msg.data as Record<string, unknown>;
      const err: RunError = {
        reason: asString(d.reason) ?? 'unknown',
        message: asString(d.message) ?? 'Decrypt failed.',
        searched: Array.isArray(d.searched) ? (d.searched as string[]) : undefined,
        file: asString(d.file),
        exit_code: asNumber(d.exit_code),
        output: asString(d.output)
      };
      setCrackingState('FAILED');
      setRunError(err);
      addLog(`[ERROR] (${err.reason}) ${err.message}`);
      if (err.output) err.output.split('\n').slice(-5).forEach(l => addLog(`[HASHCAT] ${l}`));

      if (err.reason === 'hashcat_missing') {
        setHashcatStatus({ installed: false, error: err.message });
      }
      // Only recorded when hashcat had actually started on a real hash.
      saveHistory('FAILED');
    });

    // PMKID + Hashcat export listeners (terminal echo)
    const unsubPmkid = engineIPC.on('pmkid_captured', (msg) => {
      const d = msg.data as Record<string, unknown>;
      addLog(`[PMKID] CAPTURED — ESSID: ${asString(d.ssid) ?? NA} | BSSID: ${asString(d.bssid) ?? NA}`);
      if (asString(d.pmkid)) addLog(`[PMKID] HASH: ${asString(d.pmkid)}`);
      if (asString(d.output_file)) addLog(`[PMKID] FILE: ${asString(d.output_file)}`);
      setPmkidListening(false);
    });

    const unsubPmkidTimeout = engineIPC.on('pmkid_timeout', (msg) => {
      addLog(`[PMKID] TIMEOUT: ${asString((msg.data as Record<string, unknown>).message) ?? 'no PMKID observed'}`);
      setPmkidListening(false);
    });

    const unsubPmkidEapol = engineIPC.on('pmkid_eapol_seen', (msg) => {
      addLog(`[PMKID] EAPOL FRAME DETECTED (${asNumber((msg.data as Record<string, unknown>).count) ?? NA})`);
    });

    /*
      A capture that failed has to release the button.

      There were listeners for `pmkid_captured`, `pmkid_timeout` and
      `pmkid_eapol_seen` and none for `pmkid_error` or `pmkid_aborted`, while
      `setPmkidListening(false)` happened nowhere else on an engine event. The
      terminal case that reaches this is `capture.py`'s `_pmkid_worker` raising — a
      scapy, Npcap or monitor-mode failure — which emits `pmkid_error` and no
      `pmkid_timeout`. The button then read "LISTENING — CLICK TO STOP" indefinitely
      for a capture that had already stopped, and clicking it logged "STOPPED BY
      OPERATOR" about something that was never running.

      `engineRouter` raises a toast for `pmkid_error` but owns none of this state.
    */
    const unsubPmkidError = engineIPC.on('pmkid_error', (msg) => {
      addLog(`[PMKID] ERROR: ${asString((msg.data as Record<string, unknown>).message) ?? 'capture failed'}`);
      setPmkidListening(false);
    });

    const unsubPmkidAborted = engineIPC.on('pmkid_aborted', (msg) => {
      addLog(`[PMKID] ABORTED: ${asString((msg.data as Record<string, unknown>).message) ?? 'capture did not start'}`);
      setPmkidListening(false);
    });

    const unsubHashcatExport = engineIPC.on('hashcat_exported', (msg) => {
      const d = msg.data as Record<string, unknown>;
      addLog(`[HASHCAT] EXPORT COMPLETE: ${asNumber(d.hash_count) ?? NA} hash(es)`);
      if (asString(d.output_path)) addLog(`[HASHCAT] OUTPUT: ${asString(d.output_path)}`);
    });

    const unsubHashcatExportError = engineIPC.on('hashcat_export_error', (msg) => {
      addLog(`[ERROR] EXPORT FAILED: ${asString((msg.data as Record<string, unknown>).message) ?? 'unknown error'}`);
    });

    return () => {
      unsubHashcatStatus();
      unsubStart();
      unsubProgress();
      unsubSuccess();
      unsubFailed();
      unsubAborted();
      unsubError();
      unsubPmkid();
      unsubPmkidTimeout();
      unsubPmkidEapol();
      unsubPmkidError();
      unsubPmkidAborted();
      unsubHashcatExport();
      unsubHashcatExportError();
    };
  }, [addLog, saveHistory]);

  const hashcatMissing = hashcatStatus !== null && !hashcatStatus.installed;
  const canStart = pcapPath.trim().length > 0 && !hashcatMissing && crackingState !== 'CRACKING';

  const startCracking = () => {
    const path = pcapPath.trim();
    if (!path || hashcatMissing) return;
    startedRef.current = null;
    setStarted(null);
    setStats({});
    setRunError(null);
    setFailureMessage(null);
    setCrackedPassword(null);
    testedRef.current = 0;
    totalRef.current = 0;
    setCrackingState('CRACKING');
    /*
      Warned before the run, not after it.

      A recovered passphrase is stored through the credential vault and there is
      no cleartext fallback, so a locked vault means the result of a run that
      can take hours cannot be saved. Telling the operator at the end is telling
      them too late, and this is a warning rather than a refusal: an operator
      who wants the answer on screen without recording it is making a valid
      choice, as long as they are making it knowingly.
    */
    if (!isUnlocked()) {
      addLog('[WARN] THE CREDENTIAL VAULT IS LOCKED. A RECOVERED PASSPHRASE CANNOT BE SAVED.');
      window.dispatchEvent(new CustomEvent('lockon:toast', {
        detail: {
          message: 'The credential vault is locked. If this run recovers a passphrase it will be '
            + 'shown but not stored. Unlock the vault first to keep the result.',
          type: 'warning',
        },
      }));
    }
    addLog(`[SYS] DECRYPT REQUESTED → ${path}`);
    engineIPC.send('start_decrypt', {
      pcap_file: path,
      wordlist_name: wordlist,
      mangling: manglingEnabled && targetKeywords ? targetKeywords : null
    }).catch((err) => {
      // The engine cannot emit a terminal event for a request it never got.
      setCrackingState('FAILED');
      setRunError({ reason: 'ipc_send_failed', message: String(err) });
      addLog(`[ERROR] COULD NOT REACH ENGINE: ${String(err)}`);
    });
  };

  const abortCracking = () => {
    addLog('[SYS] ABORT REQUESTED...');
    engineIPC.send('stop_decrypt').catch((err) => {
      setCrackingState('ABORTED');
      addLog(`[ERROR] ABORT REQUEST FAILED: ${String(err)}`);
    });
  };

  const statusLabel = stats.status ? stats.status.toUpperCase() : NA;

  return (
    <div className="h-full flex flex-col overflow-y-auto no-scrollbar pb-4">
      <div className="flex flex-col xl:flex-row gap-4 flex-1 min-h-0">
      {/* Left Panel: Configuration */}
      <div className="xl:w-1/3 flex flex-col gap-4">
        {/* Header */}
        <div className="glass-card p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-neon-500/20 flex items-center justify-center border border-neon-500/50">
              <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5 text-neon-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 9.9-1" />
              </svg>
            </div>
            <div>
              <h1 className="text-lg font-bold text-tactical tracking-widest text-white">DECRYPTOR</h1>
              <p className="text-xs font-mono text-gray-400">OFFLINE HANDSHAKE CRACKING — HASHCAT -m 22000</p>
            </div>
          </div>
        </div>

        {/* hashcat availability gate */}
        <div className={`glass-card p-3 border ${
          hashcatStatus === null ? 'border-space-500/30'
            : hashcatStatus.installed ? 'border-signal-strong/40 bg-signal-strong/5'
            : 'border-risk-critical/50 bg-risk-critical/10'
        }`}>
          <div className="flex items-center justify-between gap-2">
            <span className="text-[10px] font-tactical tracking-widest text-gray-400">HASHCAT BACKEND</span>
            <span className={`text-[10px] font-tactical tracking-widest px-1.5 py-0.5 rounded border ${
              hashcatStatus === null ? 'text-gray-400 border-space-500/40 bg-space-800'
                : hashcatStatus.installed ? 'text-signal-strong border-signal-strong/40 bg-signal-strong/10'
                : 'text-risk-critical border-risk-critical/40 bg-risk-critical/10'
            }`}>
              {hashcatStatus === null ? 'CHECKING…' : hashcatStatus.installed ? 'AVAILABLE' : 'NOT FOUND'}
            </span>
          </div>
          {hashcatStatus?.installed && (
            <div className="mt-1.5 text-[10px] font-mono text-gray-500 break-all">
              {hashcatStatus.version ? hashcatStatus.version.split('\n')[0] : 'version not reported'}
              {hashcatStatus.path ? ` @ ${hashcatStatus.path}` : ' (resolved on PATH)'}
            </div>
          )}
          {hashcatMissing && (
            <div className="mt-1.5 flex flex-col gap-1">
              {hashcatStatus?.error && (
                <div className="text-[10px] font-mono text-risk-critical break-all">{hashcatStatus.error}</div>
              )}
              {runError?.reason === 'hashcat_missing' && runError.searched?.length ? (
                <div className="text-[9px] font-mono text-gray-500 leading-relaxed">
                  SEARCHED:
                  {runError.searched.map(p => (
                    <span key={p} className="block pl-2 text-gray-400 break-all">{p}</span>
                  ))}
                </div>
              ) : (
                <div className="text-[9px] font-mono text-gray-500">
                  Searched PATH and the engine's common install locations.
                </div>
              )}
              <div className="text-[9px] font-mono text-amber-400 leading-relaxed">
                INSTALL HINT: download hashcat from hashcat.net and put hashcat.exe on PATH or in C:\hashcat\.
              </div>
            </div>
          )}
          {hashcatStatus === null && (
            <div className="mt-1.5 text-[9px] font-mono text-gray-500">
              Waiting for the engine to report hashcat availability.
            </div>
          )}
        </div>

        {/* Configuration Form */}
        <div className="glass-card p-4 flex-1 flex flex-col gap-5 border border-space-500/20">
          <div>
             <label className="block text-xs font-tactical tracking-widest text-gray-400 mb-2">TARGET FILE — FULL PATH (.PCAP)</label>
             <input
               type="text"
               value={pcapPath}
               onChange={(e) => { setPcapPath(e.target.value); setPickError(null); }}
               placeholder="C:\captures\handshake.pcap"
               spellCheck={false}
               disabled={crackingState === 'CRACKING'}
               className="w-full bg-space-900 border border-space-500/30 rounded p-2.5 text-xs font-mono text-white placeholder-gray-600 focus:border-neon-500/50 focus:outline-none disabled:opacity-50"
             />
             <div className="mt-2 flex items-center gap-2">
               <button
                 type="button"
                 onClick={handlePickFile}
                 disabled={crackingState === 'CRACKING'}
                 className="flex items-center gap-2 px-2.5 py-1.5 rounded border border-dashed border-space-500/50 bg-space-800/50 hover:bg-space-700/50 cursor-pointer text-[10px] font-tactical tracking-wider text-gray-400 disabled:opacity-50 disabled:pointer-events-none"
               >
                 <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                 BROWSE
               </button>
               <span className="text-[9px] font-mono text-gray-600">the engine opens this path itself</span>
             </div>
             {pickError && (
               <div className="mt-2 text-[9px] font-mono text-amber-400 leading-relaxed">
                 The file picker could not open (<span className="text-risk-critical">{pickError}</span>). Type the full
                 path in the field above instead.
               </div>
             )}
             {runError && (runError.reason === 'pcap_missing' || runError.reason === 'pcap_unreadable') && (
               <div className="mt-2 p-2 rounded border border-risk-critical/50 bg-risk-critical/10">
                 <div className="text-[9px] font-tactical tracking-widest text-risk-critical mb-0.5">{runError.reason.toUpperCase()}</div>
                 <div className="text-[10px] font-mono text-risk-critical break-all">{runError.message}</div>
               </div>
             )}
          </div>

          <div className="relative" ref={dropdownRef}>
            <label className="block text-xs font-tactical tracking-widest text-gray-400 mb-2">DICTIONARY (SECLISTS)</label>

            {/* Selected Value Box */}
            <button
              onClick={() => crackingState !== 'CRACKING' && setIsDropdownOpen(!isDropdownOpen)}
              disabled={crackingState === 'CRACKING'}
              className="w-full bg-space-900 border border-space-500/30 rounded p-3 text-left flex items-center justify-between transition-colors hover:border-space-500/50 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <div className="flex flex-col gap-0.5 overflow-hidden">
                <span className="text-sm font-mono text-gray-300 truncate">{wordlist}</span>
                <span className="text-[10px] font-mono text-gray-500">
                  {wordlist === 'custom' ? 'Local File' : 'SecLists Arsenal'}
                </span>
              </div>
              <svg xmlns="http://www.w3.org/2000/svg" className={`w-4 h-4 text-gray-500 transition-transform ${isDropdownOpen ? 'rotate-180' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
            </button>

            {/* Dropdown Menu */}
            <AnimatePresence>
              {isDropdownOpen && (
                <motion.div
                  initial={{ opacity: 0, y: -5 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -5 }}
                  transition={{ duration: 0.15 }}
                  className="absolute left-0 right-0 top-full mt-2 z-50 bg-space-900 border border-space-500/30 rounded shadow-2xl overflow-hidden flex flex-col max-h-[300px]"
                >
                  <div className="overflow-y-auto p-1 scrollbar-thin">
                    <div className="px-3 py-2">
                      <div className="text-[10px] font-tactical tracking-widest text-gray-500 mb-1 border-b border-space-500/20 pb-1">AVAILABLE DICTIONARIES</div>
                      {wordlists.length === 0 ? (
                        <div className="text-[10px] text-gray-500 py-2">No wordlists available</div>
                      ) : (
                        wordlists.map(w => (
                          <button
                            key={w.name}
                            onClick={() => { setWordlist(w.name); setIsDropdownOpen(false); }}
                            className="w-full text-left px-2 py-1.5 rounded hover:bg-space-800 transition-colors group flex items-center justify-between"
                          >
                            <span className="text-xs font-mono text-gray-300 group-hover:text-white">{w.name.replace('.txt', '')}</span>
                            <span className="text-[10px] font-mono text-gray-600">{(w.size / 1024).toFixed(0)}KB</span>
                          </button>
                        ))
                      )}
                    </div>
                  </div>

                  {/* CUSTOM UPLOAD ACTION */}
                  <div className="p-2 border-t border-space-500/30 bg-space-950/50">
                    <button
                      onClick={() => {
                        setIsDropdownOpen(false);
                        navigate('/settings');
                      }}
                      className="w-full flex items-center justify-center gap-2 py-2 bg-space-800 hover:bg-space-700 text-gray-300 hover:text-white rounded transition-colors text-xs font-tactical tracking-wider border border-space-500/30"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                      UPLOAD CUSTOM WORDLIST
                    </button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Target Profiling / Mangling — recorded as an operator note only */}
          <div className="p-3 bg-space-950/50 border border-space-500/20 rounded">
            <div className="flex items-center justify-between mb-2">
              <label className="block text-[10px] font-tactical tracking-widest text-gray-400">KEYWORD MANGLING (NOT APPLIED)</label>
              <button
                onClick={() => setManglingEnabled(!manglingEnabled)}
                disabled={crackingState === 'CRACKING'}
                className={`w-8 h-4 rounded-full transition-colors relative ${manglingEnabled ? 'bg-neon-500' : 'bg-space-700'}`}
              >
                <div className={`absolute top-[2px] bottom-[2px] w-3 rounded-full bg-white transition-all ${manglingEnabled ? 'left-[18px]' : 'left-[2px]'}`} />
              </button>
            </div>

            <AnimatePresence>
              {manglingEnabled && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  className="overflow-hidden"
                >
                  <input
                    type="text"
                    placeholder="Keywords e.g. Starbucks, 2024, BKK..."
                    value={targetKeywords}
                    onChange={(e) => setTargetKeywords(e.target.value)}
                    className="w-full bg-space-900 border border-space-500/30 rounded p-2 text-sm text-white placeholder-gray-600 focus:border-neon-500/50 focus:outline-none mb-2"
                    disabled={crackingState === 'CRACKING'}
                  />
                  <div className="text-[9px] font-mono text-amber-400 leading-relaxed">
                    The hashcat backend does NOT generate permutations from these keywords — the wordlist is used
                    as-is. Keywords are only passed through so the engine can report them back.
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
            {started?.mangling && started.mangling_applied === false && (
              <div className="mt-2 p-2 rounded border border-amber-500/40 bg-amber-500/10">
                <div className="text-[9px] font-tactical tracking-widest text-amber-400 mb-0.5">MANGLING NOT APPLIED</div>
                <div className="text-[10px] font-mono text-gray-300 leading-relaxed">
                  {started.mangling_note ?? 'The engine reported that keyword mangling was not applied.'}
                </div>
              </div>
            )}
          </div>

          <div className="mt-auto flex flex-col gap-2">
            {/* PMKID Quick Capture — inline BSSID input (no window.prompt) */}
            <div className="p-2 bg-space-950/50 border border-space-500/20 rounded flex flex-col gap-2">
              <label className="block text-[10px] font-tactical tracking-widest text-gray-400">PMKID TARGET BSSID</label>
              <input
                type="text"
                value={pmkidBssid}
                onChange={(e) => setPmkidBssid(e.target.value.toUpperCase())}
                placeholder="AA:BB:CC:DD:EE:FF"
                spellCheck={false}
                disabled={crackingState === 'CRACKING'}
                className={`w-full bg-space-900 border rounded p-2 text-xs font-mono text-white placeholder-gray-600 focus:outline-none disabled:opacity-50
                  ${pmkidBssid.length === 0 ? 'border-space-500/30'
                    : pmkidBssidValid ? 'border-signal-strong/50' : 'border-risk-critical/60'}`}
              />
              {pmkidBssid.length > 0 && !pmkidBssidValid && (
                <div className="text-[9px] font-mono text-risk-critical">
                  Expected 6 hex pairs separated by colons, e.g. AA:BB:CC:DD:EE:FF
                </div>
              )}
              <button
                onClick={() => {
                  if (pmkidListening) {
                    engineIPC.send('stop_pmkid')
                      .then(() => addLog('[SYS] PMKID CAPTURE STOPPED BY OPERATOR'))
                      .catch((err) => addLog(`[ERROR] STOP FAILED: ${String(err)}`));
                    setPmkidListening(false);
                    return;
                  }
                  const bssid = pmkidBssid.trim();
                  if (!BSSID_RE.test(bssid)) return;
                  setPmkidListening(true);
                  engineIPC.send('start_pmkid_capture', { bssid, timeout: 30 })
                    .then(() => {
                      addLog(`[SYS] PMKID CAPTURE INITIATED → ${bssid}`);
                      addLog('[SYS] LISTENING FOR EAPOL M1 FRAMES (30s timeout)...');
                    })
                    .catch((err) => {
                      setPmkidListening(false);
                      addLog(`[ERROR] PMKID REQUEST FAILED: ${String(err)}`);
                    });
                }}
                disabled={(!pmkidBssidValid && !pmkidListening) || crackingState === 'CRACKING'}
                className={`w-full py-2.5 rounded-md font-tactical tracking-widest text-xs transition-all duration-300 border flex items-center justify-center gap-2
                  ${pmkidListening
                    ? 'bg-risk-high/20 text-risk-high border-risk-high/50 hover:bg-risk-high/40'
                    : (!pmkidBssidValid || crackingState === 'CRACKING'
                      ? 'bg-space-800 text-gray-500 border-space-500/30 cursor-not-allowed'
                      : 'bg-purple-500/15 text-purple-400 border-purple-500/50 hover:bg-purple-500 hover:text-white')
                  }
                `}
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 1v6M12 17v6M4.22 4.22l4.24 4.24M15.54 15.54l4.24 4.24M1 12h6M17 12h6M4.22 19.78l4.24-4.24M15.54 8.46l4.24-4.24"/></svg>
                {pmkidListening ? 'LISTENING — CLICK TO STOP' : 'PMKID CAPTURE'}
              </button>
            </div>

            {/* Hashcat Export */}
            <button
              onClick={() => {
                const path = pcapPath.trim();
                if (!path) return;
                engineIPC.send('export_hashcat', { pcap_path: path })
                  .then(() => addLog(`[SYS] EXPORTING HASHES → .hc22000 FORMAT...`))
                  .catch((err) => addLog(`[ERROR] EXPORT REQUEST FAILED: ${String(err)}`));
              }}
              disabled={!pcapPath.trim() || crackingState === 'CRACKING'}
              className={`w-full py-2.5 rounded-md font-tactical tracking-widest text-xs transition-all duration-300 border flex items-center justify-center gap-2
                ${!pcapPath.trim() || crackingState === 'CRACKING'
                  ? 'bg-space-800 text-gray-500 border-space-500/30 cursor-not-allowed'
                  : 'bg-amber-500/15 text-amber-400 border-amber-500/50 hover:bg-amber-500 hover:text-space-950'
                }
              `}
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              EXPORT TO HASHCAT
            </button>

            {/* Main Cracking Button */}
            <div className="flex gap-2">
            {crackingState === 'CRACKING' ? (
              <button
                onClick={abortCracking}
                className="w-full py-3 rounded-md font-tactical tracking-widest text-sm transition-all duration-300 border bg-risk-critical/20 text-risk-critical border-risk-critical hover:bg-risk-critical hover:text-white"
              >
                ⏹ ABORT OPERATION
              </button>
            ) : (
              <button
                onClick={startCracking}
                disabled={!canStart}
                title={hashcatMissing ? 'hashcat is not installed — see HASHCAT BACKEND above' : undefined}
                className={`w-full py-3 rounded-md font-tactical tracking-widest text-sm transition-all duration-300 border
                  ${!canStart
                    ? 'bg-space-800 text-gray-500 border-space-500/30 cursor-not-allowed'
                    : 'bg-neon-500/20 text-neon-400 border-neon-500 hover:bg-neon-500 hover:text-space-950'
                  }
                `}
              >
                {hashcatMissing ? 'HASHCAT REQUIRED' : 'INITIATE DECRYPTION'}
              </button>
            )}
            </div>
          </div>
        </div>
      </div>

      {/* Right Panel: Terminal Output & Results */}
      <div className="flex-1 flex flex-col gap-4">
        {/* Capture Identity — straight from decrypt_started */}
        <AnimatePresence>
          {started && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass-card p-4 border border-space-500/30 grid grid-cols-2 md:grid-cols-4 gap-4"
            >
              <div>
                <div className="text-[9px] font-tactical text-gray-500 mb-1">ESSID</div>
                <div className="text-sm font-mono text-white truncate">{started.essid ?? <span className="text-gray-600">{NA}</span>}</div>
              </div>
              <div>
                <div className="text-[9px] font-tactical text-gray-500 mb-1">BSSID</div>
                <div className="text-sm font-mono text-amber-400 truncate">{started.bssid ?? <span className="text-gray-600">{NA}</span>}</div>
              </div>
              <div>
                <div className="text-[9px] font-tactical text-gray-500 mb-1">HASH MODE</div>
                <div className="text-sm font-mono text-neon-400">{started.hash_mode ?? <span className="text-gray-600">{NA}</span>}</div>
              </div>
              <div>
                <div className="text-[9px] font-tactical text-gray-500 mb-1">HASHES IN CAPTURE</div>
                <div className="text-sm font-mono text-white">
                  {started.hash_count ?? <span className="text-gray-600">{NA}</span>}
                  {started.targets.length > 1 && (
                    <span className="text-gray-500 text-xs"> ({started.targets.length} targets)</span>
                  )}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Result / Error Cards */}
        <AnimatePresence>
          {crackingState === 'SUCCESS' && (
             <motion.div
               initial={{ opacity: 0, y: -20 }}
               animate={{ opacity: 1, y: 0 }}
               className="glass-card p-6 border border-signal-strong/50 bg-signal-strong/10 flex items-center justify-between gap-4"
             >
                <div>
                  <h2 className="text-sm font-tactical text-signal-strong tracking-widest mb-1 flex items-center gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                    KEY RECOVERED
                  </h2>
                  <p className="text-xs text-gray-400 font-mono">
                    hashcat -m 22000{started?.hash_mode ? ` (${started.hash_mode})` : ''}
                    {started?.essid ? ` — ${started.essid}` : ''}
                  </p>
                </div>
                <div className="px-6 py-3 bg-space-950 rounded border border-signal-strong/30 font-mono text-2xl text-white tracking-wider break-all">
                  {crackedPassword}
                </div>
             </motion.div>
          )}

          {crackingState === 'FAILED' && (
             <motion.div
               initial={{ opacity: 0, y: -20 }}
               animate={{ opacity: 1, y: 0 }}
               className="glass-card p-5 border border-risk-high/50 bg-risk-high/10"
             >
                <h2 className="text-sm font-tactical text-risk-high tracking-widest mb-1 flex items-center gap-2">
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                  {runError ? `ENGINE ERROR — ${runError.reason.toUpperCase()}` : 'RECOVERY FAILED'}
                </h2>
                <p className="text-xs text-gray-300 font-mono break-all">
                  {runError?.message ?? failureMessage ?? 'No key recovered.'}
                </p>
                {runError?.exit_code !== undefined && (
                  <p className="text-[10px] text-gray-500 font-mono mt-1">hashcat exit code: {runError.exit_code}</p>
                )}
                {runError?.output && (
                  <pre className="mt-2 max-h-24 overflow-y-auto text-[10px] font-mono text-gray-500 whitespace-pre-wrap">{runError.output}</pre>
                )}
             </motion.div>
          )}

          {crackingState === 'ABORTED' && (
             <motion.div
               initial={{ opacity: 0, y: -20 }}
               animate={{ opacity: 1, y: 0 }}
               className="glass-card p-5 border border-amber-500/50 bg-amber-500/10"
             >
                <h2 className="text-sm font-tactical text-amber-400 tracking-widest mb-1">OPERATION ABORTED</h2>
                <p className="text-xs text-gray-300 font-mono">{failureMessage ?? 'Aborted by operator.'}</p>
             </motion.div>
          )}
        </AnimatePresence>

        {/* Matrix Terminal */}
        <div className="flex-1 glass-card border border-space-500/30 flex flex-col overflow-hidden relative group">
          <div className="h-8 bg-space-900 border-b border-space-500/30 flex items-center px-4 justify-between">
             <div className="flex gap-2">
               <div className="w-2.5 h-2.5 rounded-full bg-risk-high"></div>
               <div className="w-2.5 h-2.5 rounded-full bg-risk-medium"></div>
               <div className="w-2.5 h-2.5 rounded-full bg-signal-strong"></div>
             </div>
             <div className="text-[10px] font-mono text-gray-500">DECRYPTOR_TERMINAL_V1</div>
          </div>

          {/* KPI Dashboard — every tile is a value hashcat reported, or a dash */}
          {crackingState !== 'IDLE' && (
            <div className="bg-space-950/80 border-b border-space-500/20 p-3 flex flex-col gap-2">
              <div className="grid grid-cols-3 lg:grid-cols-6 gap-2">
                <div className="bg-space-900 border border-space-500/30 rounded p-2 text-center">
                  <div className="text-[9px] font-tactical text-gray-500 mb-1">STATUS</div>
                  <div className="text-sm font-mono font-bold text-neon-400 truncate">{statusLabel}</div>
                </div>
                <div className="bg-space-900 border border-space-500/30 rounded p-2 text-center">
                  <div className="text-[9px] font-tactical text-gray-500 mb-1">HASH RATE</div>
                  <div className="text-sm font-mono font-bold text-amber-400">
                    {stats.hashes_per_sec !== undefined ? formatRate(stats.hashes_per_sec) : <span className="text-gray-600">{NA}</span>}
                  </div>
                </div>
                <div className="bg-space-900 border border-space-500/30 rounded p-2 text-center">
                  <div className="text-[9px] font-tactical text-gray-500 mb-1">CANDIDATES TESTED</div>
                  <div className="text-sm font-mono font-bold text-white truncate">
                    {stats.tested !== undefined ? stats.tested.toLocaleString() : <span className="text-gray-600">{NA}</span>}
                    <span className="text-gray-500 text-xs">/{stats.total !== undefined ? stats.total.toLocaleString() : NA}</span>
                  </div>
                </div>
                <div className="bg-space-900 border border-space-500/30 rounded p-2 text-center">
                  <div className="text-[9px] font-tactical text-gray-500 mb-1">PROGRESS</div>
                  <div className="text-sm font-mono font-bold text-white">
                    {stats.progress !== undefined ? `${stats.progress.toFixed(2)}%` : <span className="text-gray-600">{NA}</span>}
                  </div>
                </div>
                <div className="bg-space-900 border border-space-500/30 rounded p-2 text-center">
                  <div className="text-[9px] font-tactical text-gray-500 mb-1">ETA</div>
                  <div className="text-sm font-mono font-bold text-white">
                    {stats.eta ?? <span className="text-gray-600">{NA}</span>}
                  </div>
                </div>
                <div className="bg-space-900 border border-space-500/30 rounded p-2 text-center">
                  <div className="text-[9px] font-tactical text-gray-500 mb-1">DEVICE TEMP</div>
                  <div className={`text-sm font-mono font-bold ${
                    stats.temperature_c === undefined ? 'text-gray-600'
                      : stats.temperature_c > 75 ? 'text-risk-high animate-pulse' : 'text-neon-400'
                  }`}>
                    {stats.temperature_c !== undefined ? `${stats.temperature_c}°C` : NA}
                  </div>
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[9px] font-mono text-gray-500">
                <span>DEVICE: <span className="text-gray-300">{stats.device ?? NA}</span></span>
                <span>RECOVERED: <span className="text-gray-300">
                  {stats.recovered !== undefined ? `${stats.recovered}/${stats.hashes_total ?? NA}` : NA}
                </span></span>
                {stats.temperature_c === undefined && (
                  <span className="text-gray-600">no temperature sensor reported</span>
                )}
              </div>
            </div>
          )}

          <div
            ref={terminalRef}
            className="flex-1 bg-space-950 p-4 font-mono text-xs overflow-y-auto whitespace-pre-wrap flex flex-col gap-1"
          >
            {logs.length === 0 ? (
              <span className="text-gray-600 italic">Awaiting capture path and decryption initiation...</span>
            ) : (
              logs.map((log, i) => (
                <span key={i} className={`break-all
                  ${log.startsWith('[CRACK]') ? 'text-gray-400' : ''}
                  ${log.includes('KEY RECOVERED') || log.includes('RECOVERED:') ? 'text-signal-strong font-bold' : ''}
                  ${log.startsWith('[FAILED]') ? 'text-risk-high font-bold' : ''}
                  ${log.startsWith('[ERROR]') ? 'text-risk-critical font-bold' : ''}
                  ${log.startsWith('[WARN]') ? 'text-amber-400' : ''}
                  ${log.startsWith('[SYS]') ? 'text-neon-400' : ''}
                  ${log.startsWith('[PMKID]') ? 'text-purple-400' : ''}
                  ${log.startsWith('[HASHCAT]') ? 'text-amber-400' : ''}
                `}>
                  {log}
                </span>
              ))
            )}
          </div>

          {/* Progress Bar overlay at bottom — only when hashcat reported a percentage */}
          {crackingState === 'CRACKING' && stats.progress !== undefined && (
             <div className="absolute bottom-0 left-0 right-0 h-1 bg-space-800">
               <motion.div
                 className="h-full bg-neon-400"
                 style={{ width: `${stats.progress}%` }}
               />
             </div>
          )}
        </div>
      </div>
      </div>

      {/* Cracking History */}
      {history.length > 0 && (
        <div className="glass-card p-4 mt-4 border border-space-500/20">
          <button
            onClick={() => setShowHistory(!showHistory)}
            className="w-full flex items-center justify-between mb-2"
          >
            <h3 className="text-xs font-tactical tracking-widest text-gray-400 flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-neon-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
              CRACKING HISTORY
            </h3>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono text-gray-500 bg-space-800 px-2 py-0.5 rounded border border-space-500/20">{history.length} RECORDS</span>
              <svg xmlns="http://www.w3.org/2000/svg" className={`w-3.5 h-3.5 text-gray-500 transition-transform ${showHistory ? 'rotate-180' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"/></svg>
            </div>
          </button>
          <AnimatePresence>
            {showHistory && (
              <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                <div className="overflow-x-auto max-h-[250px] overflow-y-auto no-scrollbar">
                  <table className="w-full text-[10px] font-mono">
                    <thead>
                      <tr className="border-b border-space-500/20 text-gray-500 text-left">
                        <th className="py-2 px-2 font-tactical tracking-wider">ESSID</th>
                        <th className="py-2 px-2 font-tactical tracking-wider">BSSID</th>
                        <th className="py-2 px-2 font-tactical tracking-wider">DICTIONARY</th>
                        <th className="py-2 px-2 font-tactical tracking-wider">RESULT</th>
                        <th className="py-2 px-2 font-tactical tracking-wider">PASSWORD</th>
                        <th className="py-2 px-2 font-tactical tracking-wider">TESTED</th>
                        <th className="py-2 px-2 font-tactical tracking-wider">TIME</th>
                        <th className="py-2 px-2 font-tactical tracking-wider">DATE</th>
                        <th className="py-2 px-2"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map(h => (
                        <tr key={h.id} className="border-b border-space-500/10 hover:bg-space-800/30 transition-colors">
                          <td className="py-2 px-2 text-gray-300 truncate max-w-[120px]">{h.ssid || h.pcap_file}</td>
                          <td className="py-2 px-2 text-amber-400/80 truncate max-w-[130px]">{h.bssid || NA}</td>
                          <td className="py-2 px-2 text-gray-400 truncate max-w-[100px]">{h.wordlist.replace('.txt', '')}</td>
                          <td className="py-2 px-2">
                            <span className={`px-1.5 py-0.5 rounded text-[8px] font-tactical tracking-wider ${
                              h.result === 'SUCCESS' ? 'bg-signal-strong/20 text-signal-strong border border-signal-strong/30' :
                              h.result === 'ABORTED' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                              'bg-risk-high/20 text-risk-high border border-risk-high/30'
                            }`}>
                              {h.result}
                            </span>
                            {h.is_simulated ? (
                              <span className="ml-1 px-1.5 py-0.5 rounded text-[8px] font-tactical tracking-wider bg-risk-critical/20 text-risk-critical border border-risk-critical/30">SIM</span>
                            ) : null}
                          </td>
                          <td className="py-2 px-2 font-bold break-all">{(() => {
                            const shown = revealed[h.id];
                            if (shown?.password) return <span className="text-signal-strong">{shown.password}</span>;
                            if (shown?.reason === 'locked')
                              return <span className="text-amber-400 font-normal" title="A passphrase was recovered by this run. Unlock the credential vault to read it.">VAULT LOCKED</span>;
                            if (shown?.reason === 'undecryptable')
                              return <span className="text-risk-critical font-normal" title="The stored bytes did not authenticate under this key. The record is present but its passphrase cannot be read.">UNREADABLE</span>;
                            return <span className="text-gray-500 font-normal">{NA}</span>;
                          })()}</td>
                          <td className="py-2 px-2 text-gray-400">{h.passwords_tested.toLocaleString()}/{h.passwords_total.toLocaleString()}</td>
                          <td className="py-2 px-2 text-gray-400">{h.duration_seconds}s</td>
                          <td className="py-2 px-2 text-gray-500">{new Date(h.created_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })}</td>
                          <td className="py-2 px-2">
                            <button onClick={() => { deleteCrackingRecord(h.id).then(() => getCrackingHistory().then(setHistory)); }} className="text-gray-600 hover:text-risk-critical transition-colors">
                              <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}
    </div>
  );
}
