/** IntrusionPage — Active Network Reconnaissance */
import { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { severityClasses } from '../lib/severityStyle';
import { assessHost, hostOfUrl, SEVERITY_ORDER } from '../lib/riskEngine';
import { toHostInput, worstOf } from '../lib/report/archive';
import { useIntrusionStore, DiscoveredHost } from '../stores/intrusionStore';
import { useStrikeStore } from '../stores/strikeStore';
import { useReportStore } from '../stores/reportStore';
import { useEngineStore } from '../stores/engineStore';
import { engineIPC } from '../lib/ipc';
import { ipInCidr } from '../lib/cidr';
import { getSessions, getSessionHosts, createSession, deleteSession, deleteAllSessions,
         getDeviceHistory, getDeviceAddressChanges, type ScanSession, type DeviceHistoryEntry } from '../lib/intrusionDB';
import { countUnattributedCredentials, getCredentialsForArchive, saveCredential, VaultLockedError } from '../lib/credentialDB';
import { ConfirmModal } from '../components/common/ConfirmModal';
type FilterType = 'ALL' | 'WINDOWS' | 'LINUX/UNIX' | 'VULNERABLE';
type ScanMode = 'QUICK' | 'DEEP' | 'STEALTH';

import { VaultDrawer } from '../components/intrusion/VaultDrawer';
import { TlsCertificatePanel } from '../components/intrusion/TlsCertificatePanel';
import { PassiveSigintView } from '../components/intrusion/PassiveSigintView';

export function IntrusionPage() {
  const isActive = useIntrusionStore(s => s.isActive);
  const hasScanned = useIntrusionStore(s => s.hasScanned);
  const progress = useIntrusionStore(s => s.progress);
  const targetSubnet = useIntrusionStore(s => s.targetSubnet);
  const activeSsid = useIntrusionStore(s => s.activeSsid);
  const subnets = useIntrusionStore(s => s.subnets);
  const newDevices = useIntrusionStore(s => s.newDevices);
  const hosts = useIntrusionStore(s => s.hosts);
  const sweepScopes = useIntrusionStore(s => s.sweepScopes);
  const startIntrusion = useIntrusionStore(s => s.startIntrusion);
  const stopIntrusion = useIntrusionStore(s => s.stopIntrusion);
  const smbTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const addReport = useReportStore(s => s.addReport);
  const activeStrikes = useStrikeStore(s => s.activeStrikes);

  const [saving, setSaving] = useState(false);
  const [filterType, setFilterType] = useState<FilterType>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Modal & Drawer state
  const [showConfig, setShowConfig] = useState(false);
  const [scanMode, setScanMode] = useState<ScanMode>('QUICK');
  const [selectedHostIp, setSelectedHostIp] = useState<string | null>(null);
  const selectedHost = selectedHostIp ? hosts[selectedHostIp] || null : null;

  // Sighting history for the selected host, loaded on demand.
  const [deviceHistory, setDeviceHistory] = useState<DeviceHistoryEntry[]>([]);
  const [addressChanges, setAddressChanges] = useState<{ ip: string; first: string; last: string; sightings: number }[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  useEffect(() => {
    const mac = selectedHost?.mac;
    if (!mac) {
      setDeviceHistory([]);
      setAddressChanges([]);
      return;
    }
    let cancelled = false;
    setHistoryLoading(true);
    Promise.all([getDeviceHistory(mac), getDeviceAddressChanges(mac)])
      .then(([history, changes]) => {
        if (cancelled) return;
        setDeviceHistory(history);
        setAddressChanges(changes);
      })
      .catch(err => {
        if (!cancelled) console.error('[DB] device history error:', err);
      })
      .finally(() => { if (!cancelled) setHistoryLoading(false); });
    // Guards against a stale response landing after the operator picked another host.
    return () => { cancelled = true; };
  }, [selectedHost?.mac]);
  const [activeSubnet, setActiveSubnet] = useState<string | null>(null);

  // Toast notification state
  const [toast, setToast] = useState<{ show: boolean; message: string; type: 'success' | 'error' | 'info' }>({ show: false, message: '', type: 'info' });
  const showToast = (message: string, type: 'success' | 'error' | 'info' = 'success') => {
    setToast({ show: true, message, type });
    setTimeout(() => setToast(prev => ({ ...prev, show: false })), 3000);
  };

  // STRIKE state
  const [showStrikeConfirm, setShowStrikeConfirm] = useState(false);
  const [strikeTarget, setStrikeTarget] = useState<DiscoveredHost | null>(null);
  const [showPurgeConfirm, setShowPurgeConfirm] = useState(false);

  // Scan History & Vault state
  const [showHistory, setShowHistory] = useState(false);
  const [historySearch, setHistorySearch] = useState('');
  const [showVault, setShowVault] = useState(false);
  const [sessions, setSessions] = useState<ScanSession[]>([]);
  const [viewMode, setViewMode] = useState<'ACTIVE' | 'PASSIVE'>('ACTIVE');
  const [selectedSession, setSelectedSession] = useState<any>(null);
  const [sessionHosts, setSessionHosts] = useState<any[]>([]);

  // Offense UI State
  const [bruteForceState, setBruteForceState] = useState<'IDLE' | 'CRACKING' | 'SUCCESS'>('IDLE');
  const [crackedCreds, setCrackedCreds] = useState<string | null>(null);
  /** Set when a recovered credential could not be stored because the vault is locked. */
  const [bruteforceVaultWarning, setBruteforceVaultWarning] = useState<string | null>(null);
  const [bruteForceWord, setBruteForceWord] = useState<string>('');
  const [selectedWordlist, setSelectedWordlist] = useState<string>('mirai-botnet-credentials.txt');
  const [showBfConfig, setShowBfConfig] = useState(false);
  const [bfTargetUser, setBfTargetUser] = useState("admin");
  const [bfMode, setBfMode] = useState<'DICTIONARY' | 'SPRAY'>('DICTIONARY');

  // DirBuster UI State
  const [dirbusterState, setDirbusterState] = useState<'IDLE' | 'SCANNING' | 'SUCCESS'>('IDLE');
  const [showDirbusterConfig, setShowDirbusterConfig] = useState(false);
  const [dirbusterPath, setDirbusterPath] = useState<string>('');
  const [dirbusterFindings, setDirbusterFindings] = useState<any[]>([]);
  /*
    Whether the last enumeration exhausted its wordlist.

    null until one finishes. It matters to the report: "no other paths respond"
    is a statement about the server only if every path in the list was actually
    requested. An operator who stopped the scan early has learned nothing about
    the paths that were still queued, and the document must not imply otherwise.
  */
  const [dirbusterComplete, setDirbusterComplete] = useState<boolean | null>(null);

  // SMB Enum State
  const [smbEnumState, setSmbEnumState] = useState<'IDLE' | 'SCANNING' | 'SUCCESS'>('IDLE');
  const [smbEnumFindings, setSmbEnumFindings] = useState<any | null>(null);

  /*
    Network segmentation state.

    `start_vlan_detect` was implemented, policy-gated per CIDR and tested, and
    nothing sent it. It is network-level rather than per-host, so it needs no
    ownership gate -- there is one network and one result.

    `vlanProgress` holds the engine's own `vlan_scan_started` message, because
    the check pings a gateway per subnet and can run for a while; a spinner with
    no subject looks identical to one that has hung.
  */
  const [vlanState, setVlanState] = useState<'IDLE' | 'SCANNING' | 'DONE'>('IDLE');
  const [vlanReport, setVlanReport] = useState<any | null>(null);
  const [vlanError, setVlanError] = useState<string | null>(null);
  const [vlanProgress, setVlanProgress] = useState<string | null>(null);
  /*
    Collapsed by default once a scan completes.

    The summary line carries the result an operator actually came for -- how many
    subnets, how many gateways answered, and whether anything routes between them
    -- in about 44px. The table is the evidence behind it, and it is worth
    roughly 200px of the host list, so it is opened on request rather than by
    default. Remembered for the session, so an operator who wants it open does
    not have to reopen it after every sweep.
  */
  const [vlanOpen, setVlanOpen] = useState(false);

  /*
    TLS inspection state.

    `start_deep_ssl_scan` was implemented, policy-gated and tested, and nothing in
    the application ever sent it -- no caller, and no listener for either of the
    two events it answers with. A check nobody can run is not a capability.

    The error is held separately rather than folded into the state machine,
    because `ssl_scan_error` carries the reason and the panel has to say it. A
    TLS scan that fails silently reads as a host with nothing wrong on 443.
  */
  const [sslScanState, setSslScanState] = useState<'IDLE' | 'SCANNING' | 'SUCCESS'>('IDLE');
  const [sslScanReport, setSslScanReport] = useState<any | null>(null);
  const [sslScanError, setSslScanError] = useState<string | null>(null);

  // MITM State
  const [mitmState, setMitmState] = useState<'IDLE' | 'SPOOFING' | 'ERROR'>('IDLE');
  /*
    The host the spoof was actually started against.

    `mitmState` is one value for the whole page, but STOP INTERCEPT used to send
    `selectedHost.ip` — whichever host happened to be selected when the button
    was clicked. Start on A, close the drawer, select B, and the button still
    read STOP INTERCEPT because the state is global; clicking it sent
    `stop_mitm {target_ip: B}`, which the engine ignored because B was not in
    `active_attacks`. No event came back, so the UI sat on SPOOFING forever and
    A's ARP tables stayed poisoned with no way to restore them from the
    interface — the MITM module's `stop_all` is not exposed as a command.

    This is a third party's network left altered, so the target travels with the
    attack rather than being read off the screen. `mitm_started` already carries
    it; the listener simply threw it away.
  */
  const [mitmTarget, setMitmTarget] = useState<string | null>(null);
  const [mitmPackets, setMitmPackets] = useState<any[]>([]);
  const [showMitmDrawer, setShowMitmDrawer] = useState(false);
  const [savePcap, setSavePcap] = useState(false);
  const [mitmFilter, setMitmFilter] = useState<'ALL' | 'CREDENTIALS' | 'WEB' | 'DNS'>('ALL');

  // VulnScan State
  const [vulnScanState, setVulnScanState] = useState<'IDLE' | 'SCANNING' | 'SUCCESS'>('IDLE');
  const [vulnScanFindings, setVulnScanFindings] = useState<any[]>([]);
  /**
   * Every service-inspection result this session, keyed by target.
   *
   * Two problems with holding only the latest. The panel showed results for
   * whichever host answered last regardless of which one was selected, because
   * `target` was never compared; and nothing was carried into the archive, so
   * the report raised nothing for a host the operator had just watched come back
   * CRITICAL on screen.
   */
  const [vulnScanByTarget, setVulnScanByTarget] = useState<Record<string, {
    findings: any[];
    ports_examined?: number[];
    ports_without_a_check?: number[];
    caveat?: string;
    error?: string;
    at: number;
  }>>({});

  // Traceroute State
  const [tracerouteState, setTracerouteState] = useState<'IDLE' | 'TRACING' | 'DONE'>('IDLE');
  const [tracerouteHops, setTracerouteHops] = useState<any[]>([]);
  /*
    Which host each on-screen deep-scan result came from.

    The four completion listeners wrote their payload into flat state and the drawer
    rendered it under whichever host was selected — so running ANALYZE VULNERABILITIES
    on host A, closing the drawer and opening host B showed A's CRITICAL Redis finding
    under the header "TARGET ACQUIRED <B>", with the button reading SCAN COMPLETED. Same
    for SMB, dirbuster and traceroute. None of the per-host state was reset on selection
    change either: the X resets only brute force, the backdrop only brute force and
    traceroute.

    The engine ships the subject in every one of these payloads specifically to prevent
    this — `smb_enum.py` says so in a comment: "The payload names its own subject.
    Without this the frontend had to guess the target from whichever host happened to be
    selected when the result arrived, which mislabels the evidence." The listeners never
    read it.

    The archive path was always correct, because it takes the host from the payload. This
    was a screen-only defect — but the screen is what the operator reads and writes down.
  */
  const [resultOwner, setResultOwner] = useState<{
    smb?: string; vuln?: string; dirbuster?: string; traceroute?: string; ssl?: string;
  }>({});
  /** True when a deep-scan result on screen belongs to the host being shown. */
  const ownsResult = (kind: 'smb' | 'vuln' | 'dirbuster' | 'traceroute' | 'ssl', ip?: string | null) => {
    const owner = resultOwner[kind];
    // No recorded owner means the result predates this change or the engine sent
    // none; showing it is the previous behaviour and withholding it would hide a
    // real result, so it is shown and the mismatch case is the one that is gated.
    if (!owner || !ip) return true;
    return owner === ip;
  };
  const [tracerouteAnalysis, setTracerouteAnalysis] = useState<any[]>([]);
  // Taken from the engine's own payload, not from the selected host: the path
  // in the archive must be labelled with the address it was actually traced to.
  const [tracerouteTarget, setTracerouteTarget] = useState<string | null>(null);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [showActionPanel, setShowActionPanel] = useState(false);

  const { wordlists, config } = useEngineStore();
  const interfaceName = config.interfaceName;

  /*
    The associated SSID comes from the engine, not from a Rust command of our
    own.

    This used to poll a `get_wifi_ssid` Tauri command every five seconds. That
    command had three problems, all of which the engine's `netsh wlan` parser
    had already solved:

      * It spawned `netsh` without CREATE_NO_WINDOW. The app is a GUI-subsystem
        binary with no console, so Windows allocated one for each child — a
        black window blinked on screen **every five seconds** for as long as
        this page was open.
      * It matched the literal English field name `SSID`. On a Thai or German
        Windows, `netsh` emits localised labels, so it returned "Disconnected"
        forever while the adapter was in fact associated.
      * It was an `async fn` doing a blocking `Command::output()`, parking a
        Tauri runtime worker for the 100-800 ms `netsh` takes — a thread also
        serving every other IPC call.

    `engine/scanner/net_context.py` does this correctly, with
    CREATE_NO_WINDOW and without depending on a localised label, and its result
    is already in `engineStore.netContext`. Reading it here removes the
    duplicate implementation along with all three faults.
  */
  const netContextSsid = useEngineStore(s => s.netContext?.ssid ?? null);
  useEffect(() => {
    if (netContextSsid && netContextSsid !== activeSsid) {
      useIntrusionStore.setState({ activeSsid: netContextSsid });
    }
  }, [netContextSsid, activeSsid]);

  // Ask once on arrival, so the page is current if the operator changed network
  // since the engine last reported. The engine also sends this on connect and
  // when a scan starts, which covers the rest — a five-second poll of a command
  // that shells out to `netsh` was never worth it.
  useEffect(() => {
    if (engineIPC.connected) {
      engineIPC.send('get_net_context').catch(console.error);
    }
  }, []);

  useEffect(() => {
    if (wordlists.length > 0) {
      if (bfMode === 'DICTIONARY') {
        const dic = wordlists.find(w => w.name.includes('credential') || w.name.includes('botnet'));
        setSelectedWordlist(dic ? dic.name : wordlists[0].name);
      } else {
        const spray = wordlists.find(w => w.name.includes('thai-common') || w.name.includes('default'));
        setSelectedWordlist(spray ? spray.name : wordlists[0].name);
      }
    }
  }, [bfMode, wordlists]);

  useEffect(() => {
    if (subnets.length > 0 && !activeSubnet) {
      setActiveSubnet(subnets[0]);
    } else if (targetSubnet && !activeSubnet) {
      setActiveSubnet(targetSubnet);
    }
  }, [subnets, targetSubnet]);

  // IPC Listeners for Bruteforce
  useEffect(() => {
    const unsubBfStart = engineIPC.on('bruteforce_started', () => setBruteForceState('CRACKING'));
    const unsubBfSuccess = engineIPC.on('bruteforce_success', (msg) => {
      const data = msg.data as any;
      setBruteForceState('SUCCESS');
      setCrackedCreds(data.credentials);
      // Persist it. A recovered credential that only lived in component state
      // vanished on the next navigation, so the strongest finding an audit can
      // produce — demonstrated access — never reached the vault or the report.
      // The engine sends username/password as separate fields precisely so this
      // does not have to split "user:pwd" and lose a password containing a colon.
      if (data.username != null && data.password != null) {
        /*
          The session is stamped here, and that is load-bearing.

          `getCredentialsForArchive` is scoped to one sweep's session, so a row
          written without one matches no archive and the credential disappears from
          every report. `sessionId` is the seventh, optional parameter of
          `saveCredential`, both writers stopped at the sixth, and the scoping change
          turned a cross-engagement leak into a silent loss of the strongest finding
          this tool can make.
        */
        saveCredential(
          data.target, data.port, data.service || 'unknown',
          data.username, data.password, 'bruteforce',
          useIntrusionStore.getState().currentSessionId ?? undefined
        ).catch((err) => {
          if (err instanceof VaultLockedError) {
            setBruteforceVaultWarning(
              `${data.credentials} worked on ${data.target}:${data.port} but was NOT stored — `
              + 'the credential vault is locked. Unlock it in the vault drawer to record findings.'
            );
          } else {
            console.error('[VAULT] failed to store brute-forced credential', err);
          }
        });
      }
    });
    const unsubBfProgress = engineIPC.on('bruteforce_progress', (msg) => {
      const data = msg.data as any;
      setBruteForceWord(data.current_word);
    });
    /*
      "Exhausted" is only a finding when the host judged the passwords.

      The engine now reports how many of the attempts actually got a verdict. A run
      where the host stopped answering -- fail2ban, MaxAuthTries, a host going down
      -- used to end in exactly the same event as one where every password was
      evaluated and rejected, and the operator had no way to tell them apart.
    */
    const unsubBfExhausted = engineIPC.on('bruteforce_exhausted', (msg) => {
      const d = msg.data as any;
      setBruteForceState('IDLE');
      if (d?.caveat) showToast(String(d.caveat), 'error');
    });
    const unsubBfAborted = engineIPC.on('bruteforce_aborted', (msg) => {
      const d = msg.data as any;
      setBruteForceState('IDLE');
      showToast(String(d?.reason || 'The brute force was abandoned: the host stopped answering.'), 'error');
    });
    const unsubBfError = engineIPC.on('bruteforce_error', () => {
      setBruteForceState('IDLE');
    });

    const unsubDbStart = engineIPC.on('dirbuster_started', () => {
      setDirbusterState('SCANNING');
      setDirbusterComplete(null);
    });
    const unsubDbFinding = engineIPC.on('dirbuster_finding', (msg) => {
      setDirbusterFindings(prev => {
        const next = [msg.data, ...prev];
        return next.slice(0, 100);
      });
    });
    const unsubDbProgress = engineIPC.on('dirbuster_progress', (msg: any) => {
      setDirbusterPath(msg.data.current_path);
    });
    const unsubDbCompleted = engineIPC.on('dirbuster_completed', (msg) => {
      const d = msg.data as any;
      // `target` is the base URL the engine scanned; the host inside it is the
      // subject, the same way `hostOfUrl` derives it for the archive.
      const owner = hostOfUrl(String(d?.target ?? ''));
      if (owner) setResultOwner(prev => ({ ...prev, dirbuster: owner }));
      setDirbusterComplete(d?.complete === true);
      setDirbusterState(prev => prev === 'SCANNING' ? 'SUCCESS' : prev);
      /*
        `complete` is now false when nothing answered, not just when the operator
        stopped the run. Every request raising URLError — a closed or filtered port —
        used to be swallowed by a bare `pass` and still reported the wordlist as
        exhausted with no findings, which is the one reading that licenses "these
        paths are not on this server".
      */
      if (d?.caveat) showToast(String(d.caveat), 'error');
    });
    const unsubDbError = engineIPC.on('dirbuster_error', () => {
      setDirbusterState('IDLE');
    });

    const unsubVlanStart = engineIPC.on('vlan_scan_started', (msg) => {
      const d = msg.data as any;
      setVlanProgress(typeof d?.message === 'string' ? d.message : null);
    });
    const unsubVlanDone = engineIPC.on('vlan_scan_completed', (msg) => {
      setVlanProgress(null);
      setVlanError(null);
      setVlanReport(msg.data as any);
      setVlanState('DONE');
    });

    /*
      TLS inspection. Both events carry `target`, so the owner is taken from the
      payload rather than from whatever host is selected when it lands -- a deep
      scan is slow enough that the operator has usually moved on.

      There is no `started` event for this one, so SCANNING is entered at the
      click. That makes the click the thing that must not lie: it is only entered
      if `send` resolved.
    */
    const unsubSslDone = engineIPC.on('deep_ssl_scan_completed', (msg) => {
      const d = msg.data as any;
      const owner = typeof d?.target === 'string' ? d.target : undefined;
      if (owner) setResultOwner(prev => ({ ...prev, ssl: owner }));
      setSslScanError(null);
      setSslScanReport(d);
      setSslScanState('SUCCESS');
    });
    const unsubSslError = engineIPC.on('ssl_scan_error', (msg) => {
      const d = msg.data as any;
      const owner = typeof d?.target === 'string' ? d.target : undefined;
      if (owner) setResultOwner(prev => ({ ...prev, ssl: owner }));
      // SUCCESS, deliberately: the panel opens and says what went wrong. Going
      // back to IDLE would restore the button and leave no trace that a scan was
      // attempted and failed, which reads as a host that was never examined.
      setSslScanReport(null);
      setSslScanError(typeof d?.message === 'string' ? d.message : 'The TLS inspection could not complete.');
      setSslScanState('SUCCESS');
    });

    const unsubSmbStart = engineIPC.on('smb_enum_started', () => {
      setSmbEnumState('SCANNING');
      // Held in a ref, not on `window`: a second concurrent enum used to clobber
      // the global and the timer was never cleared on unmount. The enum now runs
      // off the IPC thread and can legitimately take ~60s, so the watchdog is
      // generous — it only exists for an engine that dies without answering.
      if (smbTimeoutRef.current) clearTimeout(smbTimeoutRef.current);
      smbTimeoutRef.current = setTimeout(() => {
        smbTimeoutRef.current = null;
        setSmbEnumState(prev => prev === 'SCANNING' ? 'IDLE' : prev);
      }, 90000);
    });
    const clearSmbTimeout = () => {
      if (smbTimeoutRef.current) {
        clearTimeout(smbTimeoutRef.current);
        smbTimeoutRef.current = null;
      }
    };
    const unsubSmbError = engineIPC.on('smb_enum_error', () => {
      clearSmbTimeout();
      setSmbEnumState('IDLE');
    });
    const unsubSmbCompleted = engineIPC.on('smb_enum_completed', (msg) => {
      clearSmbTimeout();
      const d = msg.data as any;
      // The subject the engine named, so the drawer cannot show this under a
      // different host. See `resultOwner`.
      const owner = String(d?.target ?? '').trim();
      if (owner) setResultOwner(prev => ({ ...prev, smb: owner }));
      setSmbEnumFindings(d);
      setSmbEnumState('SUCCESS');
    });

    const unsubMitmStart = engineIPC.on('mitm_started', (msg: any) => {
      setMitmState('SPOOFING');
      // Recorded from the payload, not from the selection, so STOP INTERCEPT
      // reaches the host that is actually being spoofed.
      const target = msg?.data?.target;
      if (typeof target === 'string' && target) setMitmTarget(target);
    });
    // mitm_stopped now arrives only after the ARP restore has been attempted and
    // reports whether it worked. A failed restore leaves the target's network
    // state altered, so it must not read as a clean stop.
    const unsubMitmStop = engineIPC.on('mitm_stopped', (msg: any) => {
      const restored = msg?.data?.arp_restored !== false;
      setMitmState(restored ? 'IDLE' : 'ERROR');
      // Held on a failed restore: the target is still altered, and its address is
      // the only thing that says which machine needs attention.
      if (restored) setMitmTarget(null);
    });
    const unsubMitmError = engineIPC.on('mitm_error', () => setMitmState('ERROR'));
    const unsubMitmPacket = engineIPC.on('mitm_packet', (msg) => {
      setMitmPackets(prev => [msg.data, ...prev].slice(0, 100));
    });

    const unsubVulnStart = engineIPC.on('vuln_scan_started', () => setVulnScanState('SCANNING'));
    const unsubVulnComplete = engineIPC.on('vuln_scan_completed', (msg) => {
      const d = msg.data as any;
      const target = String(d?.target ?? '').trim();
      const findings = (d?.findings as any[]) || [];
      if (target) setResultOwner(prev => ({ ...prev, vuln: target }));
      // Keep the whole payload, not just `findings`. The engine also sends which
      // ports it actually had a check for and the caveat that an empty result is
      // not a clean bill of health; all of that used to be dropped here, which
      // is how a refused scan came to render as a clean one.
      if (target) {
        setVulnScanByTarget(prev => ({
          ...prev,
          [target]: {
            findings,
            ports_examined: Array.isArray(d?.ports_examined) ? d.ports_examined : undefined,
            ports_without_a_check: Array.isArray(d?.ports_without_a_check) ? d.ports_without_a_check : undefined,
            caveat: d?.caveat ? String(d.caveat) : undefined,
            error: d?.error ? String(d.error) : undefined,
            at: Date.now(),
          },
        }));
      }
      setVulnScanFindings(findings);
      // An error means the scan did not run. It must not land in the same state
      // as a completed one, which is what rendered a green "all checks passed".
      setVulnScanState(d?.error ? 'IDLE' : 'SUCCESS');
      if (d?.error) {
        showToast(`Vulnerability scan did not run: ${d.error}`, 'error');
      }
    });

    // Traceroute listeners
    const unsubTraceHop = engineIPC.on('traceroute_hop', (msg) => {
      setTracerouteHops(prev => [...prev, msg.data]);
    });
    const unsubTraceComplete = engineIPC.on('traceroute_completed', (msg) => {
      const d = msg.data as any;
      setTracerouteAnalysis(d.analysis || []);
      setTracerouteTarget(d?.target ? String(d.target) : null);
      if (d?.target) setResultOwner(prev => ({ ...prev, traceroute: String(d.target) }));
      /*
        `ok === false` means the trace itself did not run — tracert missing,
        killed on timeout, a spawn failure. The engine used to emit this event
        unconditionally after the error event, and because this handler set DONE
        it won: a tool failure looked exactly like a host that is firewalled.
        DONE is now reserved for a trace that reached a conclusion.
      */
      if (d?.ok === false) {
        setTracerouteState('IDLE');
        if (d?.error) showToast(`Traceroute did not run: ${d.error}`, 'error');
      } else {
        setTracerouteState('DONE');
      }
    });
    const unsubTraceError = engineIPC.on('traceroute_error', () => {
      setTracerouteState('IDLE');
    });

    return () => {
      unsubBfStart();
      unsubBfSuccess();
      unsubBfProgress();
      unsubBfExhausted();
      unsubBfAborted();
      unsubBfError();
      unsubDbStart();
      unsubDbFinding();
      unsubDbProgress();
      unsubDbCompleted();
      unsubDbError();
      unsubVlanStart();
      unsubVlanDone();
      unsubSslDone();
      unsubSslError();
      unsubSmbStart();
      unsubSmbError();
      unsubSmbCompleted();
      unsubMitmStart();
      unsubMitmStop();
      unsubMitmError();
      unsubMitmPacket();
      unsubVulnStart();
      unsubVulnComplete();
      unsubTraceHop();
      unsubTraceComplete();
      unsubTraceError();
    };
  }, []);

  // Filter and sort host list
  /*
    One rule set, one answer per host — literally the same call the report makes.

    `getRiskLevel` used to run its own ladder: severities from the table above,
    then a fallback that scored by port number alone, where any of
    445/21/23/3389/5900/**22** open made a host HIGH. `riskEngine` has no rule for
    port 22 at all, so a host whose only open port was SSH was HIGH on this
    screen and absent from the report. MEDIUM was also drawn in purple
    (`neon-400`), outside the risk palette entirely.

    Credentials are passed as an empty list on purpose: the vault's rows are
    sealed while a sweep is running and decrypting them to colour a card is not a
    trade worth making. A credential the sweep itself demonstrated still counts,
    because the engine puts it on the host record as `default_creds` and
    `toHostInput` reads it.
  */
  const hostFindings = (host: DiscoveredHost) => assessHost(toHostInput(host, [], false));

  /** The rule set's worst severity for a host, or null when it raises nothing. */
  const hostSeverity = (host: DiscoveredHost) => {
    const findings = hostFindings(host);
    return findings.length ? worstOf(findings).severity : null;
  };

  /**
   * Worst severity the rule set raises about one port of one host, or null when
   * it raises nothing.
   *
   * Findings name their port in the title, which is the only link back from a
   * finding to the row that produced it. Null is distinct from INFO: INFO would
   * claim the port was assessed and found unremarkable, and a port with no rule
   * was not assessed at all.
   */
  const portSeverity = (host: DiscoveredHost, port: number) => {
    const mine = hostFindings(host).filter(f => f.title.includes(`port ${port}`));
    return mine.length ? worstOf(mine).severity : null;
  };

  const subnetHosts = Object.values(hosts).filter(h => {
    /*
      Matched against the prefix, not against the first three octets.

      This compared `h.ip.startsWith(activeSubnet.split('.').slice(0,3).join('.'))`,
      which is right for a /24 and wrong for everything else in both directions:
      a /16 drops every host outside one arbitrary third octet, and a /25 accepts
      the half of the range that belongs to the other segment. It had not been
      noticed because the sweep's subnet list is almost always /24 -- and the
      segmentation map, which now counts hosts per range, is not.
    */
    if (activeSubnet) return ipInCidr(h.ip, activeSubnet);
    return true;
  });

  const hostList = subnetHosts
    .filter(h => {
      // Search filter
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const matchesIp = h.ip.includes(q);
        const matchesHostname = h.hostname?.toLowerCase().includes(q);
        const matchesMac = h.mac?.toLowerCase().includes(q);
        const matchesOs = h.os?.toLowerCase().includes(q);
        const matchesPort = h.open_ports.some(p => p.port.toString().includes(q) || p.service.toLowerCase().includes(q));
        if (!matchesIp && !matchesHostname && !matchesMac && !matchesOs && !matchesPort) return false;
      }
      // Type filter
      if (filterType === 'ALL') return true;
      if (filterType === 'WINDOWS') return h.os.includes('Windows');
      if (filterType === 'LINUX/UNIX') return h.os.includes('Linux') || h.os.includes('Unix');
      // "Vulnerable" means the rule set raised something, which is what the
      // VULNERABLE tile counts and what the report lists. It used to mean "has one
      // of six ports open", so the filter and the number beside it could disagree.
      if (filterType === 'VULNERABLE') return hostFindings(h).length > 0;
      return true;
    })
    .sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));

  // Auto-refresh scan history when scan completes
  useEffect(() => {
    if (!isActive && hasScanned) {
      getSessions().then(setSessions).catch(console.error);
    }
  }, [isActive, hasScanned]);



  const handleToggle = () => {
    if (isActive) {
      engineIPC.send('stop_intrusion').catch(console.error);
      stopIntrusion();
    } else {
      setShowConfig(true);
    }
  };

  const executeSweep = async () => {
    setShowConfig(false);
    startIntrusion(undefined, scanMode);

    // Save new session to DB to satisfy foreign keys
    const currentSessionId = useIntrusionStore.getState().currentSessionId;
    if (currentSessionId) {
      try {
        const ssidContext = activeSsid ? ` [${activeSsid}]` : '';
        const initialSubnet = (activeSubnet || targetSubnet) ? `${activeSubnet || targetSubnet}${ssidContext}` : `Auto-detecting...${ssidContext}`;
        await createSession(currentSessionId, initialSubnet, scanMode,
                            useEngineStore.getState().config.emulateHardware);
      } catch (err) {
        console.error('[DB] createSession error:', err);
      }
    }

    // session_id travels with the command so every audit row the scope gate
    // writes can be tied back to the sweep that triggered it.
    engineIPC.send('start_intrusion', { scan_mode: scanMode, session_id: currentSessionId })
      .catch(err => {
        console.error('[Intrusion] start failed:', err);
        stopIntrusion();
        window.dispatchEvent(new CustomEvent('lockon:toast', {
          detail: { message: `Could not start sweep: ${err}`, type: 'error' }
        }));
      });
  };

  const handleArchive = async () => {
    if (hostList.length === 0) return;

    setSaving(true);

    // Credentials go into the snapshot with their secrets still sealed.
    // getAllCredentials() decrypts, and this used to write that result into
    // intel_reports.raw_data as JSON — putting every recovered password back
    // into the same database file in cleartext and undoing the vault entirely.
    // Scoped to this sweep's session. Unscoped, the snapshot carried every
    // credential ever recovered, and `toHostInput` attaches them by IP alone --
    // so another engagement's 192.168.1.1 became a CONFIRMED finding here.
    let creds: any[] = [];
    try {
      creds = await getCredentialsForArchive(
        useIntrusionStore.getState().currentSessionId,
      );
      /*
        Any credential the snapshot cannot carry is named, not dropped.

        Rows with no `session_id` belong to no survey, so attaching them to this
        archive would be the cross-engagement defect the scoping removed. Leaving them
        out without saying so would be the opposite failure: an empty credentials
        section reading as "nothing was recovered".
      */
      const unattributed = await countUnattributedCredentials();
      if (unattributed > 0) {
        showToast(
          `${unattributed} credential(s) in the vault belong to no recorded sweep and are `
          + 'NOT in this archive. They were recovered, but nothing ties them to a survey, '
          + 'so this document cannot claim them.',
          'error',
        );
      }
    } catch (e) {
      console.error("Failed to load credentials for report", e);
    }

    const report = {
      id: `INT-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      type: 'INTRUSION' as const,
      targetName: targetSubnet || 'UNKNOWN SUBNET',
      timestamp: Date.now(),
      summary: {
        totalNodes: Object.values(hosts).length,
        /*
          Counted through the rule set, not from a port list. This figure is
          persisted to `intel_reports.critical_nodes` and shown in the archive
          index, so a port-number heuristic here put a number in the database
          that the report's own findings table would not reproduce.
        */
        criticalNodes: Object.values(hosts)
          .filter(h => worstOf(assessHost(toHostInput(h, creds, false))).severity === 'CRITICAL').length
      },
      rawData: {
        subnet: targetSubnet,
        hosts: Object.values(hosts),
        credentials: creds,
        // Service-inspection results, frozen into the archive so the report can
        // raise them. Without this they existed only in component state and the
        // PDF — which derives every finding from this blob — raised nothing for a
        // host the operator had just seen come back CRITICAL.
        serviceObservations: Object.entries(vulnScanByTarget).map(([target, v]) => ({ target, ...v })),
        /*
          The other deep-inspection results, frozen into the archive.

          The PDF derives every finding from this blob rather than from the
          `findings` table, so persisting to the database is only half the
          journey — without these the report still raises nothing for an SMBv1
          host the operator watched appear on screen.

          Traceroute is carried as context rather than as observations: "NAT
          boundary detected at hop 4" and "possible firewall" describe the path,
          not a weakness in it, and routing them through the risk rule set would
          pad the findings table with rows that are not findings.
        */
        smbEnum: smbEnumFindings,
        // The TLS inspection, frozen in alongside the rest. Without this the
        // operator can watch an expired certificate appear on screen and then
        // export a report that raises nothing for it, which is the exact failure
        // the SMB and vulnerability results were already fixed for.
        //
        // The error case is deliberately not archived. `sslScanError` means no
        // measurement was taken, and an archive is a record of measurements; a
        // report that listed a failed attempt among its results would invite it
        // to be read as one.
        tlsInspection: sslScanReport,
        // Segmentation, frozen in as context. Not routed through the risk
        // rule set: everything here except gateway reachability is inferred
        // from address ranges, and a findings count is a figure management acts
        // on. The error case is not archived, for the same reason the TLS one
        // is not.
        segmentation: vlanError ? null : vlanReport,
        dirbuster: dirbusterFindings.length
          ? { hits: dirbusterFindings, complete: dirbusterComplete }
          : null,
        traceroutePath: tracerouteAnalysis.length
          ? { target: tracerouteTarget, hops: tracerouteHops, analysis: tracerouteAnalysis }
          : null,
        // How much of each subnet was actually probed, frozen into the archive.
        // Without it the report can say "6 hosts found" but not "6 hosts found
        // out of 253 addresses, 247 of which were never contacted", and those
        // are very different statements to put in front of a manager.
        sweepScopes: Object.values(useIntrusionStore.getState().sweepScopes),
      }
    };

    /*
      Awaited, and a failure is reported.

      `addReport` deliberately rejects rather than swallowing — its own comment says
      a duplicate id "used to fail the INSERT and still show a success toast, so the
      operator believed a report had been stored when nothing had". Two of the four
      callers honour that; this was not one of them. There was no `await` and no
      `.catch`, and the button flipped to ARCHIVED on a timer regardless, so a
      rejection became an unhandled promise in the console and the sweep was gone:
      hosts, credentials, serviceObservations, smbEnum, dirbuster and sweepScopes.

      SQLITE_BUSY while the sweep is still inserting hosts is the likely one, and a
      full disk is the other.
    */
    try {
      await addReport(report);
    } catch (err) {
      setSaving(false);
      console.error('[Intrusion] archive failed:', err);
      showToast(
        `ARCHIVE FAILED: this sweep was NOT stored (${err instanceof Error ? err.message : String(err)}). `
        + 'Nothing has been written — re-run the archive before closing the application.',
        'error',
      );
      return;
    }

    setTimeout(() => {
      setSaving(false);
    }, 1500);
  };


  const getPhaseText = () => {
    if (progress < 30) return "PHASE 1: HOST DISCOVERY (ICMP/ARP PROBING)";
    if (progress < 85) return "PHASE 2: SERVICE ENUMERATION (PORT SCANNING)";
    return "PHASE 3: VULNERABILITY ASSESSMENT";
  };

  /*
    Hardening advice per port — deliberately no severity and no colour.

    This replaced `getPortIntel`, which was a second CVE knowledge base living in
    this component: eight ports, six CVE ids, its own severity per outcome and
    its own colours. Four of those outcomes carried a colour that contradicted
    their own severity label in the same object literal (`severity: 'MEDIUM',
    color: 'text-risk-high'`), it had no data vintage, and it appeared nowhere in
    the method appendix that the report insists is what makes a severity
    auditable.

    Worse, two of its advisories could never reach the report at all. EternalBlue
    and BlueKeep are inferred from the operating system string, while the engine's
    matcher works from banner versions — so an operator saw "CVE-2019-0708
    BlueKeep CRITICAL" on this screen and the exported document said nothing
    about it. That knowledge now lives in `engine/scanner/cve_db.py`
    (`OS_INFERRED_CVES`), arrives on the port like any other advisory, is flagged
    `inferred`, and the rule set reports it at SUSPECTED with its basis stated.

    What is left here is the part that was never a judgment: plain guidance a
    reader can act on. It cannot disagree with the rule set because it no longer
    says anything the rule set also says.
  */
  const PORT_GUIDANCE: Record<number, string> = {
    21: 'FTP is cleartext, including its credentials. Prefer SFTP or FTPS, and check whether anonymous login is permitted.',
    22: 'SSH remote access. Verify key-based authentication is enforced and password login is disabled.',
    23: 'Telnet is cleartext and has no modern justification. Replace with SSH and close the port.',
    80: 'HTTP web service. Check for default credentials and exposed admin panels, and redirect to HTTPS.',
    443: 'HTTPS web service. The certificate and protocol findings for this host are listed separately below.',
    445: 'SMB file sharing. Confirm SMBv1 is disabled and that the share list and permissions are intentional.',
    3389: 'RDP exposed. Enable Network Level Authentication and restrict the port to the networks that need it.',
    5900: 'VNC exposed. Many deployments have no password or a shared one; confirm authentication and tunnel it.',
    8080: 'Alternate HTTP port, often an admin or management interface. Check authentication and whether it should be reachable at all.',
  };


  const getRiskLevel = (host: DiscoveredHost) => {
    const findings = hostFindings(host);
    if (findings.length === 0) {
      // Nothing the rule set raises. A host with no open ports is a different
      // statement from one whose ports raised nothing, so they read differently.
      return host.open_ports.length === 0
        ? { border: 'border-space-500/20', iconText: 'text-gray-500', bg: 'bg-transparent' }
        : { border: 'border-space-500/30', iconText: 'text-gray-400', bg: 'bg-transparent' };
    }
    const c = severityClasses(worstOf(findings).severity);
    return { border: c.border, iconText: c.text, bg: c.bg };
  };

  /*
    Quick Stats, from the rule set.

    These were counted from a hardcoded port list — any of
    445/21/23/3389/5900/22 open made a host "vulnerable" — while the report
    counted the same hosts through `assessHost`. The two headline figures for one
    sweep did not have to agree, and for an SSH-only host they did not: the rule
    set has no rule for port 22.
  */
  const totalHosts = subnetHosts.length;
  const vulnerableHosts = subnetHosts.filter(h => hostFindings(h).length > 0).length;
  const criticalHosts = subnetHosts.filter(h => hostSeverity(h) === 'CRITICAL').length;
  const totalPorts = subnetHosts.reduce((sum, h) => sum + h.open_ports.length, 0);

  // Auto-detect gateway IP from discovered hosts
  const gatewayIp = (() => {
    // 1. Find host explicitly marked as gateway
    const gwHost = subnetHosts.find(h => h.isGateway);
    if (gwHost) return gwHost.ip;
    // 2. Find host ending in .1 (most common gateway)
    const dot1 = subnetHosts.find(h => h.ip.endsWith('.1'));
    if (dot1) return dot1.ip;
    // 3. Find host ending in .254
    const dot254 = subnetHosts.find(h => h.ip.endsWith('.254'));
    if (dot254) return dot254.ip;
    // 4. Fallback to subnet-based calculation
    if (activeSubnet) return activeSubnet.replace('.0/24', '.1');
    return '192.168.1.1';
  })();

  const gatewayMac = (() => {
    const gw = subnetHosts.find(h => h.ip === gatewayIp);
    return gw?.mac || 'ff:ff:ff:ff:ff:ff';
  })();

  return (
    <div className="h-full flex flex-col pt-2 pb-6 px-4 overflow-hidden select-none relative">
      <div className="flex justify-between items-end mb-4">
        <div>
          <h2 className="text-2xl font-bold text-white text-tactical tracking-wider flex items-center gap-3">
            <svg xmlns="http://www.w3.org/2000/svg" className="w-6 h-6 text-neon-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
            </svg>
            INTRUSION / LAN RECON
          </h2>
          <div className="flex gap-2 mt-2">
            <button
              onClick={() => setViewMode('ACTIVE')}
              className={`px-3 py-1 rounded text-xs font-tactical tracking-wider transition-colors border ${viewMode === 'ACTIVE' ? 'bg-neon-500/20 text-neon-400 border-neon-500/50' : 'bg-transparent text-gray-500 border-space-500/30 hover:text-gray-300'}`}
            >
              ACTIVE RECON
            </button>
            <button
              onClick={() => setViewMode('PASSIVE')}
              className={`px-3 py-1 rounded text-xs font-tactical tracking-wider transition-colors border ${viewMode === 'PASSIVE' ? 'bg-neon-500/20 text-neon-400 border-neon-500/50' : 'bg-transparent text-gray-500 border-space-500/30 hover:text-gray-300'}`}
            >
              PASSIVE SIGINT
            </button>
          </div>
          {viewMode === 'ACTIVE' && <p className="text-sm text-gray-500 font-mono mt-2">Deep scanning local subnet layers for active vulnerable nodes.</p>}

          {/* Subnet Selector */}
          {(subnets.length > 0 || targetSubnet || activeSsid) && (
            <div className="flex flex-wrap items-center gap-2 mt-3">
              {activeSsid && (
                <div className="px-3 py-1 bg-neon-500/10 border border-neon-500/30 text-neon-400 rounded text-[10px] font-tactical flex items-center gap-2">
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12.55a11 11 0 0 1 14.08 0"></path><path d="M1.42 9a16 16 0 0 1 21.16 0"></path><path d="M8.53 16.11a6 6 0 0 1 6.95 0"></path><circle cx="12" cy="20" r="1"></circle></svg>
                  {activeSsid}
                </div>
              )}
              {activeSsid && (subnets.length > 0 || targetSubnet) && (
                <div className="w-px h-4 bg-space-500/50 mx-1"></div>
              )}
              {(subnets.length > 0 ? subnets : targetSubnet ? [targetSubnet] : []).map(sub => (
                <button
                  key={sub}
                  onClick={() => setActiveSubnet(sub)}
                  className={`px-3 py-1 rounded text-[10px] font-mono tracking-wider transition-colors border ${activeSubnet === sub
                    ? 'bg-neon-500/20 text-neon-400 border-neon-500/50'
                    : 'bg-space-800 text-gray-400 border-space-500/30 hover:bg-space-700 hover:text-gray-200'
                    }`}
                >
                  {sub}
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="flex gap-4 items-center">
          {isActive ? (
            <div className="text-right mr-4">
              <div className="text-[10px] font-mono text-neon-400 mb-1.5 flex items-center justify-end gap-2">
                <span className="animate-pulse">{getPhaseText()}</span>
                <span className="text-white">[{progress.toFixed(0)}%]</span>
              </div>
              <div className="w-64 h-1.5 bg-space-800 rounded overflow-hidden relative border border-space-500/30">
                <motion.div
                  className="absolute top-0 bottom-0 left-0 bg-neon-500"
                  initial={{ width: 0 }}
                  animate={{ width: `${progress}%` }}
                />
              </div>
            </div>
          ) : (
            <div className="flex gap-3">
              <button
                onClick={async () => {
                  try {
                    const data = await getSessions();
                    setSessions(data);
                    setShowHistory(true);
                  } catch (e) {
                    console.error("Failed to load sessions", e);
                  }
                }}
                className="px-4 py-2 rounded text-sm font-tactical uppercase tracking-wider transition-colors border flex items-center gap-2 bg-space-800 text-gray-300 border-space-500/30 hover:bg-space-700 hover:text-white"
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                SCAN HISTORY
              </button>

              <button
                onClick={() => setShowVault(true)}
                className="px-4 py-2 rounded text-sm font-tactical uppercase tracking-wider transition-colors border flex items-center gap-2 bg-space-800 text-amber-400 border-amber-500/30 hover:bg-space-700 hover:text-amber-300"
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2l1.4-1.4a6.5 6.5 0 1 0-4-4Z" /><circle cx="16.5" cy="7.5" r=".5" fill="currentColor" /></svg>
                OPEN VAULT
              </button>

              {Object.values(hosts).length > 0 && (
                <button
                  onClick={handleArchive}
                  disabled={saving}
                  className={`px-4 py-2 rounded text-sm font-tactical uppercase tracking-wider transition-colors border flex items-center gap-2 ${saving
                    ? 'bg-risk-info/20 border-risk-info/50 text-risk-info cursor-default'
                    : 'bg-space-800 border-space-500/30 text-gray-300 hover:bg-space-700 hover:text-white'
                    }`}
                >
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    {saving ? (
                      <polyline points="20 6 9 17 4 12" />
                    ) : (
                      <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path>
                    )}
                  </svg>
                  {saving ? 'ARCHIVED' : 'SAVE INTEL'}
                </button>
              )}
            </div>
          )}

          <button
            onClick={handleToggle}
            className={`px-6 py-2 rounded text-sm font-tactical uppercase tracking-wider transition-all shadow-lg ${isActive
              ? 'bg-space-800 border border-neon-500 text-neon-400 hover:bg-space-700'
              : 'bg-neon-600 border border-neon-400 text-white hover:bg-neon-500'
              }`}
          >
            {isActive ? 'HALT SCAN' : 'INITIATE SWEEP'}
          </button>
        </div>
      </div>

      {viewMode === 'PASSIVE' ? (
        <div className="flex-1 min-h-0 mt-2">
          <PassiveSigintView />
        </div>
      ) : (
        <>
          {/* Quick Stats Strip */}
          {subnetHosts.length > 0 && (
            <div className="flex items-center gap-1 mb-3 py-2 px-3 bg-space-900/60 rounded border border-space-500/15">
              <span className="text-[9px] font-tactical text-gray-500 tracking-wider mr-2">RECON SUMMARY</span>
              <div className="w-px h-4 bg-space-500/30" />
              <div className="flex items-center gap-1.5 px-3">
                <span className="text-sm font-mono font-bold text-white">{totalHosts}</span>
                <span className="text-[9px] font-tactical text-gray-500">HOSTS</span>
              </div>
              <div className="w-px h-4 bg-space-500/30" />
              <div className="flex items-center gap-1.5 px-3">
                <span className={`text-sm font-mono font-bold ${vulnerableHosts > 0 ? 'text-risk-high' : 'text-gray-500'}`}>{vulnerableHosts}</span>
                <span className="text-[9px] font-tactical text-gray-500">VULN</span>
              </div>
              <div className="w-px h-4 bg-space-500/30" />
              <div className="flex items-center gap-1.5 px-3">
                <span className={`text-sm font-mono font-bold ${criticalHosts > 0 ? 'text-risk-critical animate-pulse' : 'text-gray-500'}`}>{criticalHosts}</span>
                <span className="text-[9px] font-tactical text-gray-500">CRITICAL</span>
              </div>
              <div className="w-px h-4 bg-space-500/30" />
              <div className="flex items-center gap-1.5 px-3">
                <span className="text-sm font-mono font-bold text-amber-400">{totalPorts}</span>
                <span className="text-[9px] font-tactical text-gray-500">PORTS</span>
              </div>
            </div>
          )}

          {/* ───────────────────────── SEGMENTATION ─────────────────────────
              `start_vlan_detect` had no caller either, and unlike the TLS scan
              it belongs to the network rather than to a host: it reads every
              subnet the sweep found, so it sits beside the recon summary and not
              in the host drawer.

              Most of what it returns is inferred rather than measured, and the
              panel is built around saying which is which. A VLAN id read off the
              third octet renders as a guess with its basis attached; a gateway
              assumed to be the first usable address says it is assumed; and only
              `gateway_alive` — one ping, one answer — is shown as a measurement.
              The engine now ships the basis strings alongside the values so this
              cannot drift apart from what the numbers actually are. */}
          {subnetHosts.length > 0 && (
            <div className="mb-3">
              {vlanState === 'IDLE' && (
                <button
                  onClick={async () => {
                    setVlanReport(null);
                    setVlanError(null);
                    try {
                      // No subnets passed: the engine reads them from the LAN
                      // scanner, which knows what was actually swept. Sending the
                      // frontend's idea of the subnets would re-derive it from
                      // host addresses and quietly disagree.
                      await engineIPC.send('start_vlan_detect', {});
                      setVlanState('SCANNING');
                    } catch (e) {
                      setVlanError(`The segmentation check could not be started — ${e instanceof Error ? e.message : String(e)}. Nothing was analysed.`);
                      setVlanState('DONE');
                    }
                  }}
                  className="w-full py-2 bg-space-900/60 hover:bg-space-800 border border-space-500/20 hover:border-indigo-500/40 text-gray-400 hover:text-indigo-300 text-[10px] font-tactical tracking-wider rounded transition-all flex items-center justify-center gap-2"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="2" width="8" height="8" rx="1" /><rect x="14" y="2" width="8" height="8" rx="1" /><rect x="2" y="14" width="8" height="8" rx="1" /><rect x="14" y="14" width="8" height="8" rx="1" /></svg>
                  ANALYSE NETWORK SEGMENTATION
                </button>
              )}

              {vlanState === 'SCANNING' && (
                <div className="w-full flex items-center justify-center gap-2 py-2 bg-space-900/60 border border-indigo-500/40 rounded">
                  <svg className="w-3.5 h-3.5 text-indigo-400 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" /></svg>
                  <span className="text-indigo-300 font-mono text-[10px]">{vlanProgress || 'PROBING SEGMENT BOUNDARIES…'}</span>
                </div>
              )}

              {vlanState === 'DONE' && (() => {
                /*
                  Collapsed to one line by default, and a table when opened.

                  The first version of this put every subnet on two lines with
                  "(basis not stated)" written out eight times, and ran to about
                  470px. It did not overlap the host cards — it is an ordinary
                  block and they sit in a `flex-1 overflow-y-auto` sibling — but
                  every pixel it took came out of their viewport, so with four
                  subnets the operator saw the bottom edge of two cards and
                  nothing else. Squeezing looks exactly like covering.

                  The qualification is said once, in a column header and a
                  footnote, instead of once per value. That was the single
                  largest thing on screen and it was repetition, not information.
                */
                const rows = Array.isArray(vlanReport?.vlan_map) ? vlanReport.vlan_map : [];
                const findings = Array.isArray(vlanReport?.findings) ? vlanReport.findings : [];
                const answered = rows.filter((v: any) => v?.gateway_alive === true).length;
                const routed = findings.find((f: any) => f?.type === 'inter_vlan');
                const worst = findings.find((f: any) => f?.severity === 'HIGH');

                // The engine's own words for why a value is what it is. Collected
                // rather than assumed, so a future basis reaches the footnote
                // instead of being quietly replaced by this file's idea of it.
                const bases = (key: string) => [...new Set(
                  rows.map((v: any) => v?.[key]).filter((b: unknown): b is string => typeof b === 'string' && !!b)
                )];
                /*
                  How many machines are in each range, and whether anyone looked.

                  The trap this avoids is printing `0`. A sweep covers one subnet
                  at a time, so the segmentation map routinely lists three ranges
                  nothing has ever probed -- and `0 found` for those would read as
                  "we looked and the VLAN is empty", which is the exact shape of
                  claim this project exists not to make. A range with no sweep
                  scope says so instead.

                  The coverage figure comes from the sweep's own record rather
                  than from the host count, because "2 found" means very different
                  things out of 254 addresses probed and out of 6.
                */
                const statsFor = (cidr: string) => {
                  const scope = sweepScopes[cidr];
                  if (!scope) return null;
                  return {
                    found: Object.values(hosts).filter(h => ipInCidr(h.ip, cidr)).length,
                    probed: scope.addressesProbed,
                    inRange: scope.addressesInRange,
                  };
                };

                const vlanBasis = bases('vlan_id_basis');
                const gwBasis = bases('gateway_basis');

                return (
                  <div className="w-full bg-space-950 border border-indigo-500/30 rounded">
                    {/* The summary line, which is the whole result for most runs. */}
                    <div className="flex items-center gap-2 px-3 py-2">
                      <button
                        onClick={() => setVlanOpen(o => !o)}
                        className="flex items-center gap-2 flex-1 min-w-0 text-left group"
                        aria-expanded={vlanOpen}
                      >
                        <svg xmlns="http://www.w3.org/2000/svg"
                          className={`w-3 h-3 shrink-0 text-gray-500 group-hover:text-indigo-300 transition-transform ${vlanOpen ? 'rotate-90' : ''}`}
                          viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                          <polyline points="9 18 15 12 9 6" />
                        </svg>
                        <span className="text-indigo-300 font-tactical tracking-widest text-[10px] shrink-0">SEGMENTATION</span>
                        {vlanError ? (
                          <span className="text-[10px] font-mono text-risk-high truncate">could not be analysed</span>
                        ) : (
                          <span className="text-[10px] font-mono text-gray-400 truncate">
                            {rows.length} subnet(s) · {answered} gateway(s) answered
                            {routed && <span className="text-risk-medium"> · inter-VLAN routing</span>}
                            {worst && <span className="text-risk-high"> · {String(worst.message ?? 'HIGH finding').slice(0, 48)}</span>}
                          </span>
                        )}
                      </button>
                      <button
                        onClick={() => setVlanState('IDLE')}
                        title="Dismiss"
                        className="p-1 text-gray-500 hover:text-white transition-colors rounded hover:bg-space-800 shrink-0"
                      >
                        <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                      </button>
                    </div>

                    {vlanOpen && (
                      <div className="border-t border-space-500/20 px-3 py-2">
                        {vlanError ? (
                          <div className="text-[10px] font-mono text-risk-high leading-relaxed">
                            {vlanError}
                            <div className="text-gray-400 mt-1">
                              Nothing here says this network is segmented or flat — only that it was not analysed.
                            </div>
                          </div>
                        ) : (
                          <>
                            {/* The findings first: they are the result, the table is the evidence. */}
                            {findings.length > 0 && (
                              <div className="space-y-1 mb-2">
                                {findings.map((f: any, i: number) => (
                                  <div key={i} className={`text-[10px] font-mono leading-relaxed rounded px-2 py-1 border ${
                                    f.severity === 'HIGH' ? 'bg-risk-high/10 border-risk-high/40 text-risk-high'
                                      : 'bg-space-900/60 border-space-500/20 text-gray-400'
                                  }`}>
                                    <span className="font-bold">{String(f?.severity ?? 'INFO')}</span> — {String(f?.message ?? 'no message')}
                                  </div>
                                ))}
                              </div>
                            )}

                            {rows.length > 0 && (
                              // Capped and scrolled: a sweep of a dozen subnets must
                              // not take the host list's viewport with it, which is
                              // the fault this whole rewrite is for.
                              <div className="max-h-48 overflow-y-auto no-scrollbar">
                                <table className="w-full text-[10px] font-mono border-collapse">
                                  <thead className="sticky top-0 bg-space-950">
                                    <tr className="text-gray-600 text-left">
                                      <th className="font-normal pb-1 pr-3">SUBNET</th>
                                      <th className="font-normal pb-1 pr-3">VLAN<span className="text-gray-700">*</span></th>
                                      <th className="font-normal pb-1 pr-3">GATEWAY<span className="text-gray-700">*</span></th>
                                      <th className="font-normal pb-1 pr-3">CLASS</th>
                                      <th className="font-normal pb-1 pr-3">HOSTS</th>
                                      <th className="font-normal pb-1 text-right">GATEWAY</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {rows.map((v: any, i: number) => (
                                      <tr key={i} className="border-t border-space-500/10">
                                        <td className="py-1 pr-3 text-gray-200 whitespace-nowrap">{String(v?.subnet ?? '?')}</td>
                                        {v?.error ? (
                                          <td colSpan={5} className="py-1 text-risk-high">could not be read: {String(v.error)}</td>
                                        ) : (
                                          <>
                                            <td className="py-1 pr-3 text-gray-400">{v?.vlan_id != null ? String(v.vlan_id) : '—'}</td>
                                            <td className="py-1 pr-3 text-gray-400 whitespace-nowrap">{v?.gateway ? String(v.gateway) : '—'}</td>
                                            <td className="py-1 pr-3 text-gray-500 whitespace-nowrap">{String(v?.network_class ?? '—')}</td>
                                            {(() => {
                                              const stats = statsFor(String(v?.subnet ?? ''));
                                              return (
                                                <td
                                                  className={`py-1 pr-3 whitespace-nowrap ${stats ? 'text-gray-300' : 'text-gray-600'}`}
                                                  title={stats
                                                    ? `${stats.found} host(s) answered out of ${stats.probed} address(es) probed in a range of ${stats.inRange}`
                                                    : 'no sweep has covered this range, so nothing is known about what is in it'}
                                                >
                                                  {stats
                                                    ? <>{stats.found} found <span className="text-gray-600">/ {stats.probed} probed</span></>
                                                    : 'not swept'}
                                                </td>
                                              );
                                            })()}
                                            {/*
                                              Three states, and the third is not "no".
                                              A /31 has no first usable host, so nothing
                                              was pinged — printing "no" for it would
                                              report a gateway that failed to answer.
                                            */}
                                            <td className={`py-1 text-right whitespace-nowrap ${
                                              v?.gateway_alive === true ? 'text-signal-strong'
                                                : v?.gateway_alive === false ? 'text-gray-500'
                                                : 'text-gray-600'
                                            }`}>
                                              {v?.gateway_alive === true ? 'answered'
                                                : v?.gateway_alive === false ? 'no reply'
                                                : 'not probed'}
                                            </td>
                                          </>
                                        )}
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            )}

                            {/*
                              The qualification, once.

                              Built from the basis strings the engine sent rather
                              than written here, so a column whose derivation
                              changes cannot keep a footnote that describes the
                              old one.
                            */}
                            <div className="text-gray-600 text-[10px] font-mono leading-relaxed mt-2 pt-2 border-t border-space-500/20">
                              {`* ${vlanBasis.length === 1 ? `VLAN ${vlanBasis[0]}` : 'VLAN id inferred'}; ${gwBasis.length === 1 ? `gateway ${gwBasis[0]}` : 'gateway assumed'}. Read from the address ranges, not read from any switch — only the gateway reachability column was measured. Confirm against the switch configuration before recording this as the network’s segmentation. HOSTS counts what this sweep found in each range and how much of it was probed; a range no sweep has covered says so rather than showing zero.`}
                            </div>
                          </>
                        )}
                      </div>
                    )}
                  </div>
                );
              })()}
            </div>
          )}

          {/* Quick Filters + Search */}
          {subnetHosts.length > 0 && (
            <div className="flex items-center gap-2 mb-4 border-b border-space-500/20 pb-3">
              {(['ALL', 'WINDOWS', 'LINUX/UNIX', 'VULNERABLE'] as FilterType[]).map((f) => (
                <button
                  key={f}
                  onClick={() => setFilterType(f)}
                  className={`px-4 py-1.5 rounded-sm text-[10px] font-tactical tracking-wider border transition-colors whitespace-nowrap ${filterType === f
                    ? 'bg-space-700 text-white border-space-400'
                    : 'bg-transparent text-gray-500 border-space-500/30 hover:bg-space-800 hover:text-gray-300'
                    }`}
                >
                  {f}
                </button>
              ))}

              {/* Search — fills remaining space */}
              <div className="relative flex-1 ml-1">
                <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5 text-gray-500 absolute left-2.5 top-1/2 -translate-y-1/2" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></svg>
                <input
                  type="text"
                  placeholder="Search IP, hostname, port, service..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-space-900 border border-space-500/30 rounded pl-8 pr-8 py-1.5 text-xs font-mono text-gray-300 placeholder-gray-600 focus:border-neon-500/50 focus:outline-none transition-colors"
                />
                {searchQuery && (
                  <button onClick={() => setSearchQuery('')} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300">
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
                  </button>
                )}
              </div>
              <span className="text-[10px] text-gray-500 font-mono whitespace-nowrap">{hostList.length} Nodes</span>
            </div>
          )}

          <div className="flex-1 overflow-y-auto no-scrollbar pb-10">
            {!isActive && subnetHosts.length === 0 && (
              hasScanned ? (
                <div className="h-full flex flex-col items-center justify-center border-2 border-dashed border-space-500/20 rounded-xl p-6 bg-space-900/30">
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-16 h-16 text-risk-high mb-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line>
                  </svg>
                  <h3 className="text-xl font-tactical text-gray-300 tracking-wider mb-4">NO TARGETS DETECTED</h3>

                  <div className="bg-space-950/60 border border-space-500/30 rounded-lg p-5 max-w-2xl w-full text-left">
                    <h4 className="text-xs font-tactical text-risk-high mb-3 flex items-center gap-2">
                      <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="10.29 3.86 1.82 18 2 21 22 21 22.18 18 13.71 3.86 10.29 3.86"></polygon><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                      TACTICAL ADVISORY: ZERO NODE RESPONSE
                    </h4>
                    <ul className="space-y-3 text-sm font-mono text-gray-400">
                      <li className="flex gap-2">
                        <span className="text-neon-500 mt-0.5">»</span>
                        <div><strong className="text-gray-300">AP Isolation Active:</strong> Public Wi-Fi networks (hotels, cafes, hospitals) typically block client-to-client communication. This is a network restriction, not a scanner fault.</div>
                      </li>
                      <li className="flex gap-2">
                        <span className="text-neon-500 mt-0.5">»</span>
                        <div><strong className="text-gray-300">Firewall / Stealth Mode:</strong> Targets may be dropping ICMP (Ping) and ARP probes entirely. Try running a <span className="text-neon-400">DEEP SCAN</span> to bypass basic filters.</div>
                      </li>
                      <li className="flex gap-2">
                        <span className="text-neon-500 mt-0.5">»</span>
                        <div><strong className="text-gray-300">Subnet Mismatch:</strong> Ensure the target subnet ({targetSubnet}) aligns with the physical network architecture.</div>
                      </li>
                    </ul>
                  </div>
                </div>
              ) : (
                <div className="h-full flex flex-col items-center justify-center border-2 border-dashed border-space-500/20 rounded-xl p-10 bg-space-900/30 relative overflow-hidden group">
                  {/* Tactical Radar Background */}
                  <div className="absolute inset-0 flex items-center justify-center opacity-[0.03] group-hover:opacity-10 transition-opacity duration-1000">
                    <div className="w-[500px] h-[500px] rounded-full border-2 border-space-400 animate-[spin_10s_linear_infinite] border-t-transparent border-l-transparent"></div>
                    <div className="absolute w-[350px] h-[350px] rounded-full border border-space-400 border-dashed animate-[spin_15s_linear_infinite_reverse]"></div>
                    <div className="absolute w-[200px] h-[200px] rounded-full border border-space-400"></div>
                    <div className="absolute w-full h-[1px] bg-space-400"></div>
                    <div className="absolute h-full w-[1px] bg-space-400"></div>
                  </div>

                  <div className="relative z-10 flex flex-col items-center">
                    <img src="/awaiting.svg" alt="Awaiting Orders" className="w-36 h-36 opacity-50 mb-4" />
                    <h3 className="text-lg font-tactical text-gray-400 tracking-wider mb-2">AWAITING ORDERS</h3>
                    <p className="text-sm font-mono text-gray-600 max-w-md text-center">
                      Initiate subnet sweep to map out connected devices, identify open service ports, and evaluate potential intrusion vectors within the Local Area Network.
                    </p>
                  </div>
                </div>
              )
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <AnimatePresence>
                {hostList.map((host) => {
                  const risk = getRiskLevel(host);
                  return (
                    <motion.div
                      key={host.ip}
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                      exit={{ opacity: 0, scale: 0.95 }}
                      transition={{ duration: 0.2 }}
                      className={`glass-card p-5 relative overflow-hidden group border ${risk.border} ${risk.bg} transition-all duration-300`}
                    >
                      {host.isGateway && (
                        <div className="absolute top-0 right-0 bg-neon-500/10 px-3 py-1 text-[10px] font-tactical text-neon-400 border-b border-l border-neon-500/30 rounded-bl-lg">
                          NETWORK GATEWAY
                        </div>
                      )}
                      {newDevices.includes(host.ip) && !host.isGateway && (
                        <div className="absolute top-0 right-0 bg-neon-500/20 px-3 py-1 text-[10px] font-tactical text-neon-400 border-b border-l border-neon-500/50 rounded-bl-lg animate-pulse">
                          NEW TARGET
                        </div>
                      )}

                      <div className="flex items-start gap-4 mb-4 mt-2">
                        <div className="flex items-center justify-center w-14 h-14 shrink-0">
                          {(() => {
                            const os = host.os || '';
                            const iconClass = "w-14 h-14 object-contain";
                            // Priority-ordered icon matching
                            const iconMap: [RegExp, string][] = [
                              [/Apple|macOS|iOS/i, 'Apple'],
                              [/Android/i, 'Android'],
                              [/Console|Nintendo|Xbox|PlayStation/i, 'Console'],
                              [/TV|Media|Chromecast/i, 'TV'],
                              [/Camera|NVR|DVR/i, 'Camera'],
                              [/Printer/i, 'Printer'],
                              [/Windows Server/i, 'Windows'],
                              [/Database|MSSQL|Memcached|Cache/i, 'Database'],
                              [/Virtual Machine|Hyper-V|VirtualBox|VMware/i, 'VM'],
                              [/Docker|Container|Kubernetes/i, 'Docker'],
                              [/Hypervisor|ESXi|Proxmox/i, 'Server'],
                              [/IPMI|iLO|iDRAC|Server Management/i, 'Server'],
                              [/Firewall|pfSense|FortiGate/i, 'Firewall'],
                              [/IoT Device|IoT Smart/i, 'IoT'],
                              [/Router|Cisco|MikroTik/i, 'Router'],
                              [/Smart Speaker|Sonos|Alexa/i, 'Specker'],
                              [/IoT|Smart Device/i, 'IoT'],
                              [/Storage|NAS|Synology|QNAP/i, 'NAS'],
                              [/Mobile Phone|Random MAC/i, 'Android'],
                              [/Windows/i, 'Windows'],
                              [/Linux|Unix|Raspberry/i, 'Linux'],
                              [/Server/i, 'Server'],
                            ];
                            const match = iconMap.find(([re]) => re.test(os));
                            const icon = match ? match[1] : 'Unknown';
                            return icon === 'Unknown'
                              ? <img src={`/intrusion_icons/Unknown.svg`} alt="Unknown" className={`${iconClass} opacity-70`} />
                              : <img src={`/intrusion_icons/${icon}.svg`} alt={icon} className={iconClass} />;
                          })()}
                        </div>
                        <div>
                          <h3 className={`text-xl font-mono font-bold ${risk.iconText.replace('text-', 'text-').replace('-500', '-300')}`}>{host.ip}</h3>
                          <p className="text-xs font-mono text-gray-400 mt-1">{host.hostname}</p>
                          <p className="text-[10px] font-tactical text-gray-500 uppercase mt-1">{host.os}</p>
                        </div>
                      </div>

                      <div className="bg-space-950/60 rounded border border-space-500/20 p-3">
                        <div className="text-[10px] font-mono text-gray-500 mb-2">IDENTIFIED SERVICES</div>
                        {host.open_ports.length > 0 ? (
                          <div className="flex flex-wrap gap-2">
                            {host.open_ports.map((p, i) => {
                              /*
                                Coloured by what the rule set says about this
                                port, not by the port number. The old branch
                                painted anything in a hardcoded list HIGH,
                                including port 22 — which the rule set does not
                                consider a finding at all.
                              */
                              const sev = portSeverity(host, p.port);
                              const badgeStyle = sev
                                ? `${severityClasses(sev).bg} ${severityClasses(sev).border} ${severityClasses(sev).text}`
                                : 'bg-space-800 border-space-500/50 text-gray-300';
                              const dotStyle = sev
                                ? `${severityClasses(sev).dot}${sev === 'CRITICAL' || sev === 'HIGH' ? ' animate-pulse' : ''}`
                                : 'bg-gray-400';

                              return (
                                <span key={`${p.port}-${i}`} className={`text-xs font-mono border px-2 py-0.5 rounded flex items-center gap-1.5 transition-colors cursor-default ${badgeStyle}`}>
                                  <span className={`w-1.5 h-1.5 rounded-full ${dotStyle}`} />
                                  {p.port} {p.service}
                                </span>
                              );
                            })}
                          </div>
                        ) : (
                          <span className="text-xs font-mono text-gray-600 block">No open target ports detected.</span>
                        )}
                      </div>

                      <button
                        onClick={() => setSelectedHostIp(host.ip)}
                        className={`w-full mt-4 py-2 border ${risk.border} text-xs font-tactical uppercase tracking-widest rounded transition-all duration-300 bg-space-900/50 hover:bg-neon-500 hover:text-space-950 hover:border-neon-500 ${risk.iconText.replace('text-', 'text-')} hover:text-space-950`}
                      >
                        Analyze Node
                      </button>
                    </motion.div>
                  );
                })}
              </AnimatePresence>
            </div>
          </div>
        </>
      )}

      {/* Sweep Configurator Modal */}
      <AnimatePresence>
        {showConfig && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="absolute inset-0 z-50 flex items-center justify-center bg-space-950/80 backdrop-blur-sm p-4"
          >
            <motion.div
              initial={{ scale: 0.95, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.95, y: 20 }}
              className="bg-space-900 border border-neon-500/30 rounded-xl shadow-2xl max-w-lg w-full overflow-hidden"
            >
              <div className="bg-space-950/50 px-6 py-4 border-b border-space-500/20 flex justify-between items-center">
                <div className="flex items-center gap-3">
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5 text-neon-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="3"></circle>
                    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
                  </svg>
                  <h3 className="text-white font-tactical tracking-wider">SWEEP CONFIGURATOR</h3>
                </div>
                <button onClick={() => setShowConfig(false)} className="text-gray-500 hover:text-white transition-colors">
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                </button>
              </div>

              <div className="p-6">
                <div className="mb-6 bg-space-950/30 p-4 rounded-lg border border-space-500/20">
                  <div className="text-[10px] font-mono text-gray-500 mb-1">TARGET NETWORK</div>
                  <div className="text-neon-400 font-mono flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-risk-low animate-pulse"></span>
                    {subnets.length > 1
                      ? `Auto-scanning ${subnets.length} subnets...`
                      : activeSubnet || targetSubnet || "Auto-detecting local subnet..."
                    }
                  </div>
                  {subnets.length > 1 && (
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      {subnets.map(s => (
                        <span key={s} className="text-[9px] font-mono text-gray-400 bg-space-800/80 border border-space-500/20 px-1.5 py-0.5 rounded">{s}</span>
                      ))}
                    </div>
                  )}
                </div>

                <div className="text-[10px] font-mono text-gray-500 mb-3 uppercase tracking-wider">Select Arsenal</div>
                <div className="space-y-3">
                  <button
                    onClick={() => setScanMode('QUICK')}
                    className={`w-full flex items-center gap-4 p-4 rounded-lg border transition-all text-left ${scanMode === 'QUICK' ? 'bg-space-800 border-neon-500' : 'bg-space-950/30 border-space-500/20 hover:border-space-500/50 hover:bg-space-800/50'}`}
                  >
                    <div className={`p-2 rounded ${scanMode === 'QUICK' ? 'bg-neon-500/20 text-neon-400' : 'bg-space-800 text-gray-400'}`}>
                      <svg xmlns="http://www.w3.org/2000/svg" className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <div className={`font-tactical tracking-wider ${scanMode === 'QUICK' ? 'text-white' : 'text-gray-300'}`}>QUICK SWEEP</div>
                        <span className="text-[9px] font-mono text-gray-600 bg-space-950/50 px-1.5 py-0.5 rounded">9 PORTS</span>
                      </div>
                      <div className="text-xs font-mono text-gray-500 mt-1">Scans top 9 common ports (FTP, SSH, Telnet, HTTP, HTTPS, SMB, NetBIOS, RDP, HTTP-Alt).</div>
                    </div>
                  </button>

                  {/*
                    Port counts are stated to the operator and end up in the
                    report as the scope of the sweep, so they have to match
                    TARGET_PORTS and the DEEP block in engine/scanner/lan.py.
                    They drifted once already: seventeen ports were added for
                    extended VA coverage and this card still said 30 TCP.
                  */}
                  <button
                    onClick={() => setScanMode('DEEP')}
                    className={`w-full flex items-center gap-4 p-4 rounded-lg border transition-all text-left ${scanMode === 'DEEP' ? 'bg-space-800 border-risk-high' : 'bg-space-950/30 border-space-500/20 hover:border-space-500/50 hover:bg-space-800/50'}`}
                  >
                    <div className={`p-2 rounded ${scanMode === 'DEEP' ? 'bg-risk-high/20 text-risk-high' : 'bg-space-800 text-gray-400'}`}>
                      <svg xmlns="http://www.w3.org/2000/svg" className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><circle cx="12" cy="12" r="6"></circle><circle cx="12" cy="12" r="2"></circle></svg>
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <div className={`font-tactical tracking-wider ${scanMode === 'DEEP' ? 'text-white' : 'text-gray-300'}`}>DEEP SCAN</div>
                        <span className="text-[9px] font-mono text-gray-600 bg-space-950/50 px-1.5 py-0.5 rounded">43 PORTS</span>
                      </div>
                      <div className="text-xs font-mono text-gray-500 mt-1">36 TCP + 7 UDP ports. Includes databases, APIs, AD/Kerberos, credential testing, and SSL analysis.</div>
                    </div>
                  </button>

                  <button
                    onClick={() => setScanMode('STEALTH')}
                    className={`w-full flex items-center gap-4 p-4 rounded-lg border transition-all text-left ${scanMode === 'STEALTH' ? 'bg-space-800 border-gray-400' : 'bg-space-950/30 border-space-500/20 hover:border-space-500/50 hover:bg-space-800/50'}`}
                  >
                    <div className={`p-2 rounded ${scanMode === 'STEALTH' ? 'bg-gray-700 text-gray-300' : 'bg-space-800 text-gray-400'}`}>
                      <svg xmlns="http://www.w3.org/2000/svg" className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M2 12h3l3 -9l5 18l3 -9h5"></path></svg>
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <div className={`font-tactical tracking-wider ${scanMode === 'STEALTH' ? 'text-white' : 'text-gray-300'}`}>STEALTH MODE</div>
                        <span className="text-[9px] font-mono text-gray-600 bg-space-950/50 px-1.5 py-0.5 rounded">9 PORTS</span>
                      </div>
                      <div className="text-xs font-mono text-gray-500 mt-1">Ports shuffled and probed one at a time, with randomized gaps between ports and hosts. Quieter and far less bursty than a normal sweep — but a full-subnet scan is still a pattern an IDS correlates, so read this as lower-noise, not invisible.</div>
                      {scanMode === 'STEALTH' && (
                        <div className="mt-2 space-y-1.5">
                          <div className="flex items-start gap-1.5 text-[10px] font-mono text-amber-400/80 bg-amber-500/5 border border-amber-500/15 rounded px-2 py-1.5">
                            <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3 shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                            <span>10× slower than Quick Sweep. Scans ports sequentially with random jitter to mimic organic traffic patterns.</span>
                          </div>
                          <div className="flex items-start gap-1.5 text-[10px] font-mono text-gray-500 bg-space-950/50 border border-space-500/15 rounded px-2 py-1.5">
                            <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3 shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                            <span>May detect fewer hosts than QUICK/DEEP. Use on networks with active IDS/IPS monitoring only.</span>
                          </div>
                        </div>
                      )}
                    </div>
                  </button>
                </div>

                {/* Estimated Time Indicator */}
                <div className="mt-4 p-3 rounded-lg bg-space-950/40 border border-space-500/15 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                    <span className="text-[10px] font-mono text-gray-500">ESTIMATED TIME {subnets.length > 1 ? `(${subnets.length} SUBNETS)` : ''}</span>
                  </div>
                  <span className={`text-[10px] font-tactical tracking-wider ${scanMode === 'QUICK' ? 'text-neon-400' : scanMode === 'DEEP' ? 'text-risk-high' : 'text-gray-400'}`}>
                    {scanMode === 'QUICK'
                      ? subnets.length > 2 ? '~1 — 2 MIN' : '~30 SEC — 1 MIN'
                      : scanMode === 'DEEP'
                        ? subnets.length > 2 ? '~5 — 10 MIN' : '~3 — 5 MIN'
                        : subnets.length > 2 ? '~10 — 30 MIN' : '~5 — 15 MIN'
                    }
                  </span>
                </div>
              </div>

              <div className="p-4 bg-space-950/80 border-t border-space-500/20 flex justify-end gap-3">
                <button
                  onClick={() => setShowConfig(false)}
                  className="px-4 py-2 text-xs font-tactical text-gray-400 hover:text-white transition-colors"
                >
                  CANCEL
                </button>
                <button
                  onClick={executeSweep}
                  className="px-6 py-2 bg-neon-600 hover:bg-neon-500 text-white text-xs font-tactical tracking-wider rounded transition-colors"
                >
                  ENGAGE TARGET
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Node Intelligence Drawer */}
      <AnimatePresence>
        {selectedHost && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => { setSelectedHostIp(null); setBruteForceState('IDLE'); setCrackedCreds(null); setTracerouteState('IDLE'); setTracerouteHops([]); setTracerouteAnalysis([]); setTracerouteTarget(null); }}
              className="fixed inset-0 z-[100] bg-space-950/60 backdrop-blur-sm"
            />
            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="fixed top-0 right-0 bottom-0 w-full max-w-md bg-space-900 border-l border-space-500/30 z-[110] shadow-[-20px_0_50px_rgba(0,0,0,0.5)] flex flex-col"
            >
              <div className="p-6 border-b border-space-500/20 bg-space-950/50 flex justify-between items-start">
                <div>
                  <div className="text-[10px] font-mono text-neon-500 mb-1">TARGET ACQUIRED</div>
                  <h2 className="text-2xl font-mono font-bold text-white tracking-wider">{selectedHost.ip}</h2>
                  <p className="text-sm font-tactical text-gray-400 mt-1">{selectedHost.hostname}</p>
                </div>
                <button onClick={() => { setSelectedHostIp(null); setBruteForceState('IDLE'); setCrackedCreds(null); }} className="p-2 text-gray-500 hover:text-white bg-space-800 border border-space-500/20 hover:border-space-500/50 rounded transition-colors">
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                </button>
              </div>

              <div className="flex-1 overflow-y-auto p-6 space-y-6">
                {/* OS Fingerprint */}
                <div className="bg-space-950/30 rounded-lg border border-space-500/20 p-4">
                  <h3 className="text-[10px] font-mono text-gray-500 mb-3 uppercase tracking-wider">Fingerprint Data</h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <div className="text-[10px] font-tactical text-gray-600 mb-1">OPERATING SYSTEM</div>
                      <div className="text-sm font-mono text-gray-300">{selectedHost.os}</div>

                      <div className="text-[10px] font-tactical text-gray-600 mt-3 mb-1">HARDWARE VENDOR</div>
                      <div className="text-sm font-mono text-gray-300">{selectedHost.vendor || 'Unknown / Unassigned'}</div>
                    </div>
                    <div>
                      <div className="text-[10px] font-tactical text-gray-600 mb-1">MAC ADDRESS</div>
                      <div className="text-sm font-mono text-gray-300">{selectedHost.mac ? selectedHost.mac.toUpperCase() : 'XX:XX:XX:XX:XX:XX'}</div>
                    </div>
                  </div>
                </div>

                {/* Sighting history. The query behind this existed but nothing
                    ever called it, so "have we seen this device before?" — the
                    first question about an unexpected host — was unanswerable. */}
                {selectedHost.mac && (
                  <div>
                    <h3 className="text-[10px] font-mono text-gray-500 mb-3 uppercase tracking-wider flex items-center justify-between">
                      <span>Sighting History</span>
                      <span className="text-gray-600 border border-gray-600/30 px-1.5 py-0.5 rounded text-[8px]">
                        {deviceHistory.length} RECORD{deviceHistory.length === 1 ? '' : 'S'}
                      </span>
                    </h3>
                    {historyLoading ? (
                      <div className="text-xs font-mono text-gray-600">Loading history…</div>
                    ) : deviceHistory.length === 0 ? (
                      <div className="text-xs font-mono text-gray-600">
                        First time this MAC has been recorded. Nothing to compare against yet.
                      </div>
                    ) : (
                      <div className="space-y-2">
                        {addressChanges.length > 1 && (
                          <div className="text-[10px] font-tactical text-risk-high bg-risk-high/10 border border-risk-high/30 rounded px-2 py-1.5">
                            This MAC has held {addressChanges.length} different IP addresses
                            ({addressChanges.map(a => a.ip).join(', ')}) — the device is roaming or
                            being re-addressed.
                          </div>
                        )}
                        <div className="max-h-40 overflow-y-auto space-y-1">
                          {deviceHistory.slice(0, 20).map((h, i) => (
                            <div key={`${h.session_id}-${i}`} className="flex items-center justify-between text-[10px] font-mono bg-space-900 border border-space-500/20 rounded px-2 py-1">
                              <span className="text-gray-300">{h.ip}</span>
                              <span className="text-gray-600 truncate max-w-[120px]">{h.subnet || '—'}</span>
                              <span className="text-gray-500">{new Date(h.discovered_at).toLocaleString()}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Vulnerability Matrix */}
                <div>
                  <h3 className="text-[10px] font-mono text-gray-500 mb-3 uppercase tracking-wider flex items-center justify-between">
                    <span>Vulnerability Matrix</span>
                    <span className="text-gray-600 border border-gray-600/30 px-1.5 py-0.5 rounded text-[8px]">CVE DATABASE</span>
                  </h3>
                  {selectedHost.open_ports.length > 0 ? (
                    <div className="space-y-3">
                      {(selectedHost.open_ports || []).map((p: any, i: number) => {
                        /*
                          The severity on this card is the rule set's, and the
                          guidance underneath is advice rather than a verdict.
                          They used to be one object from `getPortIntel`, which is
                          how a card could show `MEDIUM` in HIGH's colour.
                        */
                        const sev = portSeverity(selectedHost, p.port);
                        const guidance = PORT_GUIDANCE[p.port];
                        return (
                          <div key={`${p.port}-${i}`} className={`p-4 rounded-lg border ${sev ? `${severityClasses(sev).border} bg-space-800/50` : 'border-space-500/20 bg-space-950/30'}`}>
                            <div className="flex justify-between items-start mb-2">
                              <div className="flex items-center gap-2">
                                <span className={`text-[10px] font-mono px-2 py-0.5 rounded bg-space-900 border ${sev ? severityClasses(sev).border : 'border-space-500/50'} text-gray-300`}>
                                  {p.protocol || 'TCP'} {p.port}
                                </span>
                                <span className="text-sm font-tactical text-gray-400">{p.service}</span>
                              </div>
                              {sev && (
                                <span className={`text-[10px] font-tactical px-2 py-0.5 rounded border ${severityClasses(sev).border} ${severityClasses(sev).text}`}>
                                  {sev}
                                </span>
                              )}
                            </div>

                            {!(p.cves && p.cves.length > 0) && guidance ? (
                              <div className="mt-3 text-xs font-mono text-gray-500">{guidance}</div>
                            ) : p.cves && p.cves.length > 0 ? (
                              <div className="mt-3 space-y-2">
                                {p.cves.map((c: any, ci: number) => (
                                  <div key={ci}>
                                    <div className="text-xs font-mono text-gray-400">
                                      <span className={severityClasses(c.severity).text}>{c.cve}</span> — {c.description}
                                    </div>
                                    {/* Exploit Suggestion Panel */}
                                    {c.exploit && (
                                      <div className="mt-2 ml-2 p-2.5 rounded border border-amber-500/20 bg-amber-500/5 space-y-2">
                                        <div className="text-[9px] font-tactical text-amber-400 tracking-wider flex items-center gap-1.5">
                                          <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
                                          EXPLOIT SUGGESTION
                                        </div>
                                        {c.exploit.metasploit && (
                                          <div className="flex items-center gap-2">
                                            <span className="text-[9px] font-tactical text-gray-500 shrink-0 w-14">MSF:</span>
                                            <code className="text-[10px] font-mono text-red-400 bg-space-900 px-1.5 py-0.5 rounded border border-space-500/20 flex-1 truncate">{c.exploit.metasploit}</code>
                                            <button onClick={() => { navigator.clipboard.writeText(`use ${c.exploit.metasploit}`); setCopiedCmd(c.exploit.metasploit); setTimeout(() => setCopiedCmd(null), 2000); }} className="text-[8px] font-mono text-gray-500 hover:text-white px-1.5 py-0.5 border border-space-500/30 rounded hover:border-amber-500/50 transition-colors shrink-0">
                                              {copiedCmd === c.exploit.metasploit ? '✓' : 'COPY'}
                                            </button>
                                          </div>
                                        )}
                                        {c.exploit.manual && (
                                          <div className="flex items-center gap-2">
                                            <span className="text-[9px] font-tactical text-gray-500 shrink-0 w-14">CMD:</span>
                                            <code className="text-[10px] font-mono text-amber-300 bg-space-900 px-1.5 py-0.5 rounded border border-space-500/20 flex-1 truncate">{c.exploit.manual.replace('TARGET', selectedHost?.ip || 'TARGET')}</code>
                                            <button onClick={() => { const cmd = c.exploit.manual.replace('TARGET', selectedHost?.ip || 'TARGET'); navigator.clipboard.writeText(cmd); setCopiedCmd(c.exploit.manual); setTimeout(() => setCopiedCmd(null), 2000); }} className="text-[8px] font-mono text-gray-500 hover:text-white px-1.5 py-0.5 border border-space-500/30 rounded hover:border-amber-500/50 transition-colors shrink-0">
                                              {copiedCmd === c.exploit.manual ? '✓' : 'COPY'}
                                            </button>
                                          </div>
                                        )}
                                        <div className="text-[9px] font-mono text-gray-500">
                                          <span className="text-gray-600">Risk:</span> <span className="text-amber-400/80">{c.exploit.risk}</span>
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <div className="mt-2 text-[10px] font-mono text-gray-600">No known critical vulnerabilities mapped to this port signature.</div>
                            )}

                            {(p.service_name || p.server_header || p.banner) && (
                              <div className="mt-2 pt-2 border-t border-space-500/10">
                                {p.service_name && <div className="text-[10px] text-gray-400 font-mono">Service: <span className="text-gray-200">{p.service_name} {p.service_version || ''}</span></div>}
                                {p.server_header && <div className="text-[10px] text-gray-400 font-mono mt-1">Header: <span className="text-gray-200">{p.server_header}</span></div>}
                                {p.banner && !p.server_header && !p.service_name && <div className="text-[10px] text-gray-500 font-mono mt-1 truncate">{p.banner}</div>}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="p-4 rounded-lg border border-space-500/20 bg-space-950/30 text-center">
                      <span className="text-sm font-mono text-gray-500">No open ports detected. Node appears secure.</span>
                    </div>
                  )}
                </div>

                {/* Traceroute Results */}
                {tracerouteState !== 'IDLE' && ownsResult('traceroute', selectedHost.ip) && (
                  <div className="bg-space-950/30 rounded-lg border border-space-500/20 p-4">
                    <h3 className="text-[10px] font-mono text-gray-500 mb-3 uppercase tracking-wider flex items-center justify-between">
                      <span className="flex items-center gap-2">
                        <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3 text-neon-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                        ROUTE TRACE
                      </span>
                      {tracerouteState === 'TRACING' && <span className="text-neon-400 text-[9px] animate-pulse">TRACING...</span>}
                      {tracerouteState === 'DONE' && <span className="text-gray-600 text-[9px]">{tracerouteHops.length} HOPS</span>}
                    </h3>

                    {/* Hop List */}
                    <div className="space-y-1">
                      {tracerouteHops.map((hop: any, idx: number) => (
                        <div key={idx} className="flex items-center gap-2 group">
                          <span className="text-[10px] font-mono text-gray-600 w-5 text-right shrink-0">{hop.hop}</span>
                          <div className={`flex-1 flex items-center gap-2 px-2 py-1 rounded border transition-colors ${
                            hop.timeout ? 'border-space-500/10 bg-space-900/30' :
                            hop.is_target ? 'border-neon-500/30 bg-neon-500/5' :
                            'border-space-500/15 bg-space-950/40 hover:border-space-500/30'
                          }`}>
                            {hop.ip ? (
                              <>
                                <span className={`text-[10px] font-mono ${hop.is_target ? 'text-neon-400 font-bold' : 'text-gray-300'}`}>{hop.ip}</span>
                                {hop.hostname && <span className="text-[9px] text-gray-500 truncate">({hop.hostname})</span>}
                              </>
                            ) : (
                              <span className="text-[10px] font-mono text-gray-600">* * *</span>
                            )}
                            {hop.avg_rtt != null ? (
                              <span className={`text-[9px] font-mono ml-auto shrink-0 ${
                                hop.avg_rtt > 100 ? 'text-risk-critical' :
                                hop.avg_rtt > 50 ? 'text-amber-400' :
                                'text-gray-500'
                              }`}>{hop.avg_rtt}ms</span>
                            ) : hop.rtt_below_1ms ? (
                              /* The tool gave an upper bound, not a figure. Shown as the
                                 bound it is — this used to read "0.5ms", a number nothing
                                 measured. */
                              <span className="text-[9px] font-mono ml-auto shrink-0 text-gray-500">&lt;1ms</span>
                            ) : null}
                          </div>
                          {/* Connector line */}
                          {idx < tracerouteHops.length - 1 && (
                            <div className="absolute left-[22px] mt-5 w-[1px] h-1 bg-space-500/20" />
                          )}
                        </div>
                      ))}
                    </div>

                    {/* Analysis findings */}
                    {tracerouteAnalysis.length > 0 && (
                      <div className="mt-3 pt-3 border-t border-space-500/10 space-y-1.5">
                        {tracerouteAnalysis.map((finding: any, idx: number) => (
                          <div key={idx} className={`text-[10px] font-mono flex items-start gap-1.5 ${
                            finding.type === 'firewall' ? 'text-risk-critical' :
                            finding.type === 'nat' ? 'text-amber-400' :
                            finding.type === 'latency' ? 'text-amber-500' :
                            finding.type === 'warning' ? 'text-risk-high' :
                            'text-gray-400'
                          }`}>
                            <span className="shrink-0 mt-0.5">
                              {finding.type === 'firewall' ? '🛡️' :
                               finding.type === 'nat' ? '🔀' :
                               finding.type === 'latency' ? '⚡' :
                               finding.type === 'warning' ? '⚠️' : 'ℹ️'}
                            </span>
                            {finding.message}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Advanced Intel Blocks */}
                {(selectedHost.default_creds || selectedHost.ssl_cert || selectedHost.snmp_communities) && (
                  <div className="space-y-4">
                    {selectedHost.default_creds && (
                      <div className="bg-risk-critical/10 border border-risk-critical/30 rounded-lg p-4">
                        <h4 className="text-[10px] font-tactical text-risk-critical tracking-wider mb-2 flex items-center gap-2">
                          <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path></svg>
                          DEFAULT CREDENTIALS FOUND
                        </h4>
                        <div className="text-sm font-mono text-white">
                          {selectedHost.default_creds.username}:{selectedHost.default_creds.password || '(empty)'}
                        </div>
                      </div>
                    )}

                    {selectedHost.ssl_cert && <TlsCertificatePanel cert={selectedHost.ssl_cert} />}

                    {selectedHost.snmp_communities && (
                      <div className="bg-space-950/30 border border-space-500/20 rounded-lg p-4">
                        <h4 className="text-[10px] font-tactical text-gray-400 tracking-wider mb-2">SNMP COMMUNITIES</h4>
                        <div className="space-y-2">
                          {selectedHost.snmp_communities.map((c: any, idx: number) => (
                            <div key={idx} className="text-xs font-mono">
                              <span className="text-amber-400">{c.community}</span>
                              <div className="text-[10px] text-gray-500 mt-0.5 truncate" title={c.sys_descr}>{c.sys_descr}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Vuln Scan Results */}
                {vulnScanState === 'SUCCESS' && ownsResult('vuln', selectedHost.ip) && vulnScanFindings.length > 0 && (
                  <div className="space-y-4 mt-4">
                    <h4 className="text-[10px] font-tactical text-gray-500 tracking-wider flex items-center justify-between">
                      <span>VULNERABILITY SCAN FINDINGS</span>
                      <span className="text-gray-600 border border-gray-600/30 px-1.5 py-0.5 rounded text-[8px]">{vulnScanFindings.length} FOUND</span>
                    </h4>
                    {vulnScanFindings.map((f, i) => (
                      <div key={i} className={`bg-space-950/30 border rounded-lg p-4 ${severityClasses(f.severity).border} ${severityClasses(f.severity).text}`}>
                        <div className="flex items-start justify-between gap-2">
                          <h4 className="text-[10px] font-tactical tracking-wider mb-2">{f.vuln}</h4>
                          <span className={`text-[9px] font-tactical px-1.5 py-0.5 rounded border shrink-0 ${
                            severityClasses(f.severity).border + ' ' + severityClasses(f.severity).bg
                          }`}>{f.severity}</span>
                        </div>
                        <div className="text-xs font-mono text-gray-300">{f.description}</div>
                        <div className="text-[10px] font-mono text-gray-500 mt-2">PORT: {f.port} {f.cve !== 'N/A' && `| ${f.cve}`}</div>
                      </div>
                    ))}
                  </div>
                )}
                {vulnScanState === 'SUCCESS' && ownsResult('vuln', selectedHost.ip) && vulnScanFindings.length === 0 && (() => {
                  /*
                    This used to be a green tick reading "NO VULNERABILITIES
                    DETECTED — All active checks passed. No exposed secrets, weak
                    services, or misconfigurations found on this target."
                    `vuln_engine.py` sends the opposite alongside those findings:
                    only a listed set of ports has a check behind it, a check
                    that could not reach its service is indistinguishable from
                    one that found nothing, and "an empty result is not a clean
                    bill of health". All of it was discarded at this boundary.
                  */
                  const scan = selectedHost ? vulnScanByTarget[selectedHost.ip] : undefined;
                  const examined = scan?.ports_examined ?? [];
                  const unchecked = scan?.ports_without_a_check ?? [];
                  return (
                    <div className="mt-4 p-4 rounded-lg border border-amber-400/30 bg-amber-400/5">
                      <div className="flex items-start gap-3">
                        <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5 text-amber-300 shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                        <div className="min-w-0">
                          <div className="text-xs font-tactical text-amber-300 tracking-wider">NO FINDING FROM THE CHECKS THAT RAN</div>
                          <div className="text-[10px] font-mono text-gray-400 mt-1 leading-relaxed">
                            {examined.length > 0
                              ? <>Checked port{examined.length === 1 ? '' : 's'} <span className="text-gray-200">{examined.join(', ')}</span>. </>
                              : <>No port on this host has a check behind it. </>}
                            {unchecked.length > 0 && (
                              <>Port{unchecked.length === 1 ? '' : 's'} <span className="text-amber-200">{unchecked.join(', ')}</span> {unchecked.length === 1 ? 'was' : 'were'} open but not examined. </>
                            )}
                            {scan?.caveat ?? 'A check that could not reach its service looks the same here as one that found nothing. This is not a clean bill of health.'}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })()}

              </div>

              <div className="border-t border-space-500/20 bg-space-950/80">
                <button
                  onClick={() => setShowActionPanel(!showActionPanel)}
                  className="w-full p-4 flex items-center justify-between text-xs font-tactical tracking-wider text-gray-400 hover:text-white hover:bg-space-800/30 transition-colors focus:outline-none"
                >
                  <span className="flex items-center gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-neon-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>
                    OFFENSIVE MODULES & ACTIONS
                  </span>
                  <svg xmlns="http://www.w3.org/2000/svg" className={`w-4 h-4 transition-transform duration-300 ${showActionPanel ? 'rotate-180 text-neon-400' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
                </button>
                <AnimatePresence initial={false}>
                  {showActionPanel && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.3, ease: 'easeInOut' }}
                      className="overflow-hidden"
                    >
                      <div className="p-4 pt-0 space-y-2">
                        {/* STRIKE: DISCONNECT button */}
                {selectedHost.mac && (() => {
                  const strike = selectedHost.mac ? activeStrikes[selectedHost.mac.toLowerCase()] : null;
                  const isStriking = strike?.status === 'ACTIVE';
                  return (
                    <button
                      onClick={() => {
                        if (isStriking) {
                          engineIPC.send('stop_strike', { target_mac: selectedHost.mac?.toLowerCase() }).catch(console.error);
                        } else {
                          setStrikeTarget(selectedHost);
                          setShowStrikeConfirm(true);
                        }
                      }}
                      className={`w-full py-3 text-xs font-tactical tracking-widest rounded transition-all border flex items-center justify-center gap-2 ${isStriking
                        ? 'bg-risk-critical/20 hover:bg-risk-critical/30 text-risk-critical border-risk-critical/50 animate-pulse'
                        : 'bg-red-900/20 hover:bg-red-900/40 text-red-400 border-red-500/30 hover:border-red-500/60'
                        }`}
                    >
                      {isStriking ? (
                        <>
                          <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="6" y="4" width="4" height="16"></rect><rect x="14" y="4" width="4" height="16"></rect></svg>
                          CEASE FIRE — {strike?.packetsSent || 0} PACKETS SENT
                        </>
                      ) : (
                        <>
                          <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"></path><line x1="12" y1="2" x2="12" y2="12"></line></svg>
                          DISCONNECT TARGET
                        </>
                      )}
                    </button>
                  );
                })()}

                {/* MITM Button */}
                <button
                  onClick={() => {
                    if (mitmState === 'SPOOFING') {
                      // The host the spoof was started against, never the one
                      // currently selected. See `mitmTarget`.
                      engineIPC.send('stop_mitm', {
                        target_ip: mitmTarget ?? selectedHost.ip,
                      }).catch(console.error);
                    } else {
                      setMitmPackets([]);
                      setShowMitmDrawer(true);
                    }
                  }}
                  className={`w-full py-3 text-xs font-tactical tracking-widest rounded transition-all border flex items-center justify-center gap-2 ${mitmState === 'SPOOFING'
                    ? 'bg-amber-500/20 hover:bg-amber-500/30 text-amber-400 border-amber-500/50 animate-pulse'
                    : 'bg-space-800 hover:bg-space-700 text-gray-300 border-space-500/30'
                    }`}
                >
                  {mitmState === 'SPOOFING' ? (
                    <>
                      <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="6" y="4" width="4" height="16"></rect><rect x="14" y="4" width="4" height="16"></rect></svg>
                      {/*
                        Named when it is not the host on screen. The button is
                        global, so without this the operator reads "STOP
                        INTERCEPT" under B's header and has no way to tell that
                        the machine being spoofed is A.
                      */}
                      {mitmTarget && mitmTarget !== selectedHost.ip
                        ? `STOP INTERCEPT ON ${mitmTarget}`
                        : 'STOP INTERCEPT'}
                    </>
                  ) : (
                    <>
                      <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M2 12h10M12 2v20M22 12h-10" /></svg>
                      INTERCEPT TRAFFIC (MITM)
                    </>
                  )}
                </button>

                {/* VULN SCAN BUTTON */}
                <button
                  onClick={() => {
                    if (vulnScanState !== 'SCANNING') {
                      // Claimed at the start, like the trace: the gate must not hide a
                      // scan that is running on the host being shown.
                      setResultOwner(prev => ({ ...prev, vuln: selectedHost.ip }));
                      engineIPC.send('start_vuln_scan', { target_ip: selectedHost.ip, open_ports: selectedHost.open_ports.map(p => p.port) }).catch(console.error);
                    }
                  }}
                  disabled={vulnScanState === 'SCANNING'}
                  className={`w-full py-3 text-xs font-tactical tracking-widest rounded transition-all border flex items-center justify-center gap-2 ${vulnScanState === 'SCANNING'
                    ? 'bg-neon-500/20 text-neon-400 border-neon-500/50 animate-pulse'
                    : vulnScanState === 'SUCCESS' ? 'bg-risk-info/20 text-risk-info border-risk-info/50' : 'bg-space-800 hover:bg-space-700 text-gray-300 border-space-500/30'
                    }`}
                >
                  {vulnScanState === 'SCANNING' ? (
                    <>
                      <svg className="w-4 h-4 animate-spin" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                      SCANNING VULNERABILITIES...
                    </>
                  ) : vulnScanState === 'SUCCESS' ? (
                    <>
                      <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                      SCAN COMPLETED
                    </>
                  ) : (
                    <>
                      <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                      ANALYZE VULNERABILITIES
                    </>
                  )}
                </button>

                {/* TRACEROUTE BUTTON — doubles as STOP while a trace is running.
                    A trace is one blocking subprocess whose timeout is derived
                    from its own parameters, so without this the only way out
                    was to wait it out. */}
                <button
                  onClick={() => {
                    if (tracerouteState === 'TRACING') {
                      engineIPC.send('stop_traceroute').catch(console.error);
                      // The engine's terminal event clears the state; this is
                      // only so the button stops inviting another click.
                      setTracerouteState('IDLE');
                      return;
                    }
                    setTracerouteHops([]);
                    setTracerouteAnalysis([]);
                    setTracerouteTarget(null);
                    setTracerouteState('TRACING');
                    /*
                      The owner is claimed at the start, not at completion.

                      `resultOwner.traceroute` was written only by
                      `traceroute_completed`, and the panel is gated on it — so tracing
                      A, then selecting B and tracing it, hid the whole ROUTE TRACE
                      panel for the entire run: the spinner, the streaming hops, all of
                      it, because the owner was still A. The gate is meant to stop a
                      result being shown under the wrong host, not to hide a live one.
                    */
                    setResultOwner(prev => ({ ...prev, traceroute: selectedHost.ip }));
                    engineIPC.send('start_traceroute', { target_ip: selectedHost.ip }).catch(console.error);
                  }}
                  className={`w-full py-3 text-xs font-tactical tracking-widest rounded transition-all border flex items-center justify-center gap-2 ${
                    tracerouteState === 'TRACING'
                      ? 'bg-neon-500/20 text-neon-400 border-neon-500/50 animate-pulse'
                      : tracerouteState === 'DONE' ? 'bg-risk-info/20 text-risk-info border-risk-info/50' : 'bg-space-800 hover:bg-space-700 text-gray-300 border-space-500/30'
                  }`}
                >
                  {tracerouteState === 'TRACING' ? (
                    <>
                      <svg className="w-4 h-4 animate-spin" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                      TRACING ROUTE... (CLICK TO STOP)
                    </>
                  ) : tracerouteState === 'DONE' ? (
                    <>
                      <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                      TRACE AGAIN ({tracerouteHops.length} HOPS)
                    </>
                  ) : (
                    <>
                      <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                      TRACE ROUTE
                    </>
                  )}
                </button>

                {/* BRUTE-FORCE BUTTON */}
                {selectedHost.open_ports.some(p => [21, 22, 80, 443].includes(p.port)) && (
                  <>
                    {bruteForceState === 'IDLE' && (
                      <div className="space-y-3">
                        {!showBfConfig ? (
                          <button
                            onClick={() => setShowBfConfig(true)}
                            className="w-full py-3 bg-risk-critical/10 hover:bg-risk-critical text-risk-critical hover:text-white text-xs font-tactical tracking-widest rounded transition-all border border-risk-critical/50 flex items-center justify-center gap-2"
                          >
                            <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" /></svg>
                            CONFIGURE BRUTE-FORCE
                          </button>
                        ) : (
                          <div className="bg-space-950 border border-risk-critical/30 rounded-lg p-3 space-y-3">
                            <div className="flex justify-between items-center mb-1">
                              <span className="text-[10px] font-tactical text-risk-critical tracking-wider">ATTACK VECTOR</span>
                              <button onClick={() => setShowBfConfig(false)} className="text-gray-500 hover:text-white">
                                <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                              </button>
                            </div>

                            <div className="flex bg-space-900 rounded p-1">
                              <button
                                onClick={() => setBfMode('DICTIONARY')}
                                className={`flex-1 py-1.5 text-[10px] font-mono rounded ${bfMode === 'DICTIONARY' ? 'bg-risk-critical text-white' : 'text-gray-500 hover:text-gray-300'}`}
                              >
                                DICTIONARY (USER:PASS)
                              </button>
                              <button
                                onClick={() => setBfMode('SPRAY')}
                                className={`flex-1 py-1.5 text-[10px] font-mono rounded ${bfMode === 'SPRAY' ? 'bg-risk-critical text-white' : 'text-gray-500 hover:text-gray-300'}`}
                              >
                                PASSWORD SPRAY
                              </button>
                            </div>

                            {bfMode === 'SPRAY' && (
                              <div>
                                <label className="block text-[10px] font-mono text-gray-500 mb-1">TARGET USERNAME</label>
                                <input
                                  type="text"
                                  value={bfTargetUser}
                                  onChange={e => setBfTargetUser(e.target.value)}
                                  className="w-full bg-space-900 border border-space-500/30 text-white text-xs font-mono p-2 rounded focus:outline-none focus:border-risk-critical/50"
                                  placeholder="admin, root, user..."
                                />
                              </div>
                            )}

                            <div>
                              <label className="block text-[10px] font-mono text-gray-500 mb-1">SELECT WORDLIST</label>
                              <select
                                value={selectedWordlist}
                                onChange={(e) => setSelectedWordlist(e.target.value)}
                                className="w-full bg-space-900 border border-space-500/30 text-gray-300 text-xs font-mono p-2 rounded focus:outline-none focus:border-risk-critical/50 cursor-pointer"
                              >
                                {wordlists.length === 0 && <option value="" disabled>No wordlists available</option>}
                                {bfMode === 'DICTIONARY' ? (
                                  <>
                                    {wordlists.filter(w => w.name.includes('credential') || w.name.includes('botnet') || w.name.includes('cirt-default-passwords')).map(w => (
                                      <option key={w.name} value={w.name}>{w.name.replace('.txt', '')}</option>
                                    ))}
                                    {/* Fallback if list empty after filter */}
                                    {wordlists.filter(w => w.name.includes('credential') || w.name.includes('botnet')).length === 0 && wordlists.map(w => (
                                      <option key={w.name} value={w.name}>{w.name.replace('.txt', '')}</option>
                                    ))}
                                  </>
                                ) : (
                                  <>
                                    {wordlists.map(w => (
                                      <option key={w.name} value={w.name}>{w.name.replace('.txt', '')} ({(w.size / 1024).toFixed(0)}KB)</option>
                                    ))}
                                  </>
                                )}
                              </select>
                            </div>

                            <button
                              onClick={() => {
                                setBruteForceState('CRACKING');
                                setShowBfConfig(false);
                                const bfPort = selectedHost.open_ports.find(p => [21, 22, 80, 443].includes(p.port));
                                if (bfPort) {
                                  let svc = 'http';
                                  if (bfPort.port === 22) svc = 'ssh';
                                  if (bfPort.port === 21) svc = 'ftp';

                                  engineIPC.send('start_bruteforce', {
                                    target_ip: selectedHost.ip,
                                    port: bfPort.port,
                                    service_type: svc,
                                    wordlist_name: selectedWordlist,
                                    target_user: bfMode === 'SPRAY' ? bfTargetUser : undefined
                                  }).catch(console.error);
                                }
                              }}
                              className="w-full mt-2 py-2.5 bg-risk-critical hover:bg-red-500 text-white text-xs font-tactical tracking-widest rounded transition-all"
                            >
                              FIRE PAYLOAD
                            </button>
                          </div>
                        )}
                      </div>
                    )}

                    {bruteForceState === 'CRACKING' && (
                      <div className="w-full flex flex-col items-center justify-center gap-2 bg-space-900 border border-risk-critical/50 py-3 rounded text-sm overflow-hidden relative">
                        <button
                          onClick={() => {
                            const bfPort = selectedHost.open_ports.find(p => [21, 22, 80, 443].includes(p.port));
                            if (bfPort) {
                              engineIPC.send('stop_bruteforce', { target_ip: selectedHost.ip, port: bfPort.port }).catch(console.error);
                              setBruteForceState('IDLE');
                            }
                          }}
                          className="absolute top-2 right-2 p-1 text-gray-500 hover:text-white transition-colors rounded hover:bg-space-800"
                          title="Abort Attack"
                        >
                          <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                        </button>
                        <svg className="w-6 h-6 text-risk-critical animate-spin shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
                        </svg>
                        <div className="flex flex-col items-center max-w-full px-2">
                          <span className="text-risk-critical font-mono text-xs animate-pulse">BRUTE-FORCING CREDENTIALS...</span>
                          <span className="text-gray-500 font-mono text-[10px] truncate max-w-full opacity-80 mt-1">TRYING: {bruteForceWord}</span>
                        </div>
                      </div>
                    )}

                    {bruteForceState === 'SUCCESS' && (
                      <div className="w-full flex flex-col items-center justify-center gap-2 bg-signal-strong/20 border border-signal-strong/50 py-2 rounded text-sm">
                        <span className="text-signal-strong font-tactical tracking-widest text-[10px]">COMPROMISED (SECLISTS)</span>
                        <span className="text-white font-mono text-lg">{crackedCreds}</span>
                      </div>
                    )}

                    {/*
                      A credential that worked but was not recorded is a finding
                      on its way to being lost, so say it here rather than only
                      in the console.
                    */}
                    {bruteforceVaultWarning && (
                      <div className="w-full mt-2 p-2 rounded border border-amber-500/50 bg-amber-500/10">
                        <div className="text-[9px] font-tactical tracking-widest text-amber-400 mb-0.5">NOT STORED</div>
                        <div className="text-[10px] font-mono text-amber-200 leading-relaxed">{bruteforceVaultWarning}</div>
                      </div>
                    )}
                  </>
                )}

                {/* WEB DIRBUSTER BUTTON */}
                {selectedHost.open_ports.some(p => [80, 443, 8080, 8443].includes(p.port)) && (
                  <>
                    {dirbusterState === 'IDLE' && (
                      <div className="space-y-3">
                        {!showDirbusterConfig ? (
                          <button
                            onClick={() => setShowDirbusterConfig(true)}
                            className="w-full py-3 bg-neon-500/10 hover:bg-neon-500 text-neon-400 hover:text-space-950 text-xs font-tactical tracking-widest rounded transition-all border border-neon-500/50 flex items-center justify-center gap-2"
                          >
                            <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" /></svg>
                            WEB DIRECTORY ENUMERATION
                          </button>
                        ) : (
                          <div className="bg-space-950 border border-neon-500/30 rounded-lg p-3 space-y-3">
                            <div className="flex justify-between items-center mb-1">
                              <span className="text-[10px] font-tactical text-neon-400 tracking-wider">DIRBUSTER TARGET</span>
                              <button onClick={() => setShowDirbusterConfig(false)} className="text-gray-500 hover:text-white">
                                <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                              </button>
                            </div>

                            <div>
                              <label className="block text-[10px] font-mono text-gray-500 mb-1">SELECT WORDLIST</label>
                              <select
                                value={selectedWordlist}
                                onChange={(e) => setSelectedWordlist(e.target.value)}
                                className="w-full bg-space-900 border border-space-500/30 text-gray-300 text-xs font-mono p-2 rounded focus:outline-none focus:border-neon-500/50 cursor-pointer"
                              >
                                {wordlists.map(w => (
                                  <option key={w.name} value={w.name}>{w.name.replace('.txt', '')} ({(w.size / 1024).toFixed(0)}KB)</option>
                                ))}
                              </select>
                            </div>

                            <button
                              onClick={() => {
                                setDirbusterState('SCANNING');
                                setDirbusterFindings([]);
                                setDirbusterComplete(null);
                                setShowDirbusterConfig(false);
                                const dbPort = selectedHost.open_ports.find(p => [80, 443, 8080, 8443].includes(p.port));
                                if (dbPort) {
                                  setResultOwner(prev => ({ ...prev, dirbuster: selectedHost.ip }));
                                  engineIPC.send('start_dirbuster', {
                                    target_ip: selectedHost.ip,
                                    port: dbPort.port,
                                    is_https: [443, 8443].includes(dbPort.port),
                                    wordlist_name: selectedWordlist,
                                    threads: 10
                                  }).catch(console.error);
                                }
                              }}
                              className="w-full mt-2 py-2.5 bg-neon-600 hover:bg-neon-500 text-white text-xs font-tactical tracking-widest rounded transition-all"
                            >
                              START ENUMERATION
                            </button>
                          </div>
                        )}
                      </div>
                    )}

                    {dirbusterState === 'SCANNING' && (
                      <div className="w-full flex flex-col gap-2 bg-space-900 border border-neon-500/50 p-3 rounded text-sm relative">
                        <button
                          onClick={() => {
                            engineIPC.send('stop_dirbuster').catch(console.error);
                            setDirbusterState('IDLE');
                          }}
                          className="absolute top-2 right-2 p-1 text-gray-500 hover:text-white transition-colors rounded hover:bg-space-800"
                        >
                          <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                        </button>
                        <div className="flex items-center gap-2">
                          <svg className="w-4 h-4 text-neon-500 animate-spin shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" /></svg>
                          <span className="text-neon-400 font-mono text-xs">CRAWLING... {dirbusterPath}</span>
                        </div>
                        {dirbusterFindings.length > 0 && (
                          <div className="mt-2 space-y-1 max-h-32 overflow-y-auto no-scrollbar border-t border-space-500/20 pt-2">
                            {dirbusterFindings.map((f, i) => (
                              <div key={i} className="flex justify-between items-center text-[10px] font-mono">
                                <span className={f.status === 200 ? 'text-signal-strong' : f.status === 403 ? 'text-risk-high' : 'text-amber-400'}>
                                  [{f.status}] /{f.path}
                                </span>
                                <span className="text-gray-500">{(f.size / 1024).toFixed(1)} KB</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    {dirbusterState === 'SUCCESS' && ownsResult('dirbuster', selectedHost.ip) && (
                      <div className="w-full flex flex-col gap-2 bg-space-950 border border-neon-500/30 p-3 rounded text-sm">
                        <div className="flex justify-between items-center border-b border-space-500/20 pb-2">
                          <span className="text-neon-400 font-tactical tracking-widest text-[10px]">ENUMERATION COMPLETE</span>
                          <span className="text-gray-400 font-mono text-[10px]">{dirbusterFindings.length} FOUND</span>
                        </div>
                        <div className="space-y-1 max-h-40 overflow-y-auto no-scrollbar pt-2">
                          {dirbusterFindings.map((f, i) => (
                            <div key={i} className="flex justify-between items-center text-[10px] font-mono">
                              <span className={f.status === 200 ? 'text-signal-strong' : f.status === 403 ? 'text-risk-high' : 'text-amber-400'}>
                                [{f.status}] /{f.path}
                              </span>
                              <a href={f.url} target="_blank" rel="noreferrer" className="text-neon-500 hover:text-white flex items-center gap-1">
                                OPEN <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" /><polyline points="15 3 21 3 21 9" /><line x1="10" y1="14" x2="21" y2="3" /></svg>
                              </a>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </>
                )}

                {/* ───────────────────────── TLS INSPECTION ─────────────────────────
                    `start_deep_ssl_scan` reached nothing before this. The engine
                    handler, the policy gate and `deep_ssl_scan` were all written
                    and tested; no code path sent the command, and no listener read
                    either of the two events it answers with.

                    The port list is the common implicit-TLS set rather than 443
                    alone, because a mail or LDAP service with an expired
                    certificate is the same finding and the port scan already
                    reports those. 80 is deliberately absent: STARTTLS is a
                    different negotiation and this scanner does not speak it, so
                    offering the button there would produce a failure that reads
                    like a result. */}
                {selectedHost.open_ports.some(p => [443, 465, 636, 993, 995, 8443].includes(p.port)) && (
                  <>
                    {sslScanState === 'IDLE' && (
                      <button
                        onClick={async () => {
                          // The port actually seen open decides what is scanned.
                          // Defaulting to 443 would scan a closed port on a host
                          // whose TLS service is on 8443, and then report that
                          // failure as the host's posture.
                          const tlsPort = selectedHost.open_ports
                            .map(p => p.port)
                            .filter(n => [443, 8443, 465, 636, 993, 995].includes(n))
                            .sort((a, b) => a - b)[0] ?? 443;
                          setSslScanReport(null);
                          setSslScanError(null);
                          setResultOwner(prev => ({ ...prev, ssl: selectedHost.ip }));
                          try {
                            await engineIPC.send('start_deep_ssl_scan', { target_ip: selectedHost.ip, port: tlsPort });
                            // Only after the engine took it. The passive-SIGINT
                            // panel shipped the other way round and showed a
                            // capture running against a sidecar that was not
                            // attached.
                            setSslScanState('SCANNING');
                          } catch (e) {
                            setSslScanError(`The scan could not be started — ${e instanceof Error ? e.message : String(e)}. Nothing was inspected.`);
                            setSslScanState('SUCCESS');
                          }
                        }}
                        className="w-full py-3 bg-emerald-500/10 hover:bg-emerald-600 text-emerald-400 hover:text-white text-xs font-tactical tracking-widest rounded transition-all border border-emerald-500/50 flex items-center justify-center gap-2"
                      >
                        <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
                        TLS / CERTIFICATE INSPECTION
                      </button>
                    )}

                    {sslScanState === 'SCANNING' && (
                      <div className="w-full flex items-center justify-center gap-2 bg-space-900 border border-emerald-500/50 p-3 rounded text-sm relative">
                        <svg className="w-4 h-4 text-emerald-500 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" /></svg>
                        <span className="text-emerald-400 font-mono text-xs">NEGOTIATING TLS, READING CERTIFICATE…</span>
                      </div>
                    )}

                    {sslScanState === 'SUCCESS' && ownsResult('ssl', selectedHost.ip) && (
                      <div className="w-full flex flex-col gap-2 bg-space-950 border border-emerald-500/30 p-3 rounded text-sm relative">
                        <button onClick={() => setSslScanState('IDLE')} className="absolute top-2 right-2 p-1 text-gray-500 hover:text-white transition-colors rounded hover:bg-space-800">
                          <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                        </button>
                        <span className="text-emerald-400 font-tactical tracking-widest text-[10px] border-b border-space-500/20 pb-2">
                          TLS INSPECTION{sslScanReport?.port ? ` — PORT ${sslScanReport.port}` : ''}
                        </span>

                        {sslScanError ? (
                          <div className="text-[10px] font-mono text-risk-high bg-risk-high/10 border border-risk-high/30 rounded px-3 py-2 leading-relaxed">
                            {sslScanError}
                            <div className="text-gray-400 mt-1">
                              Nothing here says this host's TLS is sound — only that it could not be examined.
                            </div>
                          </div>
                        ) : (
                          <div className="space-y-2 mt-1 text-[10px] font-mono">
                            {/* Certificate identity first: it is what an operator
                                writes down, and it is also how they tell whether
                                they scanned what they meant to. */}
                            <div className="grid grid-cols-2 gap-2">
                              <div><span className="text-gray-600">SUBJECT</span><div className="text-gray-300 break-all">{sslScanReport?.cn || 'not reported'}</div></div>
                              <div><span className="text-gray-600">ISSUER</span><div className="text-gray-300 break-all">{sslScanReport?.issuer || 'not reported'}</div></div>
                              <div><span className="text-gray-600">EXPIRES</span><div className={sslScanReport?.expired ? 'text-risk-critical font-bold' : 'text-gray-300'}>{sslScanReport?.expires || 'not reported'}{sslScanReport?.expired ? ' (EXPIRED)' : ''}</div></div>
                              <div><span className="text-gray-600">PROTOCOL</span><div className="text-gray-300">{sslScanReport?.protocol || 'not reported'}{sslScanReport?.cipher_name ? ` · ${sslScanReport.cipher_name}` : ''}</div></div>
                            </div>

                            {Array.isArray(sslScanReport?.findings) && sslScanReport.findings.length > 0 && (
                              <div className="space-y-1 pt-1">
                                {sslScanReport.findings.map((f: any, i: number) => (
                                  <div key={i} className={`rounded px-2 py-1.5 border leading-relaxed ${
                                    f.severity === 'HIGH' ? 'bg-risk-high/10 border-risk-high/40 text-risk-high'
                                      : f.severity === 'MEDIUM' ? 'bg-risk-medium/10 border-risk-medium/40 text-risk-medium'
                                      : 'bg-space-800 border-space-500/30 text-gray-300'
                                  }`}>
                                    <span className="font-bold">{f.severity}</span> — {f.finding}
                                    {f.detail && <div className="text-gray-400 mt-0.5">{f.detail}</div>}
                                  </div>
                                ))}
                              </div>
                            )}

                            {/*
                              The inconclusive list is rendered with the same
                              weight as the findings, which is the whole reason
                              `deep_ssl_scan` builds one: "a check that did not run
                              produces an entry in `inconclusive`, never a
                              finding". Hiding it here would undo that in the one
                              place the operator actually reads.
                            */}
                            {Array.isArray(sslScanReport?.inconclusive) && sslScanReport.inconclusive.length > 0 && (
                              <div className="pt-1">
                                <div className="text-gray-500 mb-1">NOT ESTABLISHED ({sslScanReport.inconclusive.length})</div>
                                <div className="space-y-1">
                                  {sslScanReport.inconclusive.map((c: any, i: number) => (
                                    <div key={i} className="bg-space-800 border border-space-500/30 rounded px-2 py-1 text-gray-400 leading-relaxed">
                                      <span className="text-gray-300">{c.check}</span> — {c.reason}
                                    </div>
                                  ))}
                                </div>
                                <div className="text-gray-600 mt-1 leading-relaxed">
                                  These checks did not run. Their absence from the findings above is not a pass.
                                </div>
                              </div>
                            )}

                            {(!sslScanReport?.findings || sslScanReport.findings.length === 0)
                              && (!sslScanReport?.inconclusive || sslScanReport.inconclusive.length === 0) && (
                              <div className="text-signal-strong bg-signal-strong/10 border border-signal-strong/30 rounded px-2 py-1.5 leading-relaxed">
                                Every check ran, and none of them raised anything on this port.
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </>
                )}

                {/* SMB / AD ENUM BUTTON */}
                {selectedHost.open_ports.some(p => [139, 445].includes(p.port)) && (
                  <>
                    {smbEnumState === 'IDLE' && (
                      <button
                        onClick={() => {
                          setSmbEnumState('SCANNING');
                          setSmbEnumFindings(null);
                          setResultOwner(prev => ({ ...prev, smb: selectedHost.ip }));
                          engineIPC.send('start_smb_enum', { target_ip: selectedHost.ip }).catch(console.error);
                        }}
                        className="w-full py-3 bg-blue-500/10 hover:bg-blue-600 text-blue-400 hover:text-white text-xs font-tactical tracking-widest rounded transition-all border border-blue-500/50 flex items-center justify-center gap-2"
                      >
                        <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 22h14a2 2 0 0 0 2-2V7.5L14.5 2H6a2 2 0 0 0-2 2v4" /><polyline points="14 2 14 8 20 8" /><path d="M2 15h10" /><path d="m9 18 3-3-3-3" /></svg>
                        SMB DEEP ENUMERATION
                      </button>
                    )}

                    {smbEnumState === 'SCANNING' && (
                      <div className="w-full flex items-center justify-center gap-2 bg-space-900 border border-blue-500/50 p-3 rounded text-sm relative">
                        <svg className="w-4 h-4 text-blue-500 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" /></svg>
                        <span className="text-blue-400 font-mono text-xs">PROBING NTLM CHALLENGE & SMBv1...</span>
                      </div>
                    )}

                    {smbEnumState === 'SUCCESS' && ownsResult('smb', selectedHost.ip) && smbEnumFindings && (
                      <div className="w-full flex flex-col gap-2 bg-space-950 border border-blue-500/30 p-3 rounded text-sm relative">
                        <button onClick={() => setSmbEnumState('IDLE')} className="absolute top-2 right-2 p-1 text-gray-500 hover:text-white transition-colors rounded hover:bg-space-800">
                          <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                        </button>
                        <span className="text-blue-400 font-tactical tracking-widest text-[10px] border-b border-space-500/20 pb-2">SMB ENUMERATION REPORT</span>

                        <div className="space-y-2 mt-1">
                          <div className="flex justify-between items-center text-[10px] font-mono">
                            <span className="text-gray-500">SMBv1 SUPPORT:</span>
                            {/*
                              Three states, not two. The check returns null when
                              it could not reach the host at all, and rendering
                              that as DISABLED reported a clean security posture
                              for a machine that was merely firewalled.
                            */}
                            <span className={
                              smbEnumFindings.smbv1_enabled === true ? 'text-risk-critical animate-pulse font-bold'
                              : smbEnumFindings.smbv1_enabled === false ? 'text-signal-strong'
                              : 'text-gray-500'
                            }>
                              {smbEnumFindings.smbv1_enabled === true ? 'ENABLED (VULNERABLE)'
                               : smbEnumFindings.smbv1_enabled === false ? 'DISABLED'
                               : 'COULD NOT DETERMINE'}
                            </span>
                          </div>
                          {/*
                            The evidence behind the verdict.

                            DISABLED and COULD NOT DETERMINE were the same value until
                            now — the probe was malformed, so every host got the second
                            one — and the two are opposite claims. A reset from a host
                            that answers SMB2 is a refusal; a reset from a host that
                            answers nothing is silence. The engine says which, and the
                            note also carries the limit of the inference, since a
                            middlebox can reset a connection too.
                          */}
                          {smbEnumFindings.smbv1_note && (
                            <div className="text-[9px] font-mono text-gray-500 leading-snug -mt-1 mb-1">
                              {String(smbEnumFindings.smbv1_note)}
                            </div>
                          )}

                          <div className="flex justify-between items-center text-[10px] font-mono">
                            <span className="text-gray-500">SMB SIGNING:</span>
                            <span className={
                              smbEnumFindings.signing_required === true ? 'text-signal-strong' :
                              smbEnumFindings.signing_required === false ? 'text-amber-400 font-bold' :
                              'text-gray-500'
                            }>
                              {smbEnumFindings.signing_required === true ? 'REQUIRED' :
                               smbEnumFindings.signing_required === false ? 'NOT REQUIRED (RELAY RISK)' :
                               'UNKNOWN'}
                            </span>
                          </div>

                          <div className="flex justify-between items-center text-[10px] font-mono">
                            <span className="text-gray-500">OS VERSION:</span>
                            <span className="text-gray-300">{smbEnumFindings.os_version || 'Unknown'}</span>
                          </div>

                          <div className="flex justify-between items-center text-[10px] font-mono">
                            <span className="text-gray-500">DOMAIN/WORKGROUP:</span>
                            <span className="text-white bg-space-800 px-1 rounded">{smbEnumFindings.domain_name || 'Unknown'}</span>
                          </div>

                          <div className="flex justify-between items-center text-[10px] font-mono">
                            <span className="text-gray-500">COMPUTER NAME:</span>
                            <span className="text-gray-300">{smbEnumFindings.computer_name || 'Unknown'}</span>
                          </div>

                          {(smbEnumFindings.dns_domain_name || smbEnumFindings.dns_computer_name) && (
                            <div className="pt-2 border-t border-space-500/10 mt-2">
                              {smbEnumFindings.dns_domain_name && (
                                <div className="flex justify-between items-center text-[9px] font-mono">
                                  <span className="text-gray-600">DNS DOMAIN:</span>
                                  <span className="text-gray-400">{smbEnumFindings.dns_domain_name}</span>
                                </div>
                              )}
                              {smbEnumFindings.dns_computer_name && (
                                <div className="flex justify-between items-center text-[9px] font-mono">
                                  <span className="text-gray-600">DNS HOST:</span>
                                  <span className="text-gray-400">{smbEnumFindings.dns_computer_name}</span>
                                </div>
                              )}
                            </div>
                          )}

                          {/* Share Enumeration Results */}
                          {smbEnumFindings.shares && smbEnumFindings.shares.length > 0 && (
                            <div className="pt-2 border-t border-space-500/10 mt-2">
                              <div className="text-[9px] font-mono text-gray-500 mb-1.5">ACCESSIBLE SHARES:</div>
                              <div className="space-y-1">
                                {smbEnumFindings.shares.map((share: any, i: number) => (
                                  <div key={i} className="flex items-center justify-between text-[10px] font-mono bg-space-900/50 px-2 py-1 rounded">
                                    <span className="text-gray-300 flex items-center gap-1.5">
                                      <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3 text-blue-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                                      \\{share.name}
                                    </span>
                                    <span className={share.access === 'FULL' ? 'text-risk-critical font-bold' : 'text-gray-500'}>
                                      {share.access === 'FULL' ? 'OPEN ACCESS' : 'ACCESS DENIED'}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                          {smbEnumFindings.shares && smbEnumFindings.shares.length === 0 && (
                            <div className="pt-2 border-t border-space-500/10 mt-2">
                              <div className="text-[9px] font-mono text-gray-600">NO SHARES ACCESSIBLE VIA NULL SESSION</div>
                              {/*
                                Why, in the engine's own words. An empty list has two
                                causes that read identically without it: a session was
                                established and nothing was reachable, or the server
                                refused the anonymous session outright. Both are
                                results; they are not the same result.
                              */}
                              {smbEnumFindings.shares_note && (
                                <div className="text-[9px] font-mono text-gray-500 mt-1 leading-snug">
                                  {String(smbEnumFindings.shares_note)}
                                </div>
                              )}
                            </div>
                          )}
                          {/*
                            `shares: null` means the enumeration never got an answer
                            it could read, which is not the same claim as "no shares
                            are accessible". The engine reports it in `inconclusive`;
                            this is the screen's half of saying so, because the
                            branch above renders a clean result and an operator
                            cannot tell the two apart from an absent section.
                          */}
                          {smbEnumFindings.shares === null && (
                            <div className="pt-2 border-t border-space-500/10 mt-2">
                              <div className="text-[9px] font-mono text-amber-400">
                                SHARE ENUMERATION INCONCLUSIVE — This is NOT evidence that no
                                shares are exposed.
                              </div>
                              {smbEnumFindings.shares_note && (
                                <div className="text-[9px] font-mono text-amber-400/70 mt-1 leading-snug">
                                  {String(smbEnumFindings.shares_note)}
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </>
                )}

                <button
                  onClick={async () => {
                    // Sealed, not decrypted — a node report is written into the
                    // same database as the vault, so embedding cleartext here
                    // would undo the encryption just as the full archive did.
                    let creds: any[] = [];
                    try {
                      const all = await getCredentialsForArchive(
                        useIntrusionStore.getState().currentSessionId,
                      );
                      creds = all.filter(c => c.target_ip === selectedHost.ip);
                    } catch (e) {
                      // Was `catch (e) { }`. A locked vault is the common case
                      // here and it was swallowed, so the node report shipped
                      // `credentials: []` -- indistinguishable from a host where
                      // nothing was recovered.
                      console.error('[Intrusion] credentials for node report:', e);
                      showToast(
                        'Node report written without credentials: the vault could not be read. ' +
                        'This is not the same as nothing having been recovered.',
                        'error',
                      );
                    }

                    const nodeReport = {
                      id: `NODE-${selectedHost.ip.replace(/\./g, '-')}-${Date.now()}`,
                      type: 'INTRUSION' as const,
                      targetName: `NODE: ${selectedHost.ip}`,
                      timestamp: Date.now(),
                      summary: {
                        totalNodes: 1,
                        /*
                          Asked of the rule set, not inferred from a port count.

                          This was `open_ports.length > 0 ? 1 : 0`, so a host whose
                          only open port is 22 was persisted to
                          `intel_reports.critical_nodes` as 1 CRITICAL while the
                          report's own findings table listed none — the drift the
                          comment on the full archive says was fixed there.
                        */
                        criticalNodes: (() => {
                          const findings = assessHost(
                            toHostInput(selectedHost, creds, false));
                          const worst = worstOf(findings);
                          return SEVERITY_ORDER[worst.severity] >= SEVERITY_ORDER.CRITICAL ? 1 : 0;
                        })()
                      },
                      rawData: {
                        subnet: targetSubnet,
                        hosts: [selectedHost],
                        credentials: creds
                      }
                    };
                    // Awaited, for the same reason as the full archive above: a
                    // success toast over a failed INSERT is the exact defect
                    // `addReport` was changed to reject for. `NODE-<ip>-<Date.now()>`
                    // also collides on a double-click, which is the easiest way to
                    // reach it.
                    try {
                      await addReport(nodeReport);
                    } catch (err) {
                      console.error('[Intrusion] node report failed:', err);
                      showToast(
                        `NODE REPORT NOT STORED (${err instanceof Error ? err.message : String(err)}).`,
                        'error',
                      );
                      return;
                    }
                    showToast("Node Report exported to Archives!", 'success');
                  }}
                  className="w-full py-3 bg-space-800 hover:bg-space-700 text-gray-300 text-xs font-tactical tracking-widest rounded transition-colors border border-space-500/30 flex items-center justify-center gap-2"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
                  EXPORT NODE REPORT
                </button>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>

      {/* STRIKE Confirmation Modal */}
      <AnimatePresence>
        {showStrikeConfirm && strikeTarget && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[200] bg-space-950/80 backdrop-blur-md flex items-center justify-center"
            onClick={() => setShowStrikeConfirm(false)}
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              onClick={e => e.stopPropagation()}
              className="bg-space-900 border border-red-500/40 rounded-xl p-6 max-w-sm w-full mx-4"
            >
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-red-900/30 rounded-lg">
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-6 h-6 text-red-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                </div>
                <h3 className="text-lg font-tactical text-white tracking-wider">AUTHORIZE STRIKE</h3>
              </div>

              <div className="bg-space-950/50 rounded-lg border border-space-500/20 p-3 mb-4 text-sm font-mono">
                <div className="text-gray-500 text-[10px] mb-1">TARGET</div>
                <div className="text-white">{strikeTarget.ip} — {strikeTarget.hostname}</div>
                <div className="text-gray-500 text-[10px] mt-2 mb-1">MAC ADDRESS</div>
                <div className="text-red-400">{strikeTarget.mac?.toUpperCase()}</div>
              </div>

              <p className="text-xs text-gray-400 mb-2 leading-relaxed">
                This will send IEEE 802.11 Deauthentication frames to force-disconnect this device from the network.
                Requires a Monitor Mode adapter and Npcap.
              </p>
              
              <div className="mb-4 p-2 bg-amber-500/10 border border-amber-500/30 rounded flex items-start gap-2 text-amber-400">
                <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                <span className="text-[10px] font-mono leading-relaxed">Note: Deauthentication is a wireless-only attack. If this target is connected via physical Ethernet, the strike will have no effect.</span>
              </div>

              <div className="flex gap-3">
                <button
                  onClick={() => setShowStrikeConfirm(false)}
                  className="flex-1 py-2.5 text-xs font-tactical text-gray-400 hover:text-white border border-space-500/30 hover:border-space-500/60 rounded transition-colors"
                >
                  ABORT
                </button>
                <button
                  onClick={() => {
                    engineIPC.send('start_strike', {
                      target_mac: strikeTarget.mac?.toLowerCase(),
                      gateway_bssid: gatewayMac.toLowerCase(),
                      interface: interfaceName,
                      count: 0
                    }).catch(console.error);
                    setShowStrikeConfirm(false);
                  }}
                  className="flex-1 py-2.5 text-xs font-tactical tracking-wider bg-red-600 hover:bg-red-500 text-white rounded transition-colors"
                >
                  FIRE
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* SCAN HISTORY Panel */}
      <AnimatePresence>
        {showHistory && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => { setShowHistory(false); setSelectedSession(null); }}
              className="fixed inset-0 z-[100] bg-space-950/60 backdrop-blur-sm"
            />
            <motion.div
              initial={{ x: '-100%' }}
              animate={{ x: 0 }}
              exit={{ x: '-100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="fixed top-0 left-0 bottom-0 w-full max-w-md bg-space-900 border-r border-space-500/30 z-[110] shadow-[20px_0_50px_rgba(0,0,0,0.5)] flex flex-col"
            >
              <div className="p-6 border-b border-space-500/20 bg-space-950/50 flex flex-col gap-4">
                <div className="flex justify-between items-start">
                  <div>
                    <div className="text-[10px] font-mono text-neon-500 mb-1">INTELLIGENCE ARCHIVE</div>
                    <h2 className="text-xl font-mono font-bold text-white tracking-wider flex items-center gap-2">
                      SCAN HISTORY
                      {sessions.length > 0 && (
                        <button
                          onClick={() => setShowPurgeConfirm(true)}
                          className="text-[9px] font-tactical px-1.5 py-0.5 rounded border border-risk-critical/30 text-risk-critical hover:bg-risk-critical/10 transition-colors ml-2"
                        >
                          PURGE
                        </button>
                      )}
                    </h2>
                    <p className="text-xs font-tactical text-gray-500 mt-1">{sessions.length} sessions recorded</p>
                  </div>
                  <button onClick={() => { setShowHistory(false); setSelectedSession(null); }} className="p-2 text-gray-500 hover:text-white bg-space-800 border border-space-500/20 hover:border-space-500/50 rounded transition-colors">
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                  </button>
                </div>

                {sessions.length > 0 && (
                  <div className="relative">
                    <input 
                      type="text" 
                      value={historySearch}
                      onChange={(e) => setHistorySearch(e.target.value)}
                      placeholder="Filter by subnet, SSID, or mode..." 
                      className="w-full bg-space-900/50 border border-space-500/20 rounded pl-8 pr-3 py-1.5 text-xs font-mono text-white focus:outline-none focus:border-neon-500/50 placeholder:text-gray-600"
                    />
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5 text-gray-500 absolute left-2.5 top-1/2 -translate-y-1/2" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                  </div>
                )}
              </div>

              <div className="flex-1 overflow-y-auto p-4 space-y-2 [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:bg-space-600 [&::-webkit-scrollbar-thumb]:rounded-full">
                {sessions.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full text-center p-6 opacity-50 hover:opacity-100 transition-opacity">
                    <img src="/cat-archive-empty.svg" alt="Archive Empty" className="w-24 h-24 mb-4 opacity-80" />
                    <div className="text-gray-400 font-mono text-sm mb-2 uppercase tracking-widest">Archive Empty</div>
                    <div className="text-gray-500 font-mono text-[10px] mb-6 max-w-[200px] leading-relaxed">
                      No intrusion data available. Initiate a new network sweep to begin intelligence gathering.
                    </div>
                    <button
                      onClick={() => { setShowHistory(false); setShowConfig(true); }}
                      className="px-4 py-2 bg-neon-500/10 text-neon-400 border border-neon-500/30 hover:bg-neon-500/20 rounded text-xs font-tactical tracking-widest transition-colors"
                    >
                      INITIATE SWEEP
                    </button>
                  </div>
                ) : sessions
                    .filter(s => s.subnet.toLowerCase().includes(historySearch.toLowerCase()) || s.scan_mode.toLowerCase().includes(historySearch.toLowerCase()))
                    .map(session => (
                  <div key={session.id} className="flex flex-col gap-1">
                    <div
                      className={`w-full text-left p-4 rounded-lg border transition-all ${session.host_count === 0 ? 'opacity-50 grayscale' : ''} ${selectedSession?.id === session.id
                        ? 'bg-space-800 border-neon-500/50'
                        : 'bg-space-950/30 border-space-500/20 hover:border-space-500/50 hover:bg-space-800/50'
                        }`}
                    >
                      <div className="flex justify-between items-start mb-2 gap-3">
                        <div className="flex-1 cursor-pointer pr-2" onClick={async () => {
                          if (selectedSession?.id === session.id) {
                            setSelectedSession(null);
                          } else {
                            setSelectedSession(session);
                            try {
                              const hosts = await getSessionHosts(session.id);
                              setSessionHosts(hosts);
                            } catch (e) { console.error(e); }
                          }
                        }}>
                          <span className="text-xs font-mono text-neon-400 line-clamp-2 break-all">{session.subnet}</span>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <span className="text-[10px] font-tactical text-gray-500 px-2 py-0.5 rounded bg-space-800 border border-space-500/20">
                            {session.scan_mode}
                          </span>
                          <button
                            onClick={async (e) => {
                              e.stopPropagation();
                              await deleteSession(session.id);
                              const updated = await getSessions();
                              setSessions(updated);
                              if (selectedSession?.id === session.id) setSelectedSession(null);
                            }}
                            className="text-gray-500 hover:text-risk-high transition-colors p-1"
                            title="Delete Session"
                          >
                            <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 6h18"></path><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                          </button>
                        </div>
                      </div>
                      <div className="flex justify-between items-end">
                        <div className="cursor-pointer" onClick={async () => {
                          if (selectedSession?.id === session.id) {
                            setSelectedSession(null);
                          } else {
                            setSelectedSession(session);
                            try {
                              const hosts = await getSessionHosts(session.id);
                              setSessionHosts(hosts);
                            } catch (e) { console.error(e); }
                          }
                        }}>
                          <div className="text-sm font-mono text-white">{session.host_count} nodes</div>
                          <div className="text-[10px] font-mono text-gray-600 mt-1">
                            {new Date(session.started_at).toLocaleString()}
                          </div>
                        </div>
                        <div className="flex flex-col items-end gap-1">
                          {session.completed_at && (
                            <span className="text-[10px] font-tactical text-green-500/70">COMPLETE</span>
                          )}
                          <button 
                            onClick={(e) => {
                              e.stopPropagation();
                              const cleanSubnet = session.subnet.split(' [')[0];
                              setActiveSubnet(cleanSubnet);
                              setScanMode(session.scan_mode as ScanMode);
                              setShowHistory(false);
                              setShowConfig(true);
                            }}
                            className="text-[9px] font-tactical tracking-wider flex items-center gap-1.5 text-neon-400 border border-neon-500/30 px-2 py-1 rounded hover:bg-neon-500/10 transition-colors mt-1"
                          >
                            <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"></path><path d="M3 3v5h5"></path></svg>
                            RE-SCAN
                          </button>
                        </div>
                      </div>
                    </div>
                    
                    {/* Inline Expanded session detail (Accordion) */}
                    <AnimatePresence>
                      {selectedSession?.id === session.id && sessionHosts.length > 0 && (
                        <motion.div 
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          className="overflow-hidden"
                        >
                          <div className="mt-1 p-3 rounded bg-space-950/50 border border-space-500/10 border-l-2 border-l-neon-500/50 shadow-inner">
                            <div className="text-[9px] font-mono text-gray-500 mb-2 uppercase tracking-wider flex items-center gap-2">
                              <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
                              Discovered Nodes
                            </div>
                            <div className="space-y-1.5">
                              {sessionHosts.map(host => (
                                <div key={host.id} className="p-2 rounded bg-space-900/50 border border-space-500/5">
                                  <div className="flex justify-between items-center mb-0.5">
                                    <span className="text-xs font-mono text-white">{host.ip}</span>
                                    {host.os && <span className="text-[9px] font-tactical text-gray-400">{host.os}</span>}
                                  </div>
                                  {host.hostname && <div className="text-[10px] font-mono text-gray-500 truncate">{host.hostname}</div>}
                                  {host.mac && <div className="text-[9px] font-mono text-gray-600 mt-1">{host.mac.toUpperCase()} — {host.vendor || 'Unknown'}</div>}
                                  {host.ports.length > 0 && (
                                    <div className="flex flex-wrap gap-1 mt-1.5">
                                      {host.ports.map((p: any, i: number) => (
                                        <span key={`${p.port}-${i}`} className="text-[9px] font-mono px-1 py-0.5 rounded bg-space-800 border border-space-500/20 text-gray-400">
                                          {p.port} {p.service}
                                        </span>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                ))}
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>

      <VaultDrawer isOpen={showVault} onClose={() => setShowVault(false)} />

      {/* MITM Drawer */}
      <AnimatePresence>
        {showMitmDrawer && selectedHost && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[120] flex justify-end"
          >
            <div className="absolute inset-0 bg-space-950/80 backdrop-blur-sm" onClick={() => setShowMitmDrawer(false)} />
            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="w-full max-w-2xl bg-space-900 border-l border-space-500/30 h-full flex flex-col relative z-10 shadow-2xl"
            >
              {/* Header */}
              <div className="p-6 border-b border-space-500/20 bg-space-900/80 flex justify-between items-start shrink-0 relative overflow-hidden">
                <div className="absolute top-0 right-0 w-64 h-64 bg-amber-500/5 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2"></div>
                <div>
                  <h2 className="text-2xl font-bold text-white font-mono tracking-tight flex items-center gap-3">
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-6 h-6 text-amber-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M2 12h10M12 2v20M22 12h-10" /></svg>
                    TRAFFIC INTERCEPT
                  </h2>
                  <div className="text-sm font-mono text-gray-500 mt-1">ARP SPOOFING & PACKET INSPECTION</div>
                </div>
                <button
                  onClick={() => setShowMitmDrawer(false)}
                  className="p-2 hover:bg-space-800 rounded-md transition-colors text-gray-400 hover:text-white relative z-10"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                </button>
              </div>

              {/* Body */}
              <div className="flex-1 overflow-y-auto no-scrollbar p-6 space-y-6 flex flex-col relative">
                <div className="bg-space-950/50 border border-space-500/20 rounded-lg p-4">
                  <div className="flex justify-between items-center">
                    <div>
                      <div className="text-xs font-tactical text-gray-500 tracking-widest mb-1">TARGET NODE</div>
                      <div className="text-lg font-mono text-white">{selectedHost.ip}</div>
                      <div className="text-xs font-mono text-gray-400">{selectedHost.hostname || 'Unknown'}</div>
                    </div>
                    <div className="text-amber-500">
                      <svg xmlns="http://www.w3.org/2000/svg" className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m18 15-6-6-6 6" /></svg>
                    </div>
                    <div className="text-right">
                      <div className="text-xs font-tactical text-gray-500 tracking-widest mb-1">NETWORK GATEWAY</div>
                      <div className="text-lg font-mono text-white">{gatewayIp}</div>
                      <div className="text-xs font-mono text-gray-400">Router</div>
                    </div>
                  </div>
                </div>

                {mitmState === 'IDLE' && mitmPackets.length === 0 ? (
                  <div className="flex-1 flex flex-col items-center justify-center text-center p-8">
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-16 h-16 text-space-600 mb-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><path d="M2 12h10M12 2v20M22 12h-10" /></svg>
                    <h3 className="text-lg font-tactical text-gray-400 tracking-widest mb-2">READY TO INTERCEPT</h3>
                    <p className="text-sm font-mono text-gray-600 max-w-sm mb-6">Spoof ARP tables to reroute target traffic through LOCKON. Unencrypted DNS and HTTP requests will be captured.</p>

                    <div className="flex items-center gap-3 mb-6">
                      <button
                        onClick={() => setSavePcap(!savePcap)}
                        className={`w-10 h-5 rounded-full relative transition-colors ${savePcap ? 'bg-amber-500' : 'bg-space-800'}`}
                      >
                        <div className={`absolute top-1 left-1 w-3 h-3 rounded-full bg-white transition-transform ${savePcap ? 'translate-x-5' : 'translate-x-0'}`} />
                      </button>
                      <span className={`text-xs font-mono ${savePcap ? 'text-amber-400' : 'text-gray-500'}`}>SAVE PCAP EVIDENCE (.pcap)</span>
                    </div>

                    <button
                      onClick={() => {
                        engineIPC.send('start_mitm', { target_ip: selectedHost.ip, gateway_ip: gatewayIp, interface: interfaceName, save_pcap: savePcap }).catch(console.error);
                      }}
                      className="px-6 py-2 bg-amber-500/20 hover:bg-amber-500/30 text-amber-400 border border-amber-500/50 rounded font-tactical tracking-widest transition-colors flex items-center gap-2"
                    >
                      INITIATE SPOOFING
                    </button>
                  </div>
                ) : (
                  <div className="flex-1 flex flex-col border border-space-500/20 rounded-lg overflow-hidden bg-[#0a0d14]">
                    <div className="bg-space-900 border-b border-space-500/20 px-4 py-3 flex flex-col sm:flex-row gap-3 sm:gap-0 justify-between items-center shrink-0">
                      <div className="flex items-center gap-4">
                        <div className="flex items-center gap-2">
                          <div className={`w-2 h-2 rounded-full ${mitmState === 'SPOOFING' ? 'bg-amber-500 animate-pulse' : 'bg-red-500'}`}></div>
                          <span className="text-[10px] font-tactical tracking-widest text-gray-300">
                            {mitmState === 'SPOOFING' ? 'LIVE TRAFFIC' : 'ATTACK HALTED'}
                          </span>
                        </div>
                        {mitmState === 'SPOOFING' && (
                          <div className="flex gap-[1px] h-3 items-end">
                            {Array.from({length: 12}).map((_, i) => (
                              <div key={i} className="w-1 bg-amber-500/70" style={{ height: `${Math.max(20, Math.random() * 100)}%`, animation: `pulse ${0.5 + Math.random()}s infinite alternate` }}></div>
                            ))}
                          </div>
                        )}
                      </div>
                      <div className="flex items-center gap-1 bg-space-950 p-1 rounded border border-space-500/30">
                        {(['ALL', 'CREDENTIALS', 'WEB', 'DNS'] as const).map(f => (
                          <button
                            key={f}
                            onClick={() => setMitmFilter(f)}
                            className={`px-2 py-0.5 text-[9px] font-tactical tracking-wider rounded transition-colors ${
                              mitmFilter === f
                                ? (f === 'CREDENTIALS' ? 'bg-risk-critical text-white' : 'bg-amber-500/20 text-amber-400')
                                : 'text-gray-500 hover:text-gray-300'
                            }`}
                          >
                            {f} {f === 'CREDENTIALS' && mitmPackets.filter(p => p.info.includes('[CREDENTIALS]')).length > 0 && `(${mitmPackets.filter(p => p.info.includes('[CREDENTIALS]')).length})`}
                          </button>
                        ))}
                      </div>
                    </div>
                    
                    {/* Loot Vault (only visible if credentials exist) */}
                    {mitmPackets.filter(p => p.info.includes('[CREDENTIALS]')).length > 0 && (
                      <div className="bg-risk-critical/10 border-b border-risk-critical/30 p-2 shrink-0 max-h-32 overflow-y-auto custom-scrollbar">
                        <div className="text-[9px] font-tactical text-risk-critical tracking-widest mb-1.5 flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-risk-critical animate-pulse"></span>
                          INTERCEPTED CREDENTIALS
                        </div>
                        <div className="space-y-1">
                          {mitmPackets.filter(p => p.info.includes('[CREDENTIALS]')).map((pkt, i) => (
                            <div key={i} className="flex justify-between items-center text-[10px] font-mono bg-space-950/50 p-1.5 rounded border border-risk-critical/20">
                              <span className="text-white truncate">{pkt.info.replace('[CREDENTIALS]', '').trim()}</span>
                              <button onClick={() => { navigator.clipboard.writeText(pkt.info); showToast('Credential copied', 'info'); }} className="text-risk-critical hover:text-white px-2 shrink-0">COPY</button>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="flex-1 p-2 overflow-y-auto custom-scrollbar flex flex-col-reverse relative">
                      <div className="space-y-1 font-mono text-[11px] pb-4">
                        {mitmPackets.filter(p => {
                          if (mitmFilter === 'ALL') return true;
                          if (mitmFilter === 'CREDENTIALS') return p.info.includes('[CREDENTIALS]');
                          if (mitmFilter === 'WEB') return p.info.includes('[SNI]') || p.protocol === 'HTTP';
                          if (mitmFilter === 'DNS') return p.protocol === 'DNS';
                          return true;
                        }).map((pkt, i) => {
                          const isCred = pkt.info.includes('[CREDENTIALS]');
                          const isWeb = pkt.info.includes('[SNI]') || pkt.protocol === 'HTTP';
                          const isDns = pkt.protocol === 'DNS';
                          
                          return (
                            <div key={i} className={`flex gap-3 px-2 py-1.5 rounded border-l-2 transition-colors ${
                              isCred ? 'bg-risk-critical/10 hover:bg-risk-critical/20 border-l-risk-critical text-white' :
                              isWeb ? 'hover:bg-space-800/50 border-l-neon-400/50' :
                              isDns ? 'hover:bg-space-800/30 border-l-space-500/30 opacity-70 hover:opacity-100' :
                              'hover:bg-space-800/30 border-l-amber-500/50'
                            }`}>
                              <span className="text-gray-600 shrink-0">{new Date(pkt.timestamp * 1000).toLocaleTimeString()}</span>
                              <span className={`shrink-0 w-12 font-bold ${
                                isCred ? 'text-risk-critical' :
                                isDns ? 'text-gray-500' :
                                isWeb ? 'text-neon-400' : 'text-amber-400'
                              }`}>{pkt.protocol}</span>
                              <span className={`truncate ${isCred ? 'text-risk-critical font-bold' : isWeb ? 'text-gray-300' : 'text-gray-400'}`}>
                                {pkt.info}
                              </span>
                            </div>
                          );
                        })}
                        {mitmPackets.length === 0 && (
                          <div className="text-center text-gray-600 py-10 italic">Awaiting packets...</div>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>

            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Toast Notification */}
      <AnimatePresence>
        {toast.show && (
          <motion.div
            initial={{ opacity: 0, y: 50 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 50 }}
            className={`fixed bottom-6 right-6 z-[200] px-5 py-3 rounded-lg border backdrop-blur-md shadow-2xl text-xs font-tactical tracking-wider flex items-center gap-2 ${
              toast.type === 'success' ? 'bg-signal-strong/20 border-signal-strong/40 text-signal-strong' :
              toast.type === 'error' ? 'bg-risk-critical/20 border-risk-critical/40 text-risk-critical' :
              'bg-neon-500/20 border-neon-500/40 text-neon-400'
            }`}
          >
            {toast.type === 'success' ? '✓' : toast.type === 'error' ? '✗' : 'ℹ'} {toast.message}
          </motion.div>
        )}
      </AnimatePresence>

      <ConfirmModal
        isOpen={showPurgeConfirm}
        title="PURGE SCAN HISTORY"
        message="Are you sure you want to delete ALL scan history? This action cannot be undone."
        confirmLabel="PURGE ALL"
        variant="danger"
        onConfirm={async () => {
          await deleteAllSessions();
          setSessions([]);
          setSelectedSession(null);
        }}
        onCancel={() => setShowPurgeConfirm(false)}
      />

    </div>
  );
}
