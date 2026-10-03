/**
 * LOCKON EWAC — everything the engine says, routed to where it is kept.
 *
 * Sixty-one `engineIPC.on()` handlers used to live inside `AppShell`, a layout
 * component, in one 900-line `useEffect`. Forty-eight of them were pure routing:
 * take an event off the sidecar, write it to a store or to SQLite. The engine's
 * entire contract with the application — every field that survives a scan, every
 * row a finding is written from, what happens when a capture fails — was
 * expressed in a React component nothing could reach from a test.
 *
 * That is why this file exists rather than for the line count. The handlers are
 * where the engine's vocabulary meets this app's schema, and that boundary is
 * exactly where a rename on one side and not the other stops a field from ever
 * being stored. Two of this project's defects were that: `cipher` and
 * `auth_type` declared everywhere and never populated, and `radio_type` reaching
 * the live feed and no column. A test can now emit an event and assert what
 * landed.
 *
 * **What stayed behind.** Thirteen handlers do something visible — a toast, the
 * sonar ping, the offline banner — and those go through `hooks`, so this module
 * never imports React and never touches the DOM. That keeps it runnable under
 * `node --test` with the SQLite stub, which is the only reason the routing is
 * testable at all.
 *
 * **Store actions are read through `getState()`, not captured.** The handlers
 * were written against destructured actions from `useStore(s => s.action)`;
 * aliasing them here to `getState()` lookups let the 800 lines move verbatim,
 * which is what `pdfdiff`-style verification depends on. Zustand actions are
 * stable, so this is equivalent — but it also means a handler always writes to
 * the live store rather than to a snapshot React captured on some earlier render.
 */
import { engineIPC } from './ipc';
import { createSession, saveHost, completeSession, updateSessionSubnet } from './intrusionDB';
import { logGps, logAccessPoint, saveApLocation, recordWpsMeasurements } from './wardrivingDB';
import { recordAuditEvent } from './scopeDB';
import { pushScopeToEngine } from './scopeSync';
import { recordEvidence, recordClient, upsertFindings } from './findingsDB';
import {
  assessAccessPoint,
  assessHost,
  assessServiceObservations,
  smbObservations,
  dirbusterObservations,
  hostOfUrl,
} from './riskEngine';
import { metresBetween, gpsStepFloorM } from './localization';
import { useEngineStore } from '../stores/engineStore';
import { useMissionStore } from '../stores/missionStore';
import { useIntrusionStore } from '../stores/intrusionStore';
import { useStrikeStore } from '../stores/strikeStore';
import { useReportStore } from '../stores/reportStore';
import type {
  EngineMessage,
  ScopeStatus,
  ScopeDenied,
  SimulationScenario,
  NetContext,
} from '../types/engine';
import { mapEngineStatus } from '../types/engine';
import type { AccessPoint } from '../types/models';
import { coordinatePair } from './numbers';

export type ToastType = 'error' | 'warning' | 'info' | 'success';

/**
 * The few things routing cannot do by itself.
 *
 * Deliberately small. Anything that can be expressed as "write this to a store"
 * belongs in a handler, not here — the point of the split is that the visible
 * surface is the exception rather than the rule.
 */
export interface EngineRouterHooks {
  /** Show a transient message to the operator. */
  showToast(message: string, type?: ToastType, duration?: number): void;
  /** Record a connection failure for the offline banner, or clear it with null. */
  setConnError(message: string | null): void;
  /**
   * Audible cue for a newly seen access point; louder for a high-risk one.
   *
   * Optional, and that is the point: a test registers the handlers without it
   * and the routing runs unchanged. Web Audio has nothing to say about whether
   * an access point was stored correctly.
   */
  sonarPing?(isHighRisk: boolean): void;
}

/**
 * Assess an AP through the single risk rule set and store the resulting findings.
 *
 * Severity used to be recomputed at render time by whichever view happened to be
 * drawing, which is how one PDF ended up counting a network as vulnerable in its
 * headline while printing it as LOW in the table below. Findings are now written
 * once, with the reason and the rule version attached, and every view reads them.
 */
function persistFindingsForAp(ap: AccessPoint, missionId: string) {
  try {
    const findings = assessAccessPoint(ap as any);
    if (findings.length === 0) return;
    upsertFindings(findings, { mission_id: missionId })
      .catch(err => console.error('[DB] upsertFindings error:', err));
  } catch (err) {
    console.error('[Risk] assessment failed:', err);
  }
}

/**
 * Subscribe every engine event, and return the function that unsubscribes them.
 *
 * Call once per application lifetime. The returned cleanup detaches the handlers
 * and stops the status poll; it deliberately does **not** shut the sidecar down —
 * that is an app-lifetime singleton, and React's development double-mount runs
 * this cleanup between the two mounts, which is what used to leave the app
 * showing "Engine: OFFLINE" with no way back.
 */
export function registerEngineHandlers(hooks: EngineRouterHooks): () => void {
  /*
    Aliases, so the handlers below read exactly as they did inside the component
    and the move could be verified rather than reviewed line by line.
  */
  const setConnected = (v: boolean) => useEngineStore.getState().setConnected(v);
  const updateStatus = (...a: Parameters<ReturnType<typeof useEngineStore.getState>['updateStatus']>) =>
    useEngineStore.getState().updateStatus(...a);
  const setGpsFix = (...a: Parameters<ReturnType<typeof useEngineStore.getState>['setGpsFix']>) =>
    useEngineStore.getState().setGpsFix(...a);
  const addAccessPoint = (...a: Parameters<ReturnType<typeof useMissionStore.getState>['addAccessPoint']>) =>
    useMissionStore.getState().addAccessPoint(...a);
  const stopIntrusion = (...a: Parameters<ReturnType<typeof useIntrusionStore.getState>['stopIntrusion']>) =>
    useIntrusionStore.getState().stopIntrusion(...a);
  const setProgress = (...a: Parameters<ReturnType<typeof useIntrusionStore.getState>['setProgress']>) =>
    useIntrusionStore.getState().setProgress(...a);
  const addHost = (...a: Parameters<ReturnType<typeof useIntrusionStore.getState>['addHost']>) =>
    useIntrusionStore.getState().addHost(...a);
  const showEngineToast = hooks.showToast;
  const setConnError = hooks.setConnError;
  const playSonarPing = (isHighRisk: boolean) => hooks.sonarPing?.(isHighRisk);

    // Load persisted reports from SQLite
  useReportStore.getState().loadReports();

  // Connect to Python Engine. connectWithRetry schedules a retry when the
  // spawn itself fails — the close-handler reconnect never fires in that case,
  // so a missing or quarantined sidecar used to leave the app offline for good.
  engineIPC.connectWithRetry().catch((err) => {
    console.error(err);
    setConnError(String(err));
  });


  const unsubAP = engineIPC.on('ap_found', (msg: EngineMessage) => {
    const ap = msg.data as unknown as AccessPoint;
    const mState = useMissionStore.getState();
    const isNew = !mState.accessPoints.has(ap.bssid);
    
    if (isNew) {
      playSonarPing(ap.is_vulnerable || ap.encryption === 'OPEN');
    }
    
    addAccessPoint(ap);

    if (mState.activeMission) {
      const engine = useEngineStore.getState();
      // Fix quality travels with the sighting so coverage reporting can later
      // distinguish an empty area from one surveyed on a poor fix.
      logAccessPoint(mState.activeMission.id, ap, engine.latitude, engine.longitude, {
        hdop: engine.hdop, satellites: engine.satellites, speed: engine.speed,
      }).catch(err => console.error('[DB] logAP error:', err));

      persistFindingsForAp(ap, mState.activeMission.id);
    }
  });

  const unsubAPBatch = engineIPC.on('aps_batch', (msg: EngineMessage) => {
    // Payload is now { aps, total } rather than a bare array: emit() coerces a
    // falsy payload to {}, so an empty batch arrived as {} and broke consumers.
    const aps = (msg.data as { aps?: AccessPoint[] })?.aps;
    if (!Array.isArray(aps)) return;

    const mState = useMissionStore.getState();
    const currentAPs = mState.accessPoints;
    
    let newApFound = false;
    let newHighRisk = false;
    
    for (const ap of aps) {
      if (!currentAPs.has(ap.bssid)) {
        newApFound = true;
        if (ap.is_vulnerable || ap.encryption === 'OPEN') newHighRisk = true;
      }
      
      if (mState.activeMission) {
        const engine = useEngineStore.getState();
        logAccessPoint(mState.activeMission.id, ap, engine.latitude, engine.longitude, {
          hdop: engine.hdop, satellites: engine.satellites, speed: engine.speed,
        }).catch(err => console.error('[DB] logAP batch error:', err));

        persistFindingsForAp(ap, mState.activeMission.id);
      }
    }

    if (newApFound) {
      playSonarPing(newHighRisk);
    }

    mState.addAccessPoints(aps);
  });

  // --- Intrusion Events ---
  const unsubIntrusionProgress = engineIPC.on('intrusion_progress', (msg) => {
    const { progress, scanned, total } = msg.data as any;
    setProgress(progress, scanned, total);
  });

  /**
   * The engine never emitted `intrusion_started`, so the listener that used to
   * live here was dead code and `targetSubnet` was never populated — which is
   * why archived intrusion reports were all labelled 'UNKNOWN SUBNET'. This is
   * the first event that actually tells us what is being swept, so the session
   * row and the target subnet are established here.
   */
  const unsubIntrusionSubnets = engineIPC.on('intrusion_subnets_found', (msg) => {
    const foundSubnets: string[] = (msg.data as any).subnets || [];
    const store = useIntrusionStore.getState();
    store.setSubnets(foundSubnets);

    const primary = foundSubnets[0];
    if (primary) {
      useIntrusionStore.setState({ targetSubnet: primary });
    }

    const sessionId = store.currentSessionId;
    const activeSsid = store.activeSsid;
    if (sessionId && primary) {
      const ssidContext = activeSsid ? ` [${activeSsid}]` : '';
      // Create the session if the page has not already done so, then record
      // the subnet it resolved to.
      createSession(sessionId, primary, store.currentScanMode,
                    useEngineStore.getState().config.emulateHardware)
        .catch(() => { /* already exists — the update below is what matters */ })
        .finally(() => {
          updateSessionSubnet(sessionId, primary + ssidContext).catch(console.error);
        });
    }
  });

  /**
   * How much of each subnet was actually probed.
   *
   * The engine has emitted this since the ARP pre-filter was added, carrying
   * `addresses_in_range` against `addresses_probed` and the caveat that
   * "absence here is not evidence that nothing is there" — and nothing
   * subscribed to it. A sweep that probed six addresses out of 253 reported
   * exactly the same as one that probed all of them, in the UI and in the
   * report, so a false negative was indistinguishable from a clean result.
   */
  const unsubIntrusionScope = engineIPC.on('intrusion_scope', (msg) => {
    const d = msg.data as any;
    if (!d?.subnet) return;
    const inRange = Number(d.addresses_in_range) || 0;
    const probed = Number(d.addresses_probed) || 0;
    const neverSwept = Number(d.addresses_never_swept) || 0;
    useIntrusionStore.getState().recordSweepScope({
      subnet: String(d.subnet),
      addressesInRange: inRange,
      addressesProbed: probed,
      skippedByArpFilter: Number(d.skipped_by_arp_filter) || 0,
      addressesNeverSwept: neverSwept,
      arpReadError: d.arp_read_error ? String(d.arp_read_error) : null,
      scanMode: String(d.scan_mode ?? ''),
      discovery: String(d.discovery ?? ''),
      caveat: String(d.caveat ?? ''),
    });
    // Surface a materially narrow sweep at the moment it happens, not only in
    // the export. Probing nothing at all is the case that most needs saying:
    // it is what an ARP read failure looks like from here.
    // The ARP read failing is the most consequential thing that can go wrong
    // in a sweep and the least visible: the pre-filter decides what gets
    // probed, so a failed read silently narrows a /24 to two addresses and
    // the run still completes looking normal. It leads.
    if (d.arp_read_error) {
      showEngineToast(
        `${d.subnet}: the ARP table could not be read (${d.arp_read_error}). Only a fallback sample was probed — treat this subnet as unsurveyed, not quiet. DEEP mode ignores the pre-filter.`,
        'error', 12000
      );
    } else if (inRange > 0 && probed === 0) {
      showEngineToast(
        `${d.subnet}: nothing was probed — no address answered ARP. This says nothing about what is on that subnet.`,
        'error', 9000
      );
    } else if (neverSwept > 0) {
      // Being never contacted is a different and stronger caveat than being
      // asked and staying silent, so it gets said on its own.
      showEngineToast(
        `${d.subnet}: ${neverSwept} of ${inRange} addresses were never contacted — the ARP sweep is capped per subnet. Nothing in this result describes them.`,
        'warning', 9000
      );
    } else if (inRange > 0 && probed < inRange / 4) {
      showEngineToast(
        `${d.subnet}: probed ${probed} of ${inRange} addresses. Hosts that did not answer ARP were never contacted.`,
        'warning', 7000
      );
    }
  });

  /**
   * The engine emits both halves of this diff — `new` and `disappeared` — but
   * only `new` was ever handled, so a device that dropped off the network was
   * silently discarded. On a retest that is exactly the signal that matters:
   * a host that is gone may be the thing that was remediated.
   */
  const unsubIntrusionDiff = engineIPC.on('intrusion_diff', (msg) => {
    const data = msg.data as any;

    /*
      `unavailable` carries no devices, and the early return below would drop it.

      The diff is built from the ARP cache, so a failed ARP read made every device
      seen last sweep look as though it had left the network. The engine now says it
      could not compare instead, and the previous list is cleared rather than left on
      screen describing a comparison that did not happen.
    */
    if (data?.type === 'unavailable') {
      useIntrusionStore.getState().setNewDevices([]);
      useIntrusionStore.getState().setDisappearedDevices([]);
      showEngineToast(
        String(data.reason || 'No comparison with the previous sweep was possible.'),
        'warning', 9000,
      );
      return;
    }

    if (!data?.devices?.length) return;

    if (data.type === 'new') {
      useIntrusionStore.getState().setNewDevices(data.devices);
      showEngineToast(`${data.devices.length} new device(s) since the last sweep`, 'info', 4000);
    } else if (data.type === 'disappeared') {
      useIntrusionStore.getState().setDisappearedDevices(data.devices);
      showEngineToast(
        `${data.devices.length} device(s) no longer responding: ${data.devices.slice(0, 3).join(', ')}${data.devices.length > 3 ? '…' : ''}`,
        'info', 5000
      );
    }
  });

  const unsubIntrusionHost = engineIPC.on('intrusion_host_found', (msg) => {
    const hostData = msg.data as any;
    addHost(hostData);
    // Auto-persist to SQLite
    const sessionId = useIntrusionStore.getState().currentSessionId;
    if (sessionId) {
      saveHost(sessionId, hostData).catch(err => console.error('[DB] saveHost error:', err));

      // Host findings used to survive only inside a report's JSON blob, so a
      // host's assessment could not be queried or compared between runs.
      try {
        const findings = assessHost(hostData);
        if (findings.length) {
          upsertFindings(findings, { session_id: sessionId })
            .catch(err => console.error('[DB] upsertFindings(host) error:', err));
        }
      } catch (err) {
        console.error('[Risk] host assessment failed:', err);
      }
    }
  });

  /**
   * Service-inspection results, persisted so they reach the report.
   *
   * `vuln_scan_completed` was handled only in `IntrusionPage`, which kept the
   * findings in component state. `findings` was written from two places in this
   * file and nowhere else, so an unauthenticated Redis or an anonymous FTP
   * login appeared on screen at CRITICAL while the exported PDF raised nothing
   * for that host — and the state was gone as soon as the page unmounted.
   *
   * Severity comes from `assessServiceObservations`, not from the engine's own
   * `severity` field, so these rows are scored by the same rule set as
   * everything else in the document.
   */
  const unsubVulnScanPersist = engineIPC.on('vuln_scan_completed', (msg) => {
    const d = msg.data as any;
    const target = String(d?.target ?? '').trim();
    // The engine emits `target: null` with an error when the request was
    // malformed. There is nothing to attribute a finding to in that case.
    if (!target) return;
    const observations = Array.isArray(d?.findings) ? d.findings : [];
    if (!observations.length) return;
    const sessionId = useIntrusionStore.getState().currentSessionId;
    try {
      const findings = assessServiceObservations(target, observations);
      if (findings.length) {
        upsertFindings(findings, { session_id: sessionId ?? undefined })
          .catch(err => console.error('[DB] upsertFindings(service) error:', err));
      }
    } catch (err) {
      console.error('[Risk] service assessment failed:', err);
    }
  });

  /**
   * SMB enumeration results, persisted through the one rule set.
   *
   * Same gap as `vuln_scan`: the panel held them in component state and the
   * PDF raised nothing, so an operator could see SMBv1 enabled on screen
   * while the report for that host said nothing about it.
   */
  const unsubSmbPersist = engineIPC.on('smb_enum_completed', (msg) => {
    const d = msg.data as any;
    const target = String(d?.target ?? '').trim();
    if (!target) return;
    const sessionId = useIntrusionStore.getState().currentSessionId;
    try {
      const findings = assessServiceObservations(target, smbObservations(d));
      if (findings.length) {
        upsertFindings(findings, { session_id: sessionId ?? undefined })
          .catch(err => console.error('[DB] upsertFindings(smb) error:', err));
      }
    } catch (err) {
      console.error('[Risk] SMB assessment failed:', err);
    }
  });

  /**
   * Directory-enumeration hits.
   *
   * Batched per target rather than written per event: dirbuster emits one
   * event per responding path and each `upsertFindings` is its own
   * transaction, so a wordlist with a few hundred hits would otherwise be a
   * few hundred fsyncs during the scan.
   */
  const dirbusterPending = new Map<string, { path?: string; status?: number; size?: number }[]>();
  const unsubDirbusterFinding = engineIPC.on('dirbuster_finding', (msg) => {
    const d = msg.data as any;
    // Keyed by the host, not by the full URL. The subject of a finding is the
    // machine; the path is a detail of the observation. Keying by URL would
    // make one web server appear as one host per responding path in every
    // count the report prints.
    const host = hostOfUrl(d?.url);
    if (!host) return;
    const bucket = dirbusterPending.get(host) ?? [];
    bucket.push({ path: d?.path, status: d?.status, size: d?.size });
    dirbusterPending.set(host, bucket);
  });
  const unsubDirbusterDone = engineIPC.on('dirbuster_completed', (msg) => {
    const host = hostOfUrl((msg.data as any)?.target);
    const sessionId = useIntrusionStore.getState().currentSessionId;
    const flush = (subject: string, hits: { path?: string; status?: number; size?: number }[]) => {
      try {
        const findings = assessServiceObservations(subject, dirbusterObservations(hits));
        if (findings.length) {
          upsertFindings(findings, { session_id: sessionId ?? undefined })
            .catch(err => console.error('[DB] upsertFindings(dirbuster) error:', err));
        }
      } catch (err) {
        console.error('[Risk] dirbuster assessment failed:', err);
      }
    };
    if (host && dirbusterPending.has(host)) {
      flush(host, dirbusterPending.get(host)!);
      dirbusterPending.delete(host);
    } else {
      // No matchable target on the completion event — flush everything rather
      // than leaving observations stranded in a Map that dies with the app.
      for (const [subject, hits] of dirbusterPending) flush(subject, hits);
      dirbusterPending.clear();
    }
  });

  const unsubIntrusionComplete = engineIPC.on('intrusion_complete', () => {
    const sessionId = useIntrusionStore.getState().currentSessionId;
    const hostCount = Object.keys(useIntrusionStore.getState().hosts).length;
    if (sessionId) {
      completeSession(sessionId, hostCount).catch(err => console.error('[DB] completeSession error:', err));
    }
    stopIntrusion();
  });
  // ------------------------

  // --- STRIKE Events ---
  const unsubStrikeStarted = engineIPC.on('strike_started', (msg) => {
    const data = msg.data as any;
    useStrikeStore.getState().startStrike(data.target_mac, data.gateway_bssid);
  });

  const unsubStrikeProgress = engineIPC.on('strike_progress', (msg) => {
    const data = msg.data as any;
    useStrikeStore.getState().updateStrike(data.target_mac, { packetsSent: data.packets_sent });
  });

  const unsubStrikeStopped = engineIPC.on('strike_stopped', (msg) => {
    const data = msg.data as any;
    // FAILED is honoured rather than folded into COMPLETED. A strike whose
    // frames the interface refused used to finish as "COMPLETED" right after
    // its own error event, so nothing downstream could tell a deauth that
    // went out from one that never left the adapter.
    const status = data.status === 'CEASED' ? 'CEASED'
      : data.status === 'FAILED' ? 'ERROR'
      : 'COMPLETED';
    useStrikeStore.getState().updateStrike(data.target_mac, {
      status,
      packetsSent: data.packets_sent
    });
    if (data.status === 'FAILED') {
      showEngineToast(
        `Deauth against ${data.target_mac} transmitted nothing: ${data.error ?? 'the interface refused the frames'}.`,
        'error', 9000
      );
    }
  });

  const unsubStrikeError = engineIPC.on('strike_error', (msg) => {
    const data = msg.data as any;
    console.error('[STRIKE ERROR]', data.message);
    if (data.target_mac) {
      useStrikeStore.getState().updateStrike(data.target_mac, { status: 'ERROR' });
    }
  });
  // ---------------------

  const unsubGPS = engineIPC.on('gps_update', (msg: EngineMessage) => {
    const data = msg.data as any;
    // satellites/hdop are carried through so the KPI tile can show the real
    // fix quality instead of the hardcoded 8 it used to display.
    setGpsFix({
      latitude: data.latitude,
      longitude: data.longitude,
      heading: data.heading,
      speed: data.speed,
      satellites: data.satellites,
      hdop: data.hdop,
    });

    const mState = useMissionStore.getState();
    /*
      `coordinatePair`, not `data.latitude && data.longitude`.

      This is the gate on *recording*, not on drawing: a fix that fails it is
      never appended to the track and `logGps` never runs, so it is absent from
      the database and from every document made afterwards. A truthiness test
      therefore meant that on the equator or the prime meridian the survey
      silently recorded nothing at all, and the one rule this project has for
      what counts as a position was written down two files away.
    */
    const fix = coordinatePair(data.latitude, data.longitude);
    if (mState.activeMission && fix) {
      /*
        A fix is not a step.

        Every fix used to be appended, so a receiver standing still wrote its own
        scatter into the route as though it were travel. One archived survey holds
        280 fixes spanning 9.9 m end to end: the vehicle marker crawled around the
        map while nobody moved, the track filled with noise, and --- worse --- the
        localizer reads that track as the baseline it trilaterates from, so the
        scatter was being offered to it as geometry.

        GPS_STEP_M is the floor for calling something movement. Consumer receivers
        scatter a few metres while stationary; below that this is noise, and the
        last accepted position stands.
      */
      /*
        The same floor as the marker, derived from this fix's own HDOP.

        It matters more here than on screen. A marker that crawls is a nuisance
        for as long as the operator is looking at it; a track that records scatter
        as route is handed to the localizer as the baseline it multilaterates
        from, and then to the report as the distance surveyed.
      */
      const prev = mState.pathCoords[mState.pathCoords.length - 1];
      const floorM = gpsStepFloorM(data.hdop);
      const moved = !prev || metresBetween(prev[0], prev[1], fix.lon, fix.lat) >= floorM;
      if (moved) {
        mState.appendPathCoord([fix.lon, fix.lat]);
        logGps(mState.activeMission.id, fix.lat, fix.lon, data.heading, data.speed)
          .catch(err => console.error('[DB] logGps error:', err));
      }
    }
  });

  const unsubStatus = engineIPC.on('status', (msg: EngineMessage) => {
    // The engine speaks snake_case (gps_locked / wifi_ready). Spreading that
    // straight into the camelCase store meant `wifiReady` was never set by
    // anything, so the adapter readout said "SEARCHING" forever, while the
    // unmapped keys were written as junk state on every 2s poll.
    updateStatus(mapEngineStatus(msg.data));
  });

  const unsubInterfaces = engineIPC.on('interfaces_list', (msg: EngineMessage) => {
    const data = msg.data as any;
    useEngineStore.setState({
      wifiInterfaces: data.interfaces || [],
      comPorts: data.com_ports || [],
    });

    const { config, setConfig } = useEngineStore.getState();
    if (data.interfaces?.length > 0 && !config.interfaceName) {
       setConfig({ interfaceName: data.interfaces[0] });
    }
  });

  const unsubPurged = engineIPC.on('data_purged', () => {
    useMissionStore.getState().reset();
    useIntrusionStore.getState().reset();
  });

  /**
   * Everything the engine needs to be told about after a (re)start.
   *
   * Pushing the scope is the important part: the engine holds its own copy and
   * denies everything when it has none, so a reconnect that skipped this would
   * silently disarm every offensive module until the operator visited Settings.
   */
  const syncEngineState = () => {
    engineIPC.send('get_interfaces').catch(console.error);
    engineIPC.send('get_wordlists').catch(console.error);
    const config = useEngineStore.getState().config;
    engineIPC.send('set_auto_attack', { enabled: config.enableAutoAttack }).catch(console.error);
    // Ask what this hardware can actually do, and how old the CVE data is.
    // Both answers gate what the UI should let the operator believe.
    // With the adapter named, so the raw-socket test answers about the interface
    // a capture will really use rather than about the default route.
    engineIPC.send('check_capabilities', {
      interface_name: useEngineStore.getState().config.interfaceName || null,
    }).catch(console.error);
    engineIPC.send('get_net_context').catch(console.error);
    engineIPC.send('get_cve_info').catch(console.error);
    pushScopeToEngine()
      .then(payload => {
        if (!payload.engagement_name) {
          showEngineToast(
            'No active engagement scope — offensive modules are blocked. Define one in Settings.',
            'warning',
            8000
          );
        }
      })
      .catch(err => {
        console.error('[SCOPE] push failed:', err);
        showEngineToast(`Could not send engagement scope to engine: ${err}`, 'error', 10000);
      });
  };

  const unsubReady = engineIPC.on('ready', (msg) => {
    setConnected(true);
    setConnError(null);
    /*
      Record what the sidecar actually is.

      `engineVersion` was declared in the store and never written, and the
      engine reported a hardcoded "0.1.0", so the report's provenance carried
      no real engine identity and a stale binary was invisible. The build
      stamp is also what the PDF's method appendix needs: a severity traced to
      a rule set is only auditable if the software that produced it can be
      named.
    */
    const d = (msg.data ?? {}) as { version?: string; build?: unknown };
    const build = (d.build && typeof d.build === 'object' ? d.build : null) as
      import('../stores/engineStore').EngineBuild | null;
    useEngineStore.getState().setEngineBuild(d.version ?? build?.version ?? null, build);
    syncEngineState();
  });
  
  const unsubWordlists = engineIPC.on('wordlists_list', (msg: EngineMessage) => {
    // Payload is now { wordlists, total }; the array and `lists` forms are
    // accepted so a stale sidecar binary does not blank the picker.
    const data = msg.data as any;
    const lists = Array.isArray(data) ? data
      : Array.isArray(data?.wordlists) ? data.wordlists
      : Array.isArray(data?.lists) ? data.lists
      : [];
    useEngineStore.getState().setWordlists(lists);
  });

  const unsubWordlistError = engineIPC.on('wordlist_error', (msg: EngineMessage) => {
    const data = msg.data as { name?: string; message: string };
    showEngineToast(`WORDLIST${data.name ? ` [${data.name}]` : ''}: ${data.message}`, 'error');
  });

  const unsubPing = engineIPC.on('pong', () => setConnected(true));
  const unsubDisc = engineIPC.on('disconnected', () => {
    setConnected(false);
    showEngineToast('Engine disconnected. Attempting reconnection...', 'warning', 4000);
  });
  const unsubError = engineIPC.on('error', (msg: EngineMessage) => {
    console.error('ENGINE ERROR:', msg.data);
    const errorMsg = (msg.data as any)?.message || 'Unknown engine error';
    showEngineToast(`Engine: ${errorMsg}`, 'error');
  });

  // --- Reconnection Events ---
  const unsubReconnecting = engineIPC.on('reconnecting', (msg) => {
    const data = msg.data as any;
    setConnError(`Reconnecting to engine... (attempt ${data.attempt})`);
  });
  const unsubReconnected = engineIPC.on('reconnected', () => {
    setConnected(true);
    setConnError(null);
    showEngineToast('Engine reconnected successfully', 'info', 3000);
    syncEngineState();
  });
  const unsubReconnectFailed = engineIPC.on('reconnect_failed', () => {
    window.dispatchEvent(new CustomEvent('lockon:toast', {
      detail: { message: 'ENGINE CONNECTION LOST - MAX RETRIES REACHED', type: 'error' }
    }));
  });

  const unsubGprResult = engineIPC.on('gpr_result', (msg: EngineMessage) => {
    const data = msg.data as {
      bssid: string; lat: number; lon: number; confidence: number; peak_rssi: number;
      error_radius_m?: number; nearest_measurement_m?: number; notes?: string[];
    };

    // Persist through the DB layer. The inline UPDATE this replaced wrote to
    // access_points.latitude/longitude, which did not exist until migration
    // 008 — SQLite rejected every write and .catch(console.error) hid it, so
    // no GPR result was ever saved. Failures are surfaced now.
    saveApLocation(data.bssid, data.lat, data.lon, 'gpr', {
      confidence: data.confidence,
      errorRadiusM: data.error_radius_m ?? null,
      notes: data.notes ?? [],
    })
      .then(() => showEngineToast(
        `GPR: ${data.bssid} mapped, +/-${Math.round(data.error_radius_m ?? 0)} m (${data.confidence.toFixed(0)}%)`,
        'success'))
      .catch(err => {
        console.error('[DB] saveApLocation error:', err);
        showEngineToast(`GPR computed but could not be saved: ${err}`, 'error');
      });
  });

  const unsubGprError = engineIPC.on('gpr_error', (msg: EngineMessage) => {
    const data = msg.data as { bssid?: string; message: string };
    window.dispatchEvent(new CustomEvent('lockon:toast', {
      detail: { message: `GPR ERROR: ${data.message}`, type: 'error' }
    }));
  });

  /**
   * WPS scan results, persisted as measurements.
   *
   * Until now this listener existed but could never fire, because nothing sent
   * `scan_wps`. Meanwhile `access_points.wps_enabled` defaulted to 0 and the
   * report read that default as an observation — printing "no access point
   * advertised WPS in its beacon" about a beacon parse that never ran.
   *
   * Only access points whose beacon was actually parsed are written, and each
   * gets `wps_scanned_at` so a measured "no WPS" can be told apart from an
   * access point the scan never covered (migration 013).
   */
  const unsubWpsScanComplete = engineIPC.on('wps_scan_complete', (msg: EngineMessage) => {
    const data = msg.data as {
      total_aps: number; wps_enabled: number; wps_locked: number;
      results: Array<{ bssid: string; wps_enabled: boolean; wps_locked: boolean; wps_version?: string }>;
      inconclusive?: boolean; frames_seen?: number; beacons_seen?: number;
      reason?: string; caveat?: string;
    };

    if (data.inconclusive) {
      // The radio handed us nothing. This says nothing about the networks
      // around us, so nothing is written and the toast says why.
      showEngineToast(
        `WPS scan inconclusive: ${data.reason ?? 'no beacon was captured'} Nothing was recorded — this is not evidence that WPS is disabled.`,
        'error', 10000
      );
      return;
    }

    showEngineToast(
      `WPS scan: ${data.wps_enabled} advertising WPS (${data.wps_locked} rate-limited) out of ${data.total_aps} access point(s) measured.`,
      data.wps_enabled > 0 ? 'warning' : 'info', 7000
    );

    const measuredAt = new Date().toISOString();
    // The live store feeds the archive, the table feeds a replayed mission.
    // Both have to carry the measurement or the report loses it on one path.
    useMissionStore.getState().applyWpsMeasurements(
      (data.results || []).map(r => ({
        bssid: r.bssid,
        wps_enabled: !!r.wps_enabled,
        wps_locked: !!r.wps_locked,
        wps_version: r.wps_version ?? null,
      })),
      measuredAt
    );
    recordWpsMeasurements(
      (data.results || []).map(r => ({
        bssid: r.bssid,
        wps_enabled: !!r.wps_enabled,
        wps_locked: !!r.wps_locked,
        wps_version: r.wps_version ?? null,
      })),
      measuredAt
    ).catch(err => console.error('[DB] recordWpsMeasurements error:', err));

    window.dispatchEvent(new CustomEvent('lockon:wps_results', { detail: data.results }));
  });

  const unsubWpsError = engineIPC.on('wps_error', (msg: EngineMessage) => {
    const data = msg.data as { message: string };
    window.dispatchEvent(new CustomEvent('lockon:toast', {
      detail: { message: `WPS ERROR: ${data.message}`, type: 'error' }
    }));
  });

  const unsubHashcatExported = engineIPC.on('hashcat_exported', (msg: EngineMessage) => {
    const data = msg.data as { output_path: string; hash_count: number };
    window.dispatchEvent(new CustomEvent('lockon:toast', {
      detail: { message: `HASHCAT EXPORT: ${data.hash_count} hash(es) → ${data.output_path}`, type: 'success' }
    }));
    window.dispatchEvent(new CustomEvent('lockon:hashcat_exported', { detail: data }));
  });

  const unsubHashcatError = engineIPC.on('hashcat_export_error', (msg: EngineMessage) => {
    const data = msg.data as { message: string };
    window.dispatchEvent(new CustomEvent('lockon:toast', {
      detail: { message: `HASHCAT ERROR: ${data.message}`, type: 'error' }
    }));
  });

  const unsubPmkidCaptured = engineIPC.on('pmkid_captured', (msg: EngineMessage) => {
    const data = msg.data as { bssid: string; ssid: string; pmkid: string; output_file: string };
    window.dispatchEvent(new CustomEvent('lockon:toast', {
      detail: { message: `⚡ PMKID CAPTURED: ${data.ssid || data.bssid} → ${data.output_file}`, type: 'success' }
    }));
    window.dispatchEvent(new CustomEvent('lockon:pmkid_captured', { detail: data }));
  });

  const unsubPmkidTimeout = engineIPC.on('pmkid_timeout', (msg: EngineMessage) => {
    const data = msg.data as { bssid: string; message: string };
    window.dispatchEvent(new CustomEvent('lockon:toast', {
      detail: { message: `PMKID TIMEOUT: ${data.message}`, type: 'warning' }
    }));
  });

  const unsubPmkidError = engineIPC.on('pmkid_error', (msg: EngineMessage) => {
    const data = msg.data as { message: string };
    window.dispatchEvent(new CustomEvent('lockon:toast', {
      detail: { message: `PMKID ERROR: ${data.message}`, type: 'error' }
    }));
  });

  const unsubAutoAttackStarted = engineIPC.on('auto_attack_started', (msg: EngineMessage) => {
    const data = msg.data as { target_count: number };
    window.dispatchEvent(new CustomEvent('lockon:toast', {
      detail: { message: `⚡ AUTO-ATTACK: Engaging ${data.target_count} target(s)...`, type: 'warning' }
    }));
  });

  const unsubAutoAttackComplete = engineIPC.on('auto_attack_complete', (msg: EngineMessage) => {
    const data = msg.data as { targets_attempted: number; total_attacked: number };
    window.dispatchEvent(new CustomEvent('lockon:toast', {
      detail: { message: `AUTO-ATTACK COMPLETE: ${data.targets_attempted} attempted / ${data.total_attacked} total`, type: 'success' }
    }));
  });

  const unsubAutoAttackError = engineIPC.on('auto_attack_error', (msg: EngineMessage) => {
    const data = msg.data as { message: string };
    showEngineToast(`AUTO-ATTACK ERROR: ${data.message}`, 'error');
  });
  // ---------------------------

  // --- Engagement scope & audit trail ---
  // The engine refuses any offensive command against a target outside the
  // active engagement. A refusal must be loud: silently doing nothing is how
  // an operator concludes the tool is broken and disables the safety.
  const unsubScopeDenied = engineIPC.on('scope_denied', (msg: EngineMessage) => {
    const data = msg.data as unknown as ScopeDenied;
    showEngineToast(
      `OUT OF SCOPE — ${data.command}${data.target ? ` on ${data.target}` : ''}: ${data.reason}`,
      'warning',
      8000
    );
  });

  const unsubAuditEvent = engineIPC.on('audit_event', (msg: EngineMessage) => {
    // The engine does not write to SQLite itself — the Tauri SQL plugin is the
    // single writer — so it emits audit rows and we persist them here.
    recordAuditEvent(msg.data as any)
      .catch(err => console.error('[DB] recordAuditEvent error:', err));
  });

  const applyScope = (msg: EngineMessage) => {
    useEngineStore.getState().setScope(msg.data as unknown as ScopeStatus);
  };
  const unsubScopeStatus = engineIPC.on('scope_status', applyScope);
  const unsubScopeUpdated = engineIPC.on('scope_updated', applyScope);

  const unsubScopeWarning = engineIPC.on('scope_warning', (msg: EngineMessage) => {
    showEngineToast(`SCOPE: ${(msg.data as { message: string }).message}`, 'warning');
  });
  // --------------------------------------

  // --- Terminal events that used to strand the UI ---
  const unsubIntrusionError = engineIPC.on('intrusion_error', (msg: EngineMessage) => {
    const data = msg.data as { message: string };
    showEngineToast(`INTRUSION: ${data.message}`, 'error');
    useIntrusionStore.getState().stopIntrusion();
  });

  const unsubScanError = engineIPC.on('scan_error', (msg: EngineMessage) => {
    const data = msg.data as { message: string };
    showEngineToast(`SCAN: ${data.message}`, 'error');
  });

  const unsubGpsError = engineIPC.on('gps_error', (msg: EngineMessage) => {
    const data = msg.data as { message: string };
    showEngineToast(`GPS: ${data.message}`, 'warning');
    useEngineStore.getState().setGpsLocked(false);
  });

  const unsubScanStopped = engineIPC.on('scan_stopped', (msg: EngineMessage) => {
    const data = msg.data as { total_aps?: number; aborted?: boolean };
    useEngineStore.getState().setScanning(false);
    // The scenario belongs to the survey that just ended; keeping it would
    // show a rehearsal's details next to the next live drive.
    useEngineStore.setState({ simulation: null });
    if (data.aborted) {
      showEngineToast('Scan stopped unexpectedly — check the engine log.', 'warning');
    }
  });

  /**
   * A simulated survey announces its scenario up front, so the operator is
   * told what they are rehearsing rather than inferring it from the map.
   */
  const unsubSimulation = engineIPC.on('simulation_started', (msg: EngineMessage) => {
    const scenario = msg.data as unknown as SimulationScenario;
    useEngineStore.setState({ simulation: scenario });
    showEngineToast(
      `Simulated survey: ${scenario.ap_count} access points along a ${Math.round(scenario.route_length_m)} m route. `
      + 'Nothing recorded from it is field evidence.',
      'warning', 9000
    );
  });

  const unsubSpawnFailed = engineIPC.on('spawn_failed', (msg: EngineMessage) => {
    const data = msg.data as { message: string };
    setConnError(`Engine failed to start: ${data.message}`);
  });

  // Capture/PMKID/MITM cancellation and cleanup outcomes. The MITM one matters
  // most: it reports whether the target's ARP table was actually restored.
  const unsubCaptureAborted = engineIPC.on('capture_aborted', (msg: EngineMessage) => {
    const data = msg.data as { bssid?: string; message: string };
    showEngineToast(`CAPTURE CANCELLED${data.bssid ? ` [${data.bssid}]` : ''}: ${data.message}`, 'info');
  });

  const unsubPmkidAborted = engineIPC.on('pmkid_aborted', (msg: EngineMessage) => {
    const data = msg.data as { bssid?: string; message: string };
    showEngineToast(`PMKID CANCELLED${data.bssid ? ` [${data.bssid}]` : ''}: ${data.message}`, 'info');
  });

  // --- Evidence, clients, capability ---
  /**
   * Captures are now written to a fixed evidence directory and hashed at the
   * moment of writing. Registering them here is what turns a loose .pcap into
   * an artifact a finding can cite and a holder can verify.
   */
  const unsubEvidence = engineIPC.on('evidence_recorded', (msg: EngineMessage) => {
    const data = msg.data as any;
    const mission = useMissionStore.getState().activeMission;
    recordEvidence({ ...data, mission_id: data.mission_id ?? mission?.id ?? null })
      .catch(err => console.error('[DB] recordEvidence error:', err));
    if (data.error) {
      showEngineToast(`Evidence saved but not hashed: ${data.error}`, 'warning');
    }
  });

  const unsubClient = engineIPC.on('client_observed', (msg: EngineMessage) => {
    const mission = useMissionStore.getState().activeMission;
    recordClient(msg.data as any, mission?.id ?? null)
      .catch(err => console.error('[DB] recordClient error:', err));
  });

  /**
   * Hardware capability. Held in the store so the 802.11 controls can be
   * disabled rather than letting the operator start a capture that cannot
   * succeed — a null result there is indistinguishable from "the target is
   * secure", which is the one way this tool can produce a confidently wrong
   * report.
   */
  const unsubCapabilities = engineIPC.on('capabilities', (msg: EngineMessage) => {
    const caps = msg.data as any;
    useEngineStore.setState({ capabilities: caps });
    const blocked: string[] = caps?.unavailable_features || [];
    if (blocked.length) {
      showEngineToast(
        `${blocked.length} 802.11 feature(s) unavailable on this hardware — see Settings for what and why.`,
        'warning', 9000
      );
    }
  });

  /*
    A probe that did not finish is not a probe that found the hardware ready.

    The engine's probe thread had no handler of its own, so a raise inside it
    killed the thread and no `capabilities` event was ever emitted. The gates
    then kept whatever they held before, which on first run is permissive —
    exactly the wrong direction for a check whose purpose is to stop an operator
    running a capture that cannot succeed and reading the empty result as
    "the target is secure".
  */
  const unsubCapabilitiesError = engineIPC.on('capabilities_error', (msg: EngineMessage) => {
    const d = msg.data as any;
    useEngineStore.setState({ capabilities: null });
    showEngineToast(
      String(d?.message || 'The hardware capability probe failed.'),
      'error', 12000
    );
  });

  /**
   * Which network this machine is on. Refreshed when the engine connects and
   * whenever a real scan starts, so the feed can show an IP for the one
   * access point that can honestly carry one.
   */
  const unsubNetContext = engineIPC.on('net_context', (msg: EngineMessage) => {
    useEngineStore.setState({ netContext: msg.data as unknown as NetContext });
  });

  const unsubCveInfo = engineIPC.on('cve_info', (msg: EngineMessage) => {
    const info = msg.data as any;
    useEngineStore.setState({ cveInfo: info });
    if (info?.stale) {
      const age = info.age_days != null ? `${info.age_days} days old` : 'of unknown age';
      showEngineToast(
        `CVE data is ${age}. Findings reflect that vintage — update it in Settings before relying on them.`,
        'warning', 9000
      );
    }
  });

  const unsubEngineError = engineIPC.on('engine_error', (msg: EngineMessage) => {
    const data = msg.data as any;
    showEngineToast(
      `Engine fault: ${data.message}${data.log_path ? ' (logged)' : ''}`, 'error', 10000
    );
  });
  // -------------------------------------

  const unsubMitmCleanupFailed = engineIPC.on('mitm_cleanup_failed', (msg: EngineMessage) => {
    const data = msg.data as { target: string; message: string };
    showEngineToast(
      `⚠ ARP NOT RESTORED on ${data.target} — the target's network state is still altered. ${data.message}`,
      'error',
      15000
    );
  });
  // --------------------------------------------------

  // Poll for status
  const interval = setInterval(() => {
    if (engineIPC.connected) {
      engineIPC.send('ping').catch(() => {});
      engineIPC.send('get_status').catch(() => {});
      
      // Ensure wordlists are fetched if they were missed during startup
      if (useEngineStore.getState().wordlists.length === 0) {
        engineIPC.send('get_wordlists').catch(() => {});
      }
    }
  }, 2000);

  return () => {
    clearInterval(interval);
    unsubAP();
    unsubAPBatch();
    unsubGPS();
    unsubStatus();
    unsubInterfaces();
    unsubPurged();
    unsubIntrusionProgress();
    unsubIntrusionSubnets();
    unsubIntrusionScope();
    unsubIntrusionDiff();
    unsubIntrusionHost();
    unsubVulnScanPersist();
    unsubSmbPersist();
    unsubDirbusterFinding();
    unsubDirbusterDone();
    unsubIntrusionComplete();
    unsubStrikeStarted();
    unsubStrikeProgress();
    unsubStrikeStopped();
    unsubStrikeError();
    unsubWordlists();
    unsubReady();
    unsubPing();
    unsubDisc();
    unsubError();
    unsubReconnecting();
    unsubReconnected();
    unsubReconnectFailed();
    unsubGprResult();
    unsubGprError();
    unsubWpsScanComplete();
    unsubWpsError();
    unsubHashcatExported();
    unsubHashcatError();
    unsubPmkidCaptured();
    unsubPmkidTimeout();
    unsubPmkidError();
    unsubAutoAttackStarted();
    unsubAutoAttackComplete();
    unsubAutoAttackError();
    unsubWordlistError();
    unsubScopeDenied();
    unsubAuditEvent();
    unsubScopeStatus();
    unsubScopeUpdated();
    unsubScopeWarning();
    unsubIntrusionError();
    unsubScanError();
    unsubGpsError();
    unsubScanStopped();
    unsubSpawnFailed();
    unsubCaptureAborted();
    unsubPmkidAborted();
    unsubMitmCleanupFailed();
    unsubEvidence();
    unsubClient();
    unsubCapabilities();
    unsubCapabilitiesError();
    unsubCveInfo();
    unsubNetContext();
    unsubSimulation();
    unsubEngineError();
    // The sidecar is deliberately NOT shut down here. It is an app-lifetime
    // singleton, and React's development double-mount runs this cleanup
    // between the two mounts — killing the engine there is what left the app
    // showing "Engine: OFFLINE" with no way back. Shutdown is handled on
    // window unload instead; see below.
  };
}
