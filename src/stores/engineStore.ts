/** LOCKON EWAC — Engine Connection State */
import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { metresBetween, gpsStepFloorM } from '../lib/localization';
import type { ComPort, EngineStatus, ScopeStatus, EngineCapabilities, CveInfo, SimulationScenario, NetContext } from '../types/engine';

/**
 * The sidecar's self-description, from its `ready` event.
 *
 * Every field can be null, and none of them is ever guessed: an unknown build
 * is something the operator needs to be told, not a blank to fill in.
 */
export interface EngineBuild {
  version: string;
  /** True for the compiled sidecar, false when the engine runs from source. */
  frozen: boolean;
  /** When the .exe was produced, or (source run) when the newest .py changed. */
  built_at: string | null;
  git_describe: string | null;
  python: string;
  bundle_dir: string | null;
}

interface EngineConfig {
  comPort: string;
  baudRate: number;
  emulateHardware: boolean;
  interfaceName: string | null;
  scanInterval: number;
  locationMethod: 'weighted_centroid' | 'trilateration' | 'bayesian_grid';
  mapStyle: 'DARK' | 'SATELLITE';
  enable3DBuildings: boolean;
  enableHeatmap: boolean;
  enableAutoAttack: boolean;
}

interface EngineState {
  connected: boolean;
  scanning: boolean;
  gpsLocked: boolean;
  wifiReady: boolean;
  /*
    The raw fix, exactly as the receiver reported it.

    Used by anything that is *about* the fix -- the satellite count, HDOP, the
    quality readout. Not used to draw the vehicle, for the reason below.
  */
  latitude: number | null;
  longitude: number | null;
  heading: number | null;

  /*
    The position the interface is willing to call the operator's position.

    A consumer receiver scatters a few metres while standing still, and the
    vehicle marker was drawn straight from the raw fix -- so parked, the car
    crawled around the map, span on the spot because course-over-ground is
    essentially random at zero speed, and with auto-follow on it dragged the
    whole map with it. The track already refused to record that as travel; the
    marker had no such rule, and the troubleshooting note claiming this was
    fixed in v1.0.0 was describing the track.

    This moves only once a fix is GPS_STEP_M from the last accepted one, which
    is the same floor the track uses and for the same reason: below it, this is
    noise. The cost is that the marker can be up to that far behind the raw fix,
    which is the right trade for a 5 m threshold on a map whose job is to say
    which building you are beside.
  */
  acceptedLatitude: number | null;
  acceptedLongitude: number | null;
  /*
    Held while stationary rather than taken from every fix.

    Course over ground is meaningless at zero speed -- the receiver reports the
    direction of its own noise -- so a parked vehicle icon span continuously. The
    last heading from real movement is the better answer: it is where the vehicle
    was last known to be pointing, which is what the icon is claiming.
  */
  acceptedHeading: number | null;
  speed: number | null;
  /** Real satellite count from the GPS fix. The KPI tile used to hardcode 8. */
  satellites: number | null;
  hdop: number | null;
  engineVersion: string | null;
  /**
   * What the running sidecar actually is.
   *
   * `engineVersion` was declared, initialised to null and **never written**, and
   * the engine itself reported a hardcoded `"0.1.0"` that has never changed. So
   * a sidecar compiled days earlier was indistinguishable from a fresh one, and
   * a decoding bug already fixed in the source went on being reported from the
   * field for two days: the code was right, the `.exe` was old, and nothing
   * anywhere said so.
   */
  engineBuild: EngineBuild | null;
  wifiInterfaces: string[];
  comPorts: ComPort[];
  /** `origin` says whether a list ships with the build (read-only) or was uploaded. */
  wordlists: {name: string, size: number, origin?: 'bundled' | 'user'}[];
  /** The engine's own view of the engagement scope, so the UI shows what is
   *  actually in force rather than what the database says it should be. */
  scope: ScopeStatus | null;
  /** What this hardware and privilege level can actually do (Npcap, monitor
   *  mode, elevation). The 802.11 controls gate on this, because a capture that
   *  cannot succeed returns a result indistinguishable from "target secure". */
  capabilities: EngineCapabilities | null;
  /** Provenance and age of the CVE data currently in force. */
  cveInfo: CveInfo | null;
  /**
   * The scenario a simulated survey is running, as the engine described it.
   *
   * Deliberately NOT written into an exported PDF: a report can be generated
   * from an archived mission long after the engine forgot which scenario ran,
   * and a stale scenario name in an evidence document is worse than none. The
   * PDF's load-bearing claim — that the data came from the simulator and is not
   * field-verified — is stored per mission and stands on its own.
   */
  simulation: SimulationScenario | null;
  /**
   * The network this machine is associated with, if any. The only source
   * of an IP that can honestly be attached to an access point.
   */
  netContext: NetContext | null;
  config: EngineConfig;

  // Actions
  setConnected: (v: boolean) => void;
  setScanning: (v: boolean) => void;
  setGpsLocked: (v: boolean) => void;
  setWifiReady: (v: boolean) => void;
  setConfig: (config: Partial<EngineConfig>) => void;
  updateStatus: (status: Partial<EngineStatus>) => void;
  setGpsFix: (fix: { latitude: number; longitude: number; heading?: number | null; speed?: number | null; satellites?: number | null; hdop?: number | null }) => void;
  setEngineBuild: (version: string | null, build: EngineBuild | null) => void;
  setScope: (scope: ScopeStatus | null) => void;
  setWordlists: (lists: {name: string, size: number}[]) => void;
  reset: () => void;
}

const defaultConfig: EngineConfig = {
  comPort: 'COM3',
  baudRate: 9600,
  emulateHardware: false,
  interfaceName: null,
  scanInterval: 3.0,
  // The method the Settings card marks RECOMMENDED, and the most accurate
  // of the three on every route measured. The default used to be
  // weighted_centroid — which that same card describes as unable to leave
  // the surveyed path and "a sanity baseline, not a transmitter fix" — so
  // an operator who never opened Settings got exactly that in their report.
  locationMethod: 'bayesian_grid',
  mapStyle: 'DARK',
  enable3DBuildings: false,
  enableHeatmap: false,
  enableAutoAttack: false,
};

const initialState = {
  connected: false,
  scanning: false,
  gpsLocked: false,
  wifiReady: false,
  latitude: null as number | null,
  longitude: null as number | null,
  heading: null as number | null,
  acceptedLatitude: null as number | null,
  acceptedLongitude: null as number | null,
  acceptedHeading: null as number | null,
  speed: null as number | null,
  satellites: null as number | null,
  hdop: null as number | null,
  engineVersion: null as string | null,
  engineBuild: null as EngineBuild | null,
  wifiInterfaces: [] as string[],
  comPorts: [] as ComPort[],
  wordlists: [] as {name: string, size: number, origin?: 'bundled' | 'user'}[],
  scope: null as ScopeStatus | null,
  capabilities: null as EngineCapabilities | null,
  cveInfo: null as CveInfo | null,
  simulation: null as SimulationScenario | null,
  netContext: null as NetContext | null,
  config: defaultConfig,
};

export const useEngineStore = create<EngineState>()(
  persist(
    (set) => ({
      ...initialState,

      setConnected: (connected) => set({ connected }),
      setScanning: (scanning) => set({ scanning }),
      setGpsLocked: (gpsLocked) => set({ gpsLocked }),
      setWifiReady: (wifiReady) => set({ wifiReady }),
      setConfig: (c) => set((s) => ({ config: { ...s.config, ...c } })),
      // Takes an already-mapped EngineStatus. Callers must convert the engine's
      // snake_case `status` payload with mapEngineStatus first — spreading the
      // raw payload in here is what left `wifiReady` permanently false and wrote
      // junk `gps_locked`/`wifi_ready` keys into the store on every 2s poll.
      updateStatus: (status) => set(status),
      setGpsFix: ({ latitude, longitude, heading, speed, satellites, hdop }) => set((state) => {
        const prevLat = state.acceptedLatitude;
        const prevLon = state.acceptedLongitude;
        /*
          The floor is the one this fix can support, not a constant.

          A flat 5 m was used while the engine accepts anything up to HDOP 5.0,
          where the horizontal error is around 25 m at one sigma -- so a parked
          receiver on a mediocre fix produced jumps several times the floor and
          every one of them was accepted as travel. See `gpsStepFloorM`.
        */
        const floorM = gpsStepFloorM(hdop);
        // The first fix is always accepted: there is nothing to be noise around.
        const moved = prevLat == null || prevLon == null
          || metresBetween(prevLon, prevLat, longitude, latitude) >= floorM;

        return {
          latitude,
          longitude,
          heading: heading ?? null,
          speed: speed ?? null,
          satellites: satellites ?? null,
          hdop: hdop ?? null,
          gpsLocked: true,
          acceptedLatitude: moved ? latitude : prevLat,
          acceptedLongitude: moved ? longitude : prevLon,
          // Only a fix that moved carries a heading worth believing.
          acceptedHeading: moved ? (heading ?? state.acceptedHeading) : state.acceptedHeading,
        };
      }),
      setEngineBuild: (engineVersion, engineBuild) => set({ engineVersion, engineBuild }),
      setScope: (scope) => set({ scope }),
      setWordlists: (wordlists) => set({ wordlists }),
      reset: () => set(initialState),
    }),
    {
      name: 'lockon-engine-config',
      partialize: (state) => ({ config: state.config }),
    }
  )
);

