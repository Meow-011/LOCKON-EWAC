import { KpiCard } from './KpiCard';
import { useMissionStore } from '../../stores/missionStore';
import { useEngineStore } from '../../stores/engineStore';

export function KpiGrid() {
  const totalAPs = useMissionStore(s => s.totalAPs);
  const highRiskCount = useMissionStore(s => s.highRiskCount);
  const openNetworks = useMissionStore(s => s.openNetworks);
  const gpsLocked = useEngineStore(s => s.gpsLocked);
  const satellites = useEngineStore(s => s.satellites);
  const hdop = useEngineStore(s => s.hdop);

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      <KpiCard
        label="APs Discovered"
        value={totalAPs}
        accentColor="neon"
        icon={
          <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/>
            <circle cx="12" cy="20" r="1"/>
          </svg>
        }
      />
      <KpiCard
        label="High Risk"
        value={highRiskCount}
        accentColor="red"
        icon={
          <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
        }
      />
      <KpiCard
        label="Open Networks"
        value={openNetworks}
        accentColor="orange"
        icon={
          <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 9.9-1"/>
          </svg>
        }
      />

      {/* The real satellite count from the NMEA fix. This tile used to render a
          hardcoded 8 whenever a fix existed, which put a fabricated number on
          the dashboard next to three measured ones. */}
      <KpiCard
        label={hdop != null && hdop > 0 ? `GPS Satellites · HDOP ${hdop.toFixed(1)}` : 'GPS Satellites'}
        value={satellites ?? 0}
        accentColor={gpsLocked ? 'green' : 'blue'}
        suffix={satellites == null ? '—' : 'sat'}
        icon={
          <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M20 10c0 4.993-5.539 10.193-7.399 11.799a1 1 0 0 1-1.202 0C9.539 20.193 4 14.993 4 10a8 8 0 0 1 16 0"/>
            <circle cx="12" cy="10" r="3"/>
          </svg>
        }
      />
    </div>
  );
}
