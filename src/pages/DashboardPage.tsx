/** DashboardPage — Main tactical dashboard view */
import { KpiGrid } from '../components/dashboard/KpiGrid';
import { MapView } from '../components/dashboard/MapView';
import { ScanFeed } from '../components/dashboard/ScanFeed';
import { TargetDrawer } from '../components/dashboard/TargetDrawer';
import { MissionArchiveDrawer } from '../components/dashboard/MissionArchiveDrawer';
import { useUIStore } from '../stores/uiStore';

export function DashboardPage() {
  const dashboardFocus = useUIStore(s => s.dashboardFocus);
  const focused = dashboardFocus !== null;

  return (
    <div className="flex flex-col gap-4 h-full min-h-0 relative overflow-hidden">
      {/* Main Content — Map + Feed. Either panel can take the whole area. */}
      <div className={`flex-1 grid grid-cols-1 ${focused ? 'lg:grid-cols-1' : 'lg:grid-cols-3'} gap-4 min-h-0 transition-all duration-500`}>
        {/* Map */}
        {dashboardFocus !== 'feed' && (
          <div className={`${focused ? 'lg:col-span-1' : 'lg:col-span-2'} min-h-[300px] h-full overflow-hidden rounded-xl border border-space-500/20 relative transition-all duration-500`}>
            <MapView />
          </div>
        )}

        {/* Scan Feed */}
        {dashboardFocus !== 'map' && (
          <div className="h-full min-h-0 animate-in fade-in slide-in-from-right-4 duration-500">
            <ScanFeed />
          </div>
        )}
      </div>

      {/* KPI Cards Row — hidden while either panel is expanded. */}
      {!focused && (
        <div className="flex-none z-10 relative animate-in fade-in slide-in-from-bottom-4 duration-500">
          <KpiGrid />
        </div>
      )}

      {/* Overlays */}
      <TargetDrawer />
      <MissionArchiveDrawer />
    </div>
  );
}
