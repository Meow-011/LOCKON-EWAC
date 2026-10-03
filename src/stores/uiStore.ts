/** LOCKON EWAC — UI Preferences State */
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

/** `null` means the normal split view: map beside feed, KPI row below. */
export type DashboardFocus = 'map' | 'feed' | null;

interface UIState {
  sidebarCollapsed: boolean;
  /**
   * Which dashboard panel is expanded, if any.
   *
   * One value rather than a boolean per panel: two independent flags can both
   * be true, and the dashboard then hides the map *and* the feed and renders
   * an empty grid. Making it a single focus means that state cannot be
   * represented at all.
   */
  dashboardFocus: DashboardFocus;
  showScanFeed: boolean;
  selectedBssid: string | null;
  egoVehicle: string;
  showMissionArchive: boolean;
  capturedPcapFile: string | null;

  // Actions
  toggleSidebar: () => void;
  /** Expand a panel, or collapse it again if it is already the focused one. */
  toggleDashboardFocus: (panel: Exclude<DashboardFocus, null>) => void;
  clearDashboardFocus: () => void;
  toggleScanFeed: () => void;
  setSelectedBssid: (bssid: string | null) => void;
  setEgoVehicle: (vehicle: string) => void;
  setShowMissionArchive: (show: boolean) => void;
  setCapturedPcapFile: (file: string | null) => void;
}

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      dashboardFocus: null as DashboardFocus,
      showScanFeed: true,
      selectedBssid: null,
      egoVehicle: 'car1.svg',
      showMissionArchive: false,
      capturedPcapFile: null,

      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      toggleDashboardFocus: (panel) =>
        set((s) => ({ dashboardFocus: s.dashboardFocus === panel ? null : panel })),
      clearDashboardFocus: () => set({ dashboardFocus: null }),
      toggleScanFeed: () => set((s) => ({ showScanFeed: !s.showScanFeed })),
      setSelectedBssid: (bssid) => set({ selectedBssid: bssid }),
      setEgoVehicle: (vehicle) => set({ egoVehicle: vehicle }),
      setShowMissionArchive: (show) => set({ showMissionArchive: show }),
      setCapturedPcapFile: (file) => set({ capturedPcapFile: file }),
    }),
    {
      name: 'lockon-uistore-storage',
      partialize: (state) => ({ egoVehicle: state.egoVehicle }),
    }
  )
);
