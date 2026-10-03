import { create } from 'zustand';
import { saveReport, getAllReports, removeReport, updateReportName, clearAllReports } from '../lib/reportDB';

export interface Report {
  id: string;
  type: 'INTRUSION' | 'WIFI_WARDRIVE' | 'WIFI_SCAN';
  targetName: string;
  timestamp: number;
  /**
   * True when any of the underlying data came from the hardware simulator.
   * Every view and the exported PDF must say so — a simulated sweep that reads
   * as field evidence is the worst failure this tool can have.
   */
  simulated?: boolean;
  /**
   * Where this archive came from. `'LOCAL'` means this rig produced it;
   * `'IMPORTED'` means it arrived as a file.
   *
   * The distinction is a provenance claim the PDF cover prints, and it went
   * unmade for a long time: `markImported` existed with no callers, so every
   * imported archive kept the schema default of `'LOCAL'` and the cover
   * asserted "LIVE HARDWARE [FIELD DATA]" for a hand-written JSON file. That
   * is a way around the `simulated` chain entirely, through the one door that
   * takes input from outside.
   */
  origin?: string;
  summary: {
    totalNodes?: number;
    criticalNodes?: number;
    totalAPs?: number;
    vulnerableAPs?: number;
  };
  rawData: any;
}

interface ReportState {
  reports: Report[];
  
  // Actions
  loadReports: () => Promise<void>;
  addReport: (report: Report) => Promise<void>;
  deleteReport: (id: string) => Promise<void>;
  renameReport: (id: string, newName: string) => Promise<void>;
  clearAll: () => Promise<void>;
}

export const useReportStore = create<ReportState>((set) => ({
  reports: [],
  
  loadReports: async () => {
    try {
      const data = await getAllReports();
      set({ reports: data });
    } catch (e) {
      console.error("Failed to load reports from DB", e);
    }
  },

  // Rejects rather than swallowing: a duplicate id (re-importing the same
  // archive) used to fail the INSERT and still show a success toast, so the
  // operator believed a report had been stored when nothing had.
  addReport: async (report) => {
    await saveReport(report);
    set((state) => ({
      reports: [report, ...state.reports]
    }));
  },
  
  deleteReport: async (id) => {
    try {
      await removeReport(id);
      set((state) => ({ 
        reports: state.reports.filter(r => r.id !== id) 
      }));
    } catch (e) {
      console.error("Failed to delete report", e);
    }
  },

  renameReport: async (id, newName) => {
    try {
      await updateReportName(id, newName);
      set((state) => ({
        reports: state.reports.map(r => r.id === id ? { ...r, targetName: newName } : r)
      }));
    } catch (e) {
      console.error("Failed to rename report", e);
    }
  },
  
  clearAll: async () => {
    try {
      await clearAllReports();
      set({ reports: [] });
    } catch (e) {
      console.error("Failed to clear all reports", e);
    }
  }
}));
