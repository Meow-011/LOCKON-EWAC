/** LOCKON EWAC — STRIKE State Management */
import { create } from 'zustand';

export interface ActiveStrike {
  targetMAC: string;
  gatewayBSSID: string;
  startedAt: number;
  packetsSent: number;
  status: 'ACTIVE' | 'COMPLETED' | 'CEASED' | 'ERROR';
}

interface StrikeState {
  activeStrikes: Record<string, ActiveStrike>;

  // Actions
  startStrike: (targetMAC: string, gatewayBSSID: string) => void;
  updateStrike: (targetMAC: string, updates: Partial<ActiveStrike>) => void;
  stopStrike: (targetMAC: string) => void;
  clearStrike: (targetMAC: string) => void;
}

export const useStrikeStore = create<StrikeState>((set) => ({
  activeStrikes: {},

  startStrike: (targetMAC, gatewayBSSID) => set((state) => ({
    activeStrikes: {
      ...state.activeStrikes,
      [targetMAC]: {
        targetMAC,
        gatewayBSSID,
        startedAt: Date.now(),
        packetsSent: 0,
        status: 'ACTIVE',
      }
    }
  })),

  updateStrike: (targetMAC, updates) => set((state) => {
    const existing = state.activeStrikes[targetMAC];
    if (!existing) return state;
    return {
      activeStrikes: {
        ...state.activeStrikes,
        [targetMAC]: { ...existing, ...updates }
      }
    };
  }),

  stopStrike: (targetMAC) => set((state) => {
    const existing = state.activeStrikes[targetMAC];
    if (!existing) return state;
    return {
      activeStrikes: {
        ...state.activeStrikes,
        [targetMAC]: { ...existing, status: 'CEASED' }
      }
    };
  }),

  clearStrike: (targetMAC) => set((state) => {
    const { [targetMAC]: _, ...rest } = state.activeStrikes;
    return { activeStrikes: rest };
  }),
}));
