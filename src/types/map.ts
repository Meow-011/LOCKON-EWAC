/** Map-related types */

export interface MapMarker {
  id: string;
  latitude: number;
  longitude: number;
  ssid?: string;
  bssid: string;
  rssi: number;
  riskLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  encryption: string;
}

export interface MapViewState {
  center: [number, number]; // [lng, lat]
  zoom: number;
  bearing: number;
  pitch: number;
}
