/**
 * LOCKON EWAC — one set of signal-strength bands, for every surface.
 *
 * Five places banded RSSI independently and no two agreed:
 *
 *   | surface                  | thresholds (dBm)      | bands | palette      |
 *   |--------------------------|-----------------------|-------|--------------|
 *   | `ScanFeed`               | -50 / -60 / -70 / -80 | 5     | `signal-*`   |
 *   | `ReportsPage` table      | -60 / -70 / -80 / -90 | 5     | `signal-*`   |
 *   | `TargetDrawer` bar       | -60 / -80             | 3     | `signal-*`   |
 *   | `LocalizationPreview`    | -55 / -70 / -82       | 4     | raw hex      |
 *   | `ReportsPage` map popup  | -70                   | 2     | **`risk-*`** |
 *
 * The first two matter most: they are offset by a whole band, so an access point
 * at -65 dBm was "fair" in the live feed and "good" in the archive table built
 * from the same reading. An operator comparing the two screens is looking at one
 * measurement described two ways.
 *
 * The last one is a category error rather than a disagreement. Signal strength
 * was drawn in the **risk** palette, so -75 dBm came out amber — the colour of a
 * warning — when it only means the access point is far away. The same popup
 * prints the actual severity two elements later, in the same palette, meaning
 * something else entirely.
 *
 * The thresholds here are `ScanFeed`'s, because they match the ordinary Wi-Fi
 * convention (-50 excellent, -60 very good, -70 usable, -80 weak, below that not
 * worth associating with) and because that is the reading an operator watches
 * while driving. The archive table therefore becomes one band stricter than it
 * was, which is the correction, not a regression.
 *
 * **These bands describe reception, not risk.** A weak access point is not a
 * safer one — it is one that was further from the car. Nothing here may be
 * wired to the risk palette; `severityStyle.ts` owns that, and the two must stay
 * visibly separate so a reader can tell which question a colour answers.
 */

export interface SignalBand {
  /** Inclusive lower bound in dBm. */
  minDbm: number;
  key: 'STRONG' | 'GOOD' | 'FAIR' | 'WEAK' | 'DEAD';
  /** Wording for a tooltip or a legend. */
  label: string;
  /** Text colour class. */
  text: string;
  /** Solid fill, for a bar or a dot. */
  bar: string;
  /** Hex, for an SVG or canvas that cannot take a class. */
  hex: string;
  /** Filled bars out of four, for the bar-strength indicator. */
  bars: number;
}

/*
  Worst-last, so `find` returns the first band the reading clears.

  Every class is written out in full and never assembled from the band key.
  Tailwind finds classes by scanning source for complete strings; a class built
  at run time puts nothing in the stylesheet and renders with no colour at all.
  That already happened once in this project, in `severityStyle.ts`, and
  `npm run check:severity-css` exists because of it.
*/
export const SIGNAL_BANDS: SignalBand[] = [
  { minDbm: -50, key: 'STRONG', label: 'Strong', text: 'text-signal-strong', bar: 'bg-signal-strong', hex: '#22c55e', bars: 4 },
  { minDbm: -60, key: 'GOOD', label: 'Good', text: 'text-signal-good', bar: 'bg-signal-good', hex: '#84cc16', bars: 3 },
  { minDbm: -70, key: 'FAIR', label: 'Fair', text: 'text-signal-fair', bar: 'bg-signal-fair', hex: '#eab308', bars: 2 },
  { minDbm: -80, key: 'WEAK', label: 'Weak', text: 'text-signal-weak', bar: 'bg-signal-weak', hex: '#f97316', bars: 1 },
  { minDbm: -Infinity, key: 'DEAD', label: 'Barely detectable', text: 'text-signal-dead', bar: 'bg-signal-dead', hex: '#ef4444', bars: 0 },
];

/**
 * Styling for a reading that does not exist.
 *
 * `null` here is not the bottom of the scale. `scan_logs.rssi` used to be
 * written as `ap.rssi ?? -90`, which stored an invented reading indistinguishable
 * from an observed -90 and then fed the localizer; that was fixed, and the
 * display side has to hold the same line. A sighting with no signal reading is
 * shown as unmeasured, never as the weakest band.
 */
export const SIGNAL_UNMEASURED = {
  label: 'Not reported',
  text: 'text-gray-500',
  bar: 'bg-space-600',
  hex: '#71717a',
  bars: 0,
} as const;

/** The band a reading falls in, or `null` when there is no reading. */
export function signalBand(rssi: unknown): SignalBand | null {
  if (typeof rssi !== 'number' || !Number.isFinite(rssi)) return null;
  return SIGNAL_BANDS.find(b => rssi >= b.minDbm) ?? SIGNAL_BANDS[SIGNAL_BANDS.length - 1];
}

export function signalTextClass(rssi: unknown): string {
  return signalBand(rssi)?.text ?? SIGNAL_UNMEASURED.text;
}

export function signalBarClass(rssi: unknown): string {
  return signalBand(rssi)?.bar ?? SIGNAL_UNMEASURED.bar;
}

export function signalHex(rssi: unknown): string {
  return signalBand(rssi)?.hex ?? SIGNAL_UNMEASURED.hex;
}

/** Filled bars out of four. Zero for both the weakest band and no reading. */
export function signalBars(rssi: unknown): number {
  return signalBand(rssi)?.bars ?? SIGNAL_UNMEASURED.bars;
}

/**
 * Words for a reading, for a tooltip.
 *
 * States the number and the band together: the band alone invites the reader to
 * treat "Weak" as a property of the network rather than of where it was measured
 * from.
 */
export function signalLabel(rssi: unknown): string {
  const band = signalBand(rssi);
  if (!band) {
    return 'No signal reading was recorded for this sighting. '
      + 'That is not a reading of zero, and not a weak signal.';
  }
  return `${rssi} dBm — ${band.label} reception at the point it was measured from. `
    + 'Signal strength describes distance and obstruction, not how secure the network is.';
}
