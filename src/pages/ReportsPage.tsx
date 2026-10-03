import { useState, useRef, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useReportStore, type Report as IntelReport } from '../stores/reportStore';
import jsPDF from 'jspdf';
import 'maplibre-gl/dist/maplibre-gl.css';
import { reportExists, sha256Hex, recordExport, markImported } from '../lib/reportDB';
import { finiteNumber } from '../lib/numbers';
import { exportBaseName } from '../lib/report/exports/apRows';
import { buildCsv } from '../lib/report/exports/csv';
import { buildKml } from '../lib/report/exports/kml';
import { buildGeoJson } from '../lib/report/exports/geojson';
import {
  getActiveScope,
  exportAuditTrailCsv,
} from '../lib/scopeDB';
import {


  summarise,

  SEVERITY_ORDER,
  type Finding,
} from '../lib/riskEngine';
import {
  createBaseline,
  listBaselines,
  type RetestDelta,
} from '../lib/findingsDB';
import { assembleReportData } from '../lib/report/assemble';
import { kmz, assetBytes } from '../lib/report/kmz';
import kmlCircleIcon from '../assets/kml/placemark-circle.png';
import kmlDiamondIcon from '../assets/kml/mirror-diamond.png';
import { createLayout } from '../lib/report/layout';
import { severityClasses } from '../lib/severityStyle';
import { signalTextClass } from '../lib/signalStyle';
import { renderCoverPage } from '../lib/report/sections/coverPage';
import { renderIntegrityStamp } from '../lib/report/sections/integrityStamp';
import { renderTableOfContents } from '../lib/report/sections/tableOfContents';
import { renderPageFooter } from '../lib/report/sections/pageFooter';
import { renderRetestDelta } from '../lib/report/sections/retestDelta';
import { renderGlobalCredentials } from '../lib/report/sections/globalCredentials';
import { renderPerReportDetail } from '../lib/report/sections/perReportDetail';
import { renderWpsExposure } from '../lib/report/sections/wpsExposure';
import { renderRogueAssessment } from '../lib/report/sections/rogueAssessment';
import { renderPrioritisedFindings } from '../lib/report/sections/prioritisedFindings';
import { renderEvidenceRegister } from '../lib/report/sections/evidenceRegister';
import { renderSurveyCoverage } from '../lib/report/sections/surveyCoverage';
import { renderAuditTrail } from '../lib/report/sections/auditTrail';
import { renderEngagementScope } from '../lib/report/sections/engagementScope';
import { renderExecutiveSummary } from '../lib/report/sections/executiveSummary';
import { renderMethodAppendix } from '../lib/report/sections/methodAppendix';
import { renderPositionQuality } from '../lib/report/sections/positionQuality';
import { renderSweepCoverage } from '../lib/report/sections/sweepCoverage';
import { captureSurveyMap } from '../lib/report/surveyMap';
import { ExportMenu } from '../components/reports/ExportMenu';
import { ReportMap } from '../components/reports/ReportMap';
import {
  // Moved out of this file: reading an archive and wording its values is
  // report logic, not page logic. See src/lib/report/archive.ts.
  AMBIGUOUS_FLAG,



  apMirror,
  apsOf,
  dedupeApsByBssid,

  assessReport,
  credentialsOf,
  downloadBlob,
  errText,
  formatCoord,
  formatErrorRadius,
  formatLocationConfidence,
  formatMetres,
  hostsOf,
  isMirrorAmbiguous,
  isWirelessReport,
  locationMethodLabel,
  locationMethodNote,
  locationNotesOf,

  positionCaveats,
  rogueVerdictOf,
  stableSelectionId,



  worstBySubject,



  wpsObserved,

} from '../lib/report/archive';

export function ReportsPage() {
  const { reports, deleteReport, renameReport } = useReportStore();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [selectedReportId, setSelectedReportId] = useState<string | null>(() => {
    return reports.length > 0 ? reports[0].id : null;
  });

  const [isEditingTitle, setIsEditingTitle] = useState(false);
  const [editTitleValue, setEditTitleValue] = useState("");

  const [viewMode, setViewMode] = useState<'TABLE' | 'JSON' | 'MAP'>('TABLE');
  const [searchQuery, setSearchQuery] = useState('');
  const [sortConfig, setSortConfig] = useState<{ key: string, direction: 'asc' | 'desc' } | null>(null);
  const [focusBssid, setFocusBssid] = useState<string | null>(null);
  const [exportState, setExportState] = useState<'IDLE' | 'PDF_LOADING' | 'PDF_DONE' | 'CSV_DONE' | 'JSON_DONE'>('IDLE');
  const [notification, setNotification] = useState<{ show: boolean, message: string, type: 'success' | 'info' | 'error', onClickAction?: () => void }>({ show: false, message: '', type: 'info' });
  const [previewPdfUrl, setPreviewPdfUrl] = useState<string | null>(null);
  /** The blob URL of the most recent export, so the one before it can be released. */
  const lastPdfBlobUrlRef = useRef<string | null>(null);
  /** What the preview is showing right now, readable from a stale closure. */
  const previewUrlRef = useRef<string | null>(null);

  // Multi-select state
  const [isMultiSelect, setIsMultiSelect] = useState(false);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);

  /**
   * Opt-in, off by default. When false the PDF masks recovered passwords; when
   * true the PDF carries them in cleartext and says so on the cover and in the
   * footer of the credentials page.
   */
  const [discloseCredentials, setDiscloseCredentials] = useState(false);

  /*
    The retest baseline, selectable again.

    It was pinned at `null` with a comment explaining that the control had been
    removed and that `compareToBaseline` and its tests were "left in findingsDB
    for whatever brings the feature back". Everything else was already in place:
    the PDF builder's RETEST / REMEDIATION DELTA section, the fingerprint
    matching that recognises an issue across visits instead of reporting it as
    new each time, and `ExportMenu`'s own `selected` and `keepOpen` fields, whose
    documentation names this feature as the reason they exist. What was missing
    was the menu group.

    It is a setting, not an action: choosing one decides what the *next* PDF
    contains, so the menu marks the current choice rather than only listing the
    options, and stays open when one is picked.

    `null` remains a first-class choice rather than an absence. A document that
    claims no remediation progress is the correct output when no baseline was
    chosen, and "No comparison" has to be visibly selected for an operator to
    know that is what they are about to export.
  */
  const [baselineId, setBaselineId] = useState<number | null>(null);
  const [baselines, setBaselines] = useState<{ id: number; label: string; created_at: string; finding_count: number }[]>([]);
  const [baselineError, setBaselineError] = useState<string | null>(null);
  const baselineDelta: RetestDelta | null = null;

  // Timers were previously fired and forgotten, so a toast or an export-state
  // reset could land after the page unmounted (React state update on an
  // unmounted tree) or stack up when notifications overlapped.
  const notificationTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const exportStateTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  /*
    The stored baselines, read once and after each new one is recorded.

    A read failure is held and shown rather than swallowed. An empty list and a
    list that could not be read look identical in a menu, and the difference
    decides whether "No comparison" means "you have not taken a baseline" or
    "this export may be missing one you did take".
  */
  const refreshBaselines = useCallback(async () => {
    try {
      setBaselines(await listBaselines());
      setBaselineError(null);
    } catch (e) {
      setBaselines([]);
      setBaselineError(`The stored baselines could not be read — ${e instanceof Error ? e.message : String(e)}.`);
    }
  }, []);

  useEffect(() => { void refreshBaselines(); }, [refreshBaselines]);

  /**
   * Record the current findings as a baseline to compare future visits against.
   *
   * Scoped to the selected report's mission, not to the installation: a baseline
   * is a baseline *of* something, and `createBaseline` counts what it is a
   * baseline of using the same scoping `compareToBaseline` uses, so the two
   * agree about the denominator every percentage in the retest section is
   * derived from.
   *
   * It does not select itself afterwards. Comparing a set of findings against a
   * baseline taken from those same findings produces a delta of zero, which is
   * a true statement that reads as "nothing changed" — exactly the wrong thing
   * to put under a REMEDIATION DELTA heading on the day the work starts.
   */
  const handleCreateBaseline = useCallback(async (report: IntelReport) => {
    try {
      const label = `${report.targetName} — ${new Date().toISOString().slice(0, 10)}`;
      await createBaseline(label, { mission_id: (report as any).missionId ?? null });
      await refreshBaselines();
      showNotification(`BASELINE RECORDED — "${label}". Select it on a later export to show what changed.`);
    } catch (e) {
      showNotification(`COULD NOT RECORD BASELINE — ${e instanceof Error ? e.message : String(e)}`);
    }
  }, [refreshBaselines]);

  useEffect(() => {
    return () => {
      if (notificationTimer.current) clearTimeout(notificationTimer.current);
      if (exportStateTimer.current) clearTimeout(exportStateTimer.current);
      notificationTimer.current = null;
      exportStateTimer.current = null;
    };
  }, []);

  const showNotification = (message: string, type: 'success' | 'info' | 'error' = 'success', onClickAction?: () => void) => {
    if (notificationTimer.current) clearTimeout(notificationTimer.current);
    setNotification({ show: true, message, type, onClickAction });
    notificationTimer.current = setTimeout(() => {
      notificationTimer.current = null;
      setNotification(prev => ({ ...prev, show: false }));
    }, onClickAction ? 8000 : 4000);
  };

  const resetExportStateSoon = () => {
    if (exportStateTimer.current) clearTimeout(exportStateTimer.current);
    exportStateTimer.current = setTimeout(() => {
      exportStateTimer.current = null;
      setExportState('IDLE');
    }, 2000);
  };

  useEffect(() => { previewUrlRef.current = previewPdfUrl; }, [previewPdfUrl]);

  /*
    Release the last export's blob when the page goes away.

    Only the *superseded* URL is revoked during a session, so the newest one outlives
    the component — a few MB for a report carrying the survey-map image, held for the
    life of a SPA that never reloads.
  */
  useEffect(() => () => {
    const url = lastPdfBlobUrlRef.current;
    if (url) {
      try {
        URL.revokeObjectURL(url);
      } catch {
        // Already released by the browser. Nothing to do.
      }
    }
  }, []);

  const selectedReport = reports.find(r => r.id === selectedReportId) || null;

  useEffect(() => {
    setIsEditingTitle(false);
  }, [selectedReportId]);

  const handleSaveTitle = () => {
    if (selectedReport && editTitleValue.trim() && editTitleValue.trim() !== selectedReport.targetName) {
      renameReport(selectedReport.id, editTitleValue.trim());
    }
    setIsEditingTitle(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleSaveTitle();
    if (e.key === 'Escape') setIsEditingTitle(false);
  };

  const handleImportClick = () => {
    fileInputRef.current?.click();
  };


  /**
   * `intel_reports.id` is a PRIMARY KEY and `addReport` now rejects rather than
   * swallowing the constraint error, so the duplicate case has to be handled
   * here: tell the operator the archive is already stored, and offer a re-import
   * under a fresh id when they genuinely want a second copy.
   */
  const importReport = async (candidate: IntelReport, forceNewId = false) => {
    /*
      `origin` is stamped here, on the way in.

      `markImported` below is the database half and it was the only half. The
      store received the parsed file object verbatim — whose `origin` is whatever
      the file carried, normally nothing — and `loadReports()` has exactly one
      caller, at app start. So for the rest of the session the in-memory record
      said nothing about where it came from, and the PDF cover reads
      `r.origin === 'IMPORTED'` off the store: the filter came back empty, the
      `!! IMPORTED DATA - NOT GATHERED BY THIS RIG !!` banner was skipped, and
      the cover printed "LIVE HARDWARE [FIELD DATA]" in green for a file that
      arrived over the network from somewhere unknown.

      It corrected itself after a restart, because the database was right. That is
      what kept it hidden: anyone who imported, restarted, then exported saw the
      correct document.

      `saveReport` does not write the column, so the UPDATE is still needed. Both
      halves now, and the failure message below says which one did not land.
    */
    const record: IntelReport = {
      ...candidate,
      ...(forceNewId
        ? { id: `${candidate.id}-COPY-${Date.now().toString(36).toUpperCase()}` }
        : {}),
      origin: 'IMPORTED',
    };

    try {
      const alreadyInStore = useReportStore.getState().reports.some(r => r.id === record.id);
      const alreadyArchived = alreadyInStore || await reportExists(record.id);

      if (alreadyArchived) {
        setSelectedReportId(record.id);
        showNotification(
          `ALREADY ARCHIVED: report ${record.id} is already in this archive — nothing was imported. CLICK TO IMPORT A SECOND COPY UNDER A NEW ID.`,
          'error',
          () => { void importReport(candidate, true); }
        );
        return;
      }

      await useReportStore.getState().addReport(record);

      /*
        Mark it as imported before anything can export it.

        `markImported` existed and had no callers, so an imported archive kept
        `origin` at its schema default of 'LOCAL' — and the PDF cover printed
        "DATA SOURCE: LIVE HARDWARE [FIELD DATA]" for it. Any JSON file with the
        right five keys became field evidence gathered by this rig, and the
        "IMPORTED" badge the UI already had could never appear. That is a way
        around the whole `simulated` provenance chain, through the one door that
        accepts a file from outside.

        A failure here is not silent and does not leave the record looking local:
        the import is reported as provenance-unverified so the operator knows not
        to export it as field data.
      */
      let provenanceRecorded = true;
      try {
        await markImported(record.id);
      } catch (err) {
        provenanceRecorded = false;
        console.error('[Reports] markImported failed:', err);
      }

      setSelectedReportId(record.id);
      showNotification(
        provenanceRecorded
          ? (forceNewId
              ? `ARCHIVE IMPORTED AS A NEW COPY: ${record.targetName} (ID ${record.id}) — marked IMPORTED, not field data.`
              : `ARCHIVE IMPORTED: ${record.targetName} (ID ${record.id}) — marked IMPORTED, not field data.`)
          // The in-memory record is marked regardless, so this session exports
          // correctly. What failed is the database write, which means the mark is
          // lost at the next restart — and then it would export as field data.
          : `IMPORTED, BUT PROVENANCE WAS NOT SAVED: ${record.targetName} (ID ${record.id}). It is marked IMPORTED for this session only; after a restart it would export as LIVE HARDWARE. Re-import it or correct the record before delivering.`,
        provenanceRecorded ? 'success' : 'error'
      );
    } catch (err) {
      showNotification(`IMPORT FAILED: ${errText(err)}`, 'error');
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const json = JSON.parse(event.target?.result as string);
        if (json.id && json.type && json.targetName && json.timestamp && json.summary && json.rawData) {
          void importReport(json as IntelReport);
        } else {
          showNotification("INVALID ARCHIVE: The provided file does not match the classified report schema.", 'error');
        }
      } catch (err) {
        showNotification(`DECRYPTION FAILED: Unable to parse the JSON archive (${errText(err)}).`, 'error');
      }
      if (fileInputRef.current) fileInputRef.current.value = "";
    };
    reader.onerror = () => {
      showNotification("READ FAILED: The archive file could not be read from disk.", 'error');
      if (fileInputRef.current) fileInputRef.current.value = "";
    };
    reader.readAsText(file);
  };

  // ── Derived Table Data ── //
  //
  // Severity comes from `riskEngine` and nowhere else. The two counts here used
  // to disagree with the document: the WLAN tile read the engine's binary
  // `is_vulnerable` (which calls WPA1 vulnerable) while the PDF table recomputed
  // `WEP || OPEN`, and the LAN tile filtered `risk_score >= 7.0` on a column
  // nothing has ever written, so it was permanently zero.
  let tableData: any[] = [];
  let computedTotal = 0;

  const selectedFindings: Finding[] = selectedReport ? assessReport(selectedReport) : [];
  const selectedSummary = summarise(selectedFindings);

  /** Worst severity per subject, keyed upper-case, for the on-screen table. */
  // One rule, shared with the PDF and every export. See worstBySubject.
  const subjectSeverity = worstBySubject(selectedFindings);

  /**
   * Subjects carrying at least one HIGH or CRITICAL finding.
   *
   * Counted from the findings rather than from a Map of labels, so the on-screen
   * dial uses the same definition of "significant" as `summarise()` does for the
   * headline figure.
   */
  const significantSubjectCount = new Set(
    selectedFindings
      .filter(f => SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER.HIGH)
      .map(f => f.subject_id.toUpperCase())
  ).size;

  if (selectedReport) {
    if (selectedReport.type === 'INTRUSION') {
      tableData = [...hostsOf(selectedReport)];
    } else {
      tableData = [...apsOf(selectedReport)];
    }
    computedTotal = tableData.length;
  }
  /** CRITICAL + HIGH, which is the only honest reading of a headline figure. */
  const computedSignificant = selectedSummary.significant;

  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    tableData = tableData.filter(item =>
      Object.values(item).some(val => String(val).toLowerCase().includes(q))
    );
  }

  if (sortConfig) {
    tableData.sort((a, b) => {
      let valA = a[sortConfig.key];
      let valB = b[sortConfig.key];
      // Handle undefined or null
      if (valA === undefined || valA === null) valA = '';
      if (valB === undefined || valB === null) valB = '';

      if (valA < valB) return sortConfig.direction === 'asc' ? -1 : 1;
      if (valA > valB) return sortConfig.direction === 'asc' ? 1 : -1;
      return 0;
    });
  }

  const handleSort = (key: string) => {
    let direction: 'asc' | 'desc' = 'desc';
    if (sortConfig && sortConfig.key === key && sortConfig.direction === 'desc') {
      direction = 'asc';
    }
    setSortConfig({ key, direction });
  };

  /*
    Was a local table whose thresholds sat 10 dB above `ScanFeed`'s, so an access
    point at -65 dBm was "good" here and "fair" in the live feed it came from.
    Now shared; this table is one band stricter than it used to be, which is the
    correction.
  */
  const getSignalColor = signalTextClass;

  const handleCopyRaw = async (report: IntelReport) => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(report.rawData, null, 2));
    } catch (err) {
      showNotification(`CLIPBOARD WRITE FAILED: ${errText(err)}`, 'error');
      return;
    }
    setExportState('JSON_DONE');
    showNotification('RAW JSON COPIED TO CLIPBOARD', 'info');
    resetExportStateSoon();
  };

  /** Base name for any file exported from one archive. */
  // `exportBaseName` and `apExportRows` live in `src/lib/report/exports/apRows.ts`.

  const handleExportCSV = (report: IntelReport) => {
    // The old toast claimed "SAVED TO DOWNLOADS" before anything was written.
    // We can only honestly report that the file was handed to the browser's
    // download handler, and we must report it when even that fails.
    const fileName = `${exportBaseName(report)}.csv`;

    try {
      // Lives in `src/lib/report/exports/csv.ts`.
      const csvContent = buildCsv(report);

      // The BOM stays: Excel reads a UTF-8 CSV as the local codepage without it.
      downloadBlob(new Blob(['﻿' + csvContent], { type: 'text/csv;charset=utf-8;' }), fileName);
    } catch (err) {
      showNotification(`CSV EXPORT FAILED: ${errText(err)}`, 'error');
      return;
    }

    setExportState('CSV_DONE');
    showNotification(`CSV HANDED TO DOWNLOAD HANDLER: ${fileName} (check your browser download location)`, 'success');
    resetExportStateSoon();
  };

  /**
   * KMZ, which is the format a GIS analyst or Google Earth actually opens. Every
   * value is XML-escaped: an SSID is attacker-controlled text and must never be
   * able to close a tag.
   *
   * Async because the archive is built here: the icons are read from the app's
   * own assets and the document is deflated, both of which return promises. The
   * caller already handles this one as a promise.
   */
  const handleExportKML = async (report: IntelReport) => {
    if (!isWirelessReport(report)) {
      showNotification('KML EXPORT IS FOR WIRELESS SURVEYS: this archive is a LAN sweep and carries no coordinates.', 'info');
      return;
    }
    const fileName = `${exportBaseName(report)}.kmz`;

    try {
      // Lives in `src/lib/report/exports/kml.ts`.
      const kml = buildKml(report);
      if (kml === null) {
        showNotification('NO POSITIONED ACCESS POINTS: nothing in this archive carries an estimated coordinate, so no KML was written.', 'error');
        return;
      }

      /*
        Written as KMZ, with the two icons inside it.

        `assetBytes` handles both forms the bundler can produce. Vite inlines a
        small asset as a `data:` URI and emits a larger one as a file, and
        fetching the inlined form is refused by the shipped `connect-src` -- which
        would have blocked both of these in a built copy while working under
        `tauri dev`. A failure to read one is reported rather than silently
        producing an archive whose pins do not resolve: that failure is exactly
        what this change exists to remove, and an export that quietly
        reintroduced it would be worse than the URLs were, because nothing would
        say so.
      */
      const icons = await Promise.all(
        [
          { path: 'icons/placemark-circle.png', url: kmlCircleIcon },
          { path: 'icons/mirror-diamond.png', url: kmlDiamondIcon },
        ].map(async ({ path, url }) => {
          try {
            return { path, data: await assetBytes(url) };
          } catch (e) {
            throw new Error(`icon ${path} could not be read: ${e instanceof Error ? e.message : String(e)}`);
          }
        })
      );
      downloadBlob(await kmz(kml, icons), fileName);
    } catch (err) {
      showNotification(`KML EXPORT FAILED: ${errText(err)}`, 'error');
      return;
    }

    showNotification(`KML HANDED TO DOWNLOAD HANDLER: ${fileName}`, 'success');
  };

  /** GeoJSON, for anything that speaks it rather than KML. */
  const handleExportGeoJSON = (report: IntelReport) => {
    if (!isWirelessReport(report)) {
      showNotification('GEOJSON EXPORT IS FOR WIRELESS SURVEYS: this archive is a LAN sweep and carries no coordinates.', 'info');
      return;
    }
    const fileName = `${exportBaseName(report)}.geojson`;

    try {
      /*
        The same rule as the KML, which it did not use.

        This filtered on `typeof === 'number' && Number.isFinite`, so an access
        point at exactly `0, 0` -- the value a NULL column decays into -- was
        exported as a position in the Gulf of Guinea, and a corrupted latitude of
        95 would have been exported too. The KML dropped both. One archive, two
        geospatial exports, two different sets of located transmitters.
      */
      // Lives in `src/lib/report/exports/geojson.ts`.
      const collection = buildGeoJson(report);
      if (collection === null) {
        showNotification('NO POSITIONED ACCESS POINTS: nothing in this archive carries an estimated coordinate, so no GeoJSON was written.', 'error');
        return;
      }

      downloadBlob(
        new Blob([JSON.stringify(collection, null, 2)], { type: 'application/geo+json' }),
        fileName
      );
    } catch (err) {
      showNotification(`GEOJSON EXPORT FAILED: ${errText(err)}`, 'error');
      return;
    }

    showNotification(`GEOJSON HANDED TO DOWNLOAD HANDLER: ${fileName}`, 'success');
  };

  /**
   * The full audit export the PDF has always told the reader to request. It did
   * not exist until now, so the instruction was unfulfillable.
   */
  const handleExportAuditTrail = async () => {
    try {
      const scope = await getActiveScope();
      const { csv, rows } = await exportAuditTrailCsv(scope?.id);
      if (rows === 0) {
        showNotification('AUDIT TRAIL IS EMPTY: no scope-gated action has been recorded on this rig, so there is nothing to export.', 'info');
        return;
      }
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      const fileName = scope
        ? `LOCKON_AUDIT_TRAIL_scope${scope.id}_${stamp}.csv`
        : `LOCKON_AUDIT_TRAIL_ALL_${stamp}.csv`;
      downloadBlob(new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8;' }), fileName);
      showNotification(
        `FULL AUDIT TRAIL HANDED TO DOWNLOAD HANDLER: ${rows} event(s) in ${fileName}`,
        'success'
      );
    } catch (err) {
      showNotification(`AUDIT EXPORT FAILED: ${errText(err)}`, 'error');
    }
  };

  const handleDelete = (id: string) => {
    const isCurrentlySelected = id === selectedReportId;
    deleteReport(id);

    // If we deleted the active one, pick the next available
    if (isCurrentlySelected) {
      const remaining = reports.filter(r => r.id !== id);
      setSelectedReportId(remaining.length > 0 ? remaining[0].id : null);
    }
  };

  const handleExportPDF = async (reportsArray: IntelReport[]) => {
    if (reportsArray.length === 0) return;
    setExportState('PDF_LOADING');
    try {
      await buildAndSavePDF(reportsArray);
    } catch (err) {
      setExportState('IDLE');
      showNotification(`PDF GENERATION FAILED: ${errText(err)} — no file was written.`, 'error');
    }
  };

  /*
    Where the document's sections live, because they are in two places.

    All nineteen are modules under `src/lib/report/sections/`, in the order the
    document draws them:

      - 1.  COVER PAGE                    -> sections/coverPage.ts
      - 3.  EXECUTIVE SUMMARY             -> sections/executiveSummary.ts
      - 4.  AUTHORIZED ENGAGEMENT SCOPE   -> sections/engagementScope.ts
      - 5.  SCOPE ENFORCEMENT AUDIT TRAIL -> sections/auditTrail.ts
      - 6.  SURVEY COVERAGE               -> sections/surveyCoverage.ts
      - 6b. SUBNET SWEEP COVERAGE         -> sections/sweepCoverage.ts
      - 6c. EVIDENCE REGISTER             -> sections/evidenceRegister.ts
      - 7.  PRIORITISED FINDINGS          -> sections/prioritisedFindings.ts
      - 8.  ROGUE AP / EVIL TWIN          -> sections/rogueAssessment.ts
      - 9.  WPS EXPOSURE                  -> sections/wpsExposure.ts
      - 9b. POSITION QUALITY              -> sections/positionQuality.ts
      - 10. PER-ARCHIVE DETAIL            -> sections/perReportDetail.ts
      - 11. GLOBAL CREDENTIALS            -> sections/globalCredentials.ts
      - 12. RETEST / REMEDIATION DELTA    -> sections/retestDelta.ts
      - 13. METHOD AND LIMITATIONS        -> sections/methodAppendix.ts
      - 14. FOOTER ON ALL PAGES           -> sections/pageFooter.ts
      - 15. POPULATE TOC PAGE             -> sections/tableOfContents.ts
      - 16. EXPORT INTEGRITY              -> sections/integrityStamp.ts

    Section 2 is thirteen lines that reserve a page and remember its number, which
    is bookkeeping rather than a section, so it stays.

    What is left here is the order they run in, the four values that travel
    between them, and the save. Three sections return something a later one needs
    -- the credentials page number, the filename and the pre-stamp digest -- and
    those were `let`s in a 2,700-line closure, read hundreds of lines from where
    they were set. They are parameters and return values now, which is the part of
    this that was worth more than navigability.

    This note used to say the remaining sections were staying, because "moving
    them buys navigability and not testability". The first half is right and the
    second half stopped being the point. `pdfdiff` is what made the move safe
    rather than brave: each section was extracted verbatim, the real app
    re-exported, and the document compared string by string before the next one
    was touched -- against a LAN archive *and* a wireless one, because the two
    draw different halves of this list.
  */
  const buildAndSavePDF = async (reportsArray: IntelReport[]) => {
    const doc = new jsPDF();
    /*
      Everything this document states, gathered before a single page is drawn.

      The seven labelled blocks that used to sit here — provenance, the
      authorization record and its audit trail, the one set of severity numbers,
      rogue/WPS grouping, the evidence register, survey coverage and the method
      appendix inputs — moved to `src/lib/report/assemble.ts` unchanged. They are
      where every figure a manager reads is decided, and inside this closure
      nothing could assert against them.
    */
    const reportData = await assembleReportData(reportsArray, { baselineId, baselineDelta });

    /*
      The survey figure, rendered before any page is drawn.

      It needs a live WebGL context and a network round trip for tiles, so it is
      done once, up front, and the result is just a bitmap by the time the
      document is being laid out. Failure is not fatal: `image` comes back null
      with a reason, the section is skipped, and the rest of the report is
      unaffected — a missing figure must never cost the document.
    */
    const wirelessReports = reportsArray.filter(r => isWirelessReport(r));
    // Deduplicated, like every other population figure in the document. A plain
    // flatMap plotted the same radio once per archive and double-counted it in the
    // figure's KEY census.
    const surveyAps = dedupeApsByBssid(wirelessReports.flatMap(r => apsOf(r)));
    const surveyPath = wirelessReports.flatMap(r => r.rawData?.pathCoords ?? []);
    const surveyMap = wirelessReports.length > 0
      // `worstFor` is the report's own verdict for a radio, so the figure
      // colours a dot with exactly the severity the findings table prints for
      // it. Deriving a second opinion here is how a figure ends up contradicting
      // the table on the facing page.
      ? await captureSurveyMap(surveyAps, surveyPath, {
          /*
            `worstFor` answers INFO for two different situations: a radio that
            earned an INFO finding, and a radio that earned no finding at all.
            On a map those must not share a colour. 102 of the 172 access points
            here raised nothing, and letting them render as INFO would put the
            report's own "we had no opinion" in the same ink as "we looked and
            said something mild".

            `confidence` is null only in the unmatched case, so it is what
            separates them.
          */
          severityFor: (ap: any) => {
            const worst = reportData.worstFor(ap?.bssid);
            return worst.confidence === null ? 'NONE' : worst.severity;
          },
        })
      : { image: null, width: 0, height: 0, plotted: 0, ambiguous: 0, ringsOmitted: 0, hasRoute: false, routeSpanM: 0, routeFixes: 0, basemap: 'offline-grid' as const, counts: {}, unresolved: 0, mirrorsDrawn: 0, reason: 'no wireless report in this export' };
    if (!surveyMap.image && surveyMap.reason) {
      console.warn('[report] survey map not included:', surveyMap.reason);
    }
    const {

      allSimulated, isMixedProvenance,
      activeScope,

      allCredentials,




      methodology, cveData, capabilities, evilTwinMethod, appVersion, engineVersion,

    } = reportData;

    /*
      The document's own identifier.

      Derived here rather than inside the cover because the page header and the
      exported filename print the same string, and a second derivation is a second
      chance to disagree. It was `MULTI-${Date.now().toString().slice(-6)}` once:
      a number recorded nowhere, which a recipient could not look up and which
      differed between two exports of the same selection. Hashing the sorted
      archive ids makes it stable, and those ids are listed in the executive
      summary so it can be traced back.
    */
    const reportIdStr = reportData.isMulti
      ? `MULTI-${stableSelectionId(reportData.reportsArray.map(r => r.id))}`
      : reportData.reportsArray[0].id;

    // --- 1. COVER PAGE ---
    // Lives in `src/lib/report/sections/coverPage.ts`.
    await renderCoverPage({ doc, data: reportData, reportIdStr, discloseCredentials });

    // --- 2. TABLE OF CONTENTS ALLOCATION ---
    doc.addPage();
    const tocPageNum = (doc as any).internal.getNumberOfPages();
    /*
      Page furniture, bound to this document.

      `fit`, `sectionHeading`, `paragraph` and `callout` moved to
      `src/lib/report/layout.ts`. They enforce the one rule every body
      section depends on — nothing runs off the bottom of a page — and they
      were defined in this closure, so a section could not become a module
      without them.
    */
    const layout = createLayout(doc);
    // --- 3. EXECUTIVE SUMMARY PAGE ---
    // Lives in `src/lib/report/sections/executiveSummary.ts`.
    renderExecutiveSummary(layout, reportData, { reportIdStr, discloseCredentials });

    // --- 4. AUTHORIZED ENGAGEMENT SCOPE ---
    // Lives in `src/lib/report/sections/engagementScope.ts`.
    renderEngagementScope(layout, reportData);

    // --- 5. SCOPE ENFORCEMENT AUDIT TRAIL ---
    // Lives in `src/lib/report/sections/auditTrail.ts`.
    renderAuditTrail(layout, reportData);
    // --- 6. SURVEY COVERAGE ---
    // Lives in `src/lib/report/sections/surveyCoverage.ts`.
    renderSurveyCoverage(layout, reportData, { surveyMap });

    // --- 6b. SUBNET SWEEP COVERAGE ---
    // Lives in `src/lib/report/sections/sweepCoverage.ts`.
    renderSweepCoverage(layout, reportData);

    // --- 6c. EVIDENCE REGISTER ---
    // Lives in `src/lib/report/sections/evidenceRegister.ts`.
    renderEvidenceRegister(layout, reportData);
    // --- 7. PRIORITISED FINDINGS ---
    // Lives in `src/lib/report/sections/prioritisedFindings.ts`.
    renderPrioritisedFindings(layout, reportData);

    // --- 8. ROGUE ACCESS POINT / EVIL TWIN ASSESSMENT ---
    // Lives in `src/lib/report/sections/rogueAssessment.ts`.
    renderRogueAssessment(layout, reportData);

    // --- 9. WPS EXPOSURE ---
    // Lives in `src/lib/report/sections/wpsExposure.ts`.
    renderWpsExposure(layout, reportData);

    // --- 9b. POSITION QUALITY ---
    // Lives in `src/lib/report/sections/positionQuality.ts`.
    renderPositionQuality(layout, reportData);

    // --- 10. LOOP THROUGH REPORTS ---
    // Lives in `src/lib/report/sections/perReportDetail.ts`.
    renderPerReportDetail(layout, reportData);

    // --- 11. GLOBAL CREDENTIALS (masked by default) ---
    // Lives in `src/lib/report/sections/globalCredentials.ts`.
    const credentialsPageNum = renderGlobalCredentials(layout, reportData, { discloseCredentials });

    // --- 12. RETEST / REMEDIATION DELTA ---
    // Lives in `src/lib/report/sections/retestDelta.ts`.
    renderRetestDelta(layout, reportData, { baselineId });

    // --- 13. METHOD AND LIMITATIONS APPENDIX ---
    // What makes every severity above auditable. Lives in
    // `src/lib/report/sections/methodAppendix.ts`.
    renderMethodAppendix(layout, reportData);

    // --- 14. FOOTER ON ALL PAGES ---
    // Lives in `src/lib/report/sections/pageFooter.ts`.
    renderPageFooter(layout, reportData, { reportIdStr, discloseCredentials, credentialsPageNum });

    // --- 15. POPULATE TOC PAGE ---
    // Lives in `src/lib/report/sections/tableOfContents.ts`.
    const saveName = renderTableOfContents(layout, reportData, { tocPageNum, reportIdStr, discloseCredentials });

    // --- 16. EXPORT INTEGRITY ---
    // Lives in `src/lib/report/sections/integrityStamp.ts`.
    const stamp = await renderIntegrityStamp(doc, sha256Hex, errText);
    const interimDigest = stamp.interimDigest;
    // Still a `let`: the save below records the first reason a digest could
    // not be produced, and a failure there must not overwrite one from here.
    let digestError = stamp.digestError;

    // Report what actually happened. The old toast announced success before the
    // save had been attempted at all.
    /*
      One outstanding preview blob at a time.

      `URL.revokeObjectURL` appeared nowhere in this file. A blob URL was created on
      every export, before the save was even attempted, and used only inside two
      notification click handlers — so each export pinned its whole PDF in memory for
      the document's lifetime. This is a SPA with no reload, so that is the rest of the
      session; a report carrying the survey-map JPEG is several MB, and ten exports
      retained tens of MB with no way to release them short of restarting.

      Revoking the *previous* one here rather than this one on close: the notification
      that opens the preview stays clickable for a while, and a revoked URL would make
      it open a blank frame. A new export supersedes the old notification, so by this
      point the earlier blob has no remaining route to it.
    */
    const pdfBlobUrl = (doc as any).output('bloburl') as string;
    const supersededUrl = lastPdfBlobUrlRef.current;
    if (supersededUrl && supersededUrl !== pdfBlobUrl) {
      /*
        A ref, not the state value.

        Everything above this line is `await`-heavy, so `previewPdfUrl` here is the
        value captured when this closure was created. An operator who opens the
        previous export's preview *while* this one assembles would have had its URL
        revoked out from under the iframe, with the modal left open on a blank frame,
        because the closure still saw null.
      */
      if (previewUrlRef.current === supersededUrl) setPreviewPdfUrl(null);
      try {
        URL.revokeObjectURL(supersededUrl);
      } catch {
        // A URL the browser has already released. Nothing to do.
      }
    }
    lastPdfBlobUrlRef.current = pdfBlobUrl;
    try {
      await doc.save(saveName, { returnPromise: true });
    } catch (err) {
      setExportState('IDLE');
      showNotification(
        `PDF SAVE FAILED: ${errText(err)} — the report was built but not written to disk. CLICK TO VIEW IT IN-APP.`,
        'error',
        () => setPreviewPdfUrl(pdfBlobUrl)
      );
      return;
    }

    // Digest of the delivered file, recorded against every archive that went into
    // it so the operator can quote it without regenerating anything.
    let deliveredDigest: string | null = null;
    try {
      deliveredDigest = await sha256Hex((doc as any).output('arraybuffer') as ArrayBuffer);
      for (const r of reportsArray) {
        await recordExport(r.id, {
          sha256: deliveredDigest,
          filename: saveName,
          // Null rather than a fabricated 'OP-LOCKON'. This row is the durable
          // provenance record for a delivered document; inventing an operator
          // identity in it makes the record assert something nobody stated. An
          // unrecorded operator is a gap to be filled, not a name to invent.
          exported_by: activeScope?.operator ?? null,
          app_version: appVersion ?? null,
          engine_version: engineVersion,
          cve_data_date: cveData?.generated_at ?? null,
          methodology: {
            risk: methodology,
            rogue_ap: evilTwinMethod,
            cve_data: cveData,
            capabilities_summary: (capabilities as any)?.summary ?? null,
            unavailable_features: (capabilities as any)?.unavailable_features ?? null,
            pre_stamp_sha256: interimDigest,
          },
        });
      }
    } catch (err) {
      digestError = digestError ?? errText(err);
    }

    setExportState('PDF_DONE');
    const flags = [
      allSimulated ? 'SIMULATED' : isMixedProvenance ? 'MIXED PROVENANCE' : null,
      allCredentials.length > 0 ? (discloseCredentials ? 'CLEARTEXT CREDS' : 'CREDS MASKED') : null,
    ].filter(Boolean).join(' / ');
    const digestNote = deliveredDigest
      ? ` SHA-256 ${deliveredDigest.slice(0, 16).toUpperCase()} (recorded)`
      : ` INTEGRITY DIGEST NOT RECORDED${digestError ? `: ${digestError}` : ''}`;
    showNotification(
      `PDF WRITTEN: ${saveName}${flags ? ` [${flags}]` : ''}.${digestNote} — CLICK TO VIEW`,
      deliveredDigest ? 'success' : 'error',
      () => setPreviewPdfUrl(pdfBlobUrl)
    );
    resetExportStateSoon();
  };

  return (
    <div className="h-full flex flex-col p-4 overflow-hidden">
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-white text-tactical tracking-wider flex items-center gap-3">
          <svg xmlns="http://www.w3.org/2000/svg" className="w-6 h-6 text-risk-info" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z" />
            <path d="M14 2v4a2 2 0 0 0 2 2h4" /><path d="M10 9H8" /><path d="M16 13H8" /><path d="M16 17H8" />
          </svg>
          INTEL ARCHIVE
        </h2>
        <p className="text-sm text-gray-500 font-mono mt-1">Classified scan reports and historical tactical data.</p>
      </div>

      <div className="flex-1 flex gap-4 min-h-0">

        {/* Left Column: Report List */}
        <div className="w-72 lg:w-80 shrink-0 flex flex-col glass-card border-space-500/20 overflow-hidden relative">
          <div className="px-4 py-3 border-b border-space-500/20 bg-space-900/50 flex justify-between items-center">
            <h3 className="text-xs font-tactical text-gray-400 tracking-widest">SAVED ARCHIVES ({reports.length})</h3>

            <input
              type="file"
              accept=".json"
              ref={fileInputRef}
              onChange={handleFileChange}
              className="hidden"
            />
            <div className="flex gap-2">
              <button
                onClick={() => { setIsMultiSelect(!isMultiSelect); setSelectedIds([]); }}
                className={`text-[10px] font-tactical px-2 py-0.5 rounded border transition-colors flex items-center gap-1 ${isMultiSelect ? 'bg-signal-strong/20 border-signal-strong/50 text-signal-strong' : 'border-space-500/30 text-gray-400 hover:text-white hover:bg-space-800'}`}
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 11l3 3L22 4" /><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" /></svg>
                MULTI
              </button>
              {!isMultiSelect && (
                <button
                  onClick={handleImportClick}
                  className="text-[10px] font-tactical px-2 py-0.5 rounded border border-space-500/30 text-gray-400 hover:text-white hover:bg-space-800 transition-colors flex items-center gap-1"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="17 8 12 3 7 8" /><line x1="12" y1="3" x2="12" y2="15" /></svg>
                  IMPORT
                </button>
              )}
            </div>
          </div>

          <div className="flex-1 overflow-y-auto no-scrollbar p-2 space-y-2">
            {reports.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center p-6 text-center">
                <svg xmlns="http://www.w3.org/2000/svg" className="w-12 h-12 text-space-600 mb-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                  <polyline points="17 8 12 3 7 8" />
                  <line x1="12" y1="3" x2="12" y2="15" />
                </svg>
                <p className="text-sm font-mono text-gray-500">No reports generated yet.</p>
              </div>
            ) : (
              <AnimatePresence>
                {reports.map((r) => (
                  <motion.button
                    key={r.id}
                    layout
                    /*
                      A stable hook for `scripts/export-smoke-test.mjs`, which has
                      to select a report before it can export one. Matching on
                      Tailwind classes instead would make the harness pass
                      silently the moment the styling changed — it would find no
                      row, export nothing, and report a clean run. This is the
                      one path `npm test` cannot reach, so the harness must fail
                      loudly or not at all.
                    */
                    data-report-row={r.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    onClick={() => {
                      if (isMultiSelect) {
                        setSelectedIds(prev => prev.includes(r.id) ? prev.filter(id => id !== r.id) : [...prev, r.id]);
                      } else {
                        setSelectedReportId(r.id);
                      }
                    }}
                    className={`w-full text-left p-4 rounded-lg border transition-all relative ${isMultiSelect
                        ? (selectedIds.includes(r.id) ? 'bg-space-800 border-signal-strong/50' : 'bg-space-900/40 border-space-500/10 hover:bg-space-800/80 hover:border-space-500/30')
                        : (selectedReportId === r.id ? 'bg-space-800 border-risk-info/50' : 'bg-space-900/40 border-space-500/10 hover:bg-space-800/80 hover:border-space-500/30')
                      }`}
                  >
                    <div className="flex gap-3">
                      {isMultiSelect && (
                        <div className="pt-0.5 shrink-0">
                          <div className={`w-4 h-4 rounded border flex items-center justify-center transition-colors ${selectedIds.includes(r.id) ? 'bg-signal-strong border-signal-strong' : 'border-space-500'}`}>
                            {selectedIds.includes(r.id) && <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>}
                          </div>
                        </div>
                      )}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between mb-2 gap-2">
                          <div className="flex items-center gap-1.5 min-w-0">
                            <span className={`text-[10px] font-tactical px-2 py-0.5 rounded shrink-0 ${r.type === 'INTRUSION' ? 'bg-neon-500/20 text-neon-400' : 'bg-risk-high/20 text-risk-high'}`}>
                              {r.type}
                            </span>
                            {r.simulated && (
                              <span
                                title="This report was produced by the hardware simulator. Its findings are not field-verified."
                                className="text-[9px] font-tactical px-1.5 py-0.5 rounded bg-amber-400/20 text-amber-300 border border-amber-400/50 tracking-wider shrink-0"
                              >
                                SIMULATED
                              </span>
                            )}
                          </div>
                          <span className="text-[10px] font-mono text-gray-500 shrink-0">
                            {new Date(r.timestamp).toLocaleDateString()}
                          </span>
                        </div>
                        <div className="text-sm font-bold text-white font-mono truncate">{r.targetName}</div>
                        <div className="text-xs font-mono text-gray-500 mt-1 truncate">ID: {r.id}</div>
                        {r.simulated && (
                          <div className="text-[10px] font-mono text-amber-400/80 mt-1 truncate">NOT FIELD-VERIFIED</div>
                        )}
                      </div>
                    </div>
                  </motion.button>
                ))}
              </AnimatePresence>
            )}
          </div>

          {isMultiSelect && selectedIds.length > 0 && (
            <div className="p-3 border-t border-space-500/20 bg-space-900/80 backdrop-blur space-y-2">
              {(() => {
                const picked = reports.filter(r => selectedIds.includes(r.id));
                const simCount = picked.filter(r => r.simulated).length;
                if (simCount === 0) return null;
                return (
                  <div className="text-[10px] font-mono text-amber-300 bg-amber-400/10 border border-amber-400/40 rounded px-2 py-1.5 leading-snug">
                    {simCount === picked.length
                      ? `ALL ${picked.length} SELECTED OPERATIONS ARE SIMULATED — the PDF will be marked NOT FIELD-VERIFIED.`
                      : `MIXED SELECTION: ${simCount} of ${picked.length} operations are SIMULATED — the PDF will name which is which.`}
                  </div>
                );
              })()}
              <button
                onClick={() => handleExportPDF(reports.filter(r => selectedIds.includes(r.id)))}
                disabled={exportState === 'PDF_LOADING'}
                className="w-full py-2 bg-red-900/20 hover:bg-red-900/40 border border-red-500/30 text-red-400 rounded text-xs font-tactical tracking-wider flex items-center justify-center gap-2 transition-colors"
              >
                {exportState === 'PDF_LOADING' ? (
                  <>
                    <svg className="w-4 h-4 animate-spin text-red-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                    MERGING...
                  </>
                ) : (
                  <>
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /><polyline points="10 9 9 9 8 9" /></svg>
                    MERGE TO PDF ({selectedIds.length})
                  </>
                )}
              </button>
            </div>
          )}
        </div>

        {/* Right Column: Report Details */}
        <div className="flex-1 glass-card border-space-500/20 flex flex-col overflow-hidden relative bg-space-900/20">
          {selectedReport ? (
            <>
              {/* Header */}
              <div className="p-6 border-b border-space-500/20 bg-space-900/80">
                {/*
                  Title and buttons share the top line; the metadata gets its
                  own full-width row beneath them.

                  It used to sit in the left column, competing with the button
                  row for horizontal space, and lost — "DATETIME: 9/27/2026,
                  5:19:36 PM" broke across two lines while the right half of the
                  header was empty. Nothing about these three fields needs to be
                  beside the title, and given the whole width they fit on one
                  line at any sensible window size.
                */}
                <div className="flex justify-between items-start gap-6">
                  <div className="min-w-0 flex-1">
                    <h3 className="text-2xl font-bold font-mono text-white flex items-center gap-3 h-10 w-full min-w-[300px]">
                      {isEditingTitle ? (
                        <input
                          autoFocus
                          type="text"
                          value={editTitleValue}
                          onChange={(e) => setEditTitleValue(e.target.value)}
                          onBlur={handleSaveTitle}
                          onKeyDown={handleKeyDown}
                          className="bg-space-800 text-white border border-neon-500/50 rounded-md px-3 py-1 font-mono text-xl w-80 max-w-full outline-none focus:border-neon-400"
                        />
                      ) : (
                        <>
                          <span className="truncate">{selectedReport.targetName}</span>
                          <button
                            onClick={() => {
                              setEditTitleValue(selectedReport.targetName);
                              setIsEditingTitle(true);
                            }}
                            className="p-1.5 rounded-md hover:bg-space-700/50 text-gray-500 hover:text-neon-400 transition-colors shrink-0"
                            title="Rename Report"
                          >
                            <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z" /></svg>
                          </button>
                        </>
                      )}
                    </h3>
                  </div>
                  <div className="flex flex-nowrap items-center gap-2 justify-end shrink-0">
                    {/*
                      Three controls, not eight, and the two that are not in the
                      menu are outside it on purpose.

                      The credential toggle is a mode, not an action, and it
                      changes what the PDF contains. Its state has to be legible
                      at the moment the operator exports, which is the only
                      moment it matters. PURGE is irreversible, and a
                      destructive action sitting one row below "JSON to
                      clipboard" in a list of exports is how an engagement gets
                      deleted by someone who meant to send it.
                    */}
                    <button
                      onClick={() => setDiscloseCredentials(v => !v)}
                      title={
                        discloseCredentials
                          ? 'FULL DISCLOSURE IS ON: exported PDFs will contain recovered passwords in cleartext and will be marked as such on the cover and in the credentials-page footer. Click to go back to masked.'
                          : 'Passwords are masked in exported PDFs (first and last character plus length). Click to enable a full-disclosure export containing cleartext passwords.'
                      }
                      className={`px-3 py-2 border rounded text-[10px] font-tactical tracking-wider transition-colors flex items-center gap-2 ${discloseCredentials
                          ? 'bg-risk-critical/20 border-risk-critical/60 text-risk-critical'
                          : 'bg-space-800 hover:bg-space-700 border-space-500/30 text-gray-300'
                        }`}
                    >
                      <span className={`w-2 h-2 rounded-full ${discloseCredentials ? 'bg-risk-critical animate-pulse' : 'bg-signal-strong'}`} />
                      {discloseCredentials ? 'CREDS: CLEARTEXT' : 'CREDS: MASKED'}
                    </button>

                    <ExportMenu
                      busy={exportState === 'PDF_LOADING'}
                      busyLabel="RENDERING"
                      groups={[
                        {
                          title: 'DOCUMENT',
                          items: [{
                            id: 'pdf',
                            label: 'PDF REPORT',
                            hint: 'The assessment as management reads it: findings, methodology, coverage and the evidence register.',
                            onSelect: () => handleExportPDF([selectedReport]),
                            done: exportState === 'PDF_DONE',
                            doneLabel: 'PDF EXPORTED',
                            // The credential mode is repeated here because this
                            // is the only export it affects, and this is the
                            // moment it decides what leaves the building.
                            note: discloseCredentials ? 'CLEARTEXT' : 'masked',
                            noteTone: discloseCredentials ? 'warning' : 'normal',
                          }],
                        },
                        {
                          title: 'DATA',
                          items: [
                            {
                              id: 'csv',
                              label: 'CSV',
                              hint: 'One row per access point or host, for a spreadsheet.',
                              onSelect: () => handleExportCSV(selectedReport),
                              done: exportState === 'CSV_DONE',
                              doneLabel: 'CSV EXPORTED',
                            },
                            {
                              id: 'json',
                              label: 'JSON TO CLIPBOARD',
                              hint: 'The raw archive, unmodified, for another tool or a bug report.',
                              onSelect: () => handleCopyRaw(selectedReport),
                              done: exportState === 'JSON_DONE',
                              doneLabel: 'COPIED',
                            },
                          ],
                        },
                        {
                          title: 'SPATIAL',
                          /*
                            Disabled rather than clickable for a LAN sweep.

                            Both handlers already refuse and answer with a
                            toast, which tells the operator only after they have
                            asked. A LAN archive has no coordinates in it, and
                            that is knowable before the click.
                          */
                          items: [
                            {
                              id: 'kml',
                              label: 'KMZ',
                              hint: 'Google Earth / GIS placemarks: SSID, BSSID, vendor, encryption, severity, first seen. The pin artwork travels inside the file, so it opens with no network.',
                              // `void`, because the handler became async when the
                              // archive began being built here. Its own try/catch
                              // reports a failure; this says the promise is
                              // deliberately not awaited.
                              onSelect: () => { void handleExportKML(selectedReport); },
                              disabledReason: isWirelessReport(selectedReport)
                                ? null
                                : 'This archive is a LAN sweep and carries no coordinates.',
                            },
                            {
                              id: 'geojson',
                              label: 'GEOJSON',
                              hint: 'The same attributes as a FeatureCollection, for anything that does not read KML.',
                              onSelect: () => handleExportGeoJSON(selectedReport),
                              disabledReason: isWirelessReport(selectedReport)
                                ? null
                                : 'This archive is a LAN sweep and carries no coordinates.',
                            },
                          ],
                        },
                        {
                          title: 'EVIDENCE',
                          items: [{
                            id: 'audit',
                            label: 'AUDIT TRAIL CSV',
                            hint: 'Every scope decision, allowed and blocked, with no row cap. This is the export the PDF tells the reader to request.',
                            onSelect: () => { void handleExportAuditTrail(); },
                          }],
                        },
                        {
                          /*
                            The retest baseline.

                            A setting rather than an export: every item here
                            decides what the *next* PDF contains, so they mark
                            the current choice and leave the menu open. Those two
                            fields already existed on `ExportItem` and named this
                            feature as the reason they were there; nothing used
                            them, because the group had been removed.

                            It sits last, under DOCUMENT and DATA, because an
                            operator reaches for an export and discovers the
                            comparison, not the other way round.
                          */
                          title: 'COMPARE AGAINST',
                          items: [
                            {
                              id: 'baseline-none',
                              label: 'No comparison',
                              hint: 'Export the findings as they stand. The document claims no remediation progress, which is the right output when there is no baseline to claim it against.',
                              onSelect: () => setBaselineId(null),
                              selected: baselineId === null,
                              keepOpen: true,
                            },
                            ...baselines.map(b => ({
                              id: `baseline-${b.id}`,
                              label: b.label,
                              // The count is the denominator of every percentage
                              // the retest section prints, so it is shown at the
                              // moment of choosing rather than only inside the
                              // document that resulted.
                              hint: `${b.finding_count} finding(s) recorded ${new Date(b.created_at).toLocaleDateString()}. Findings are matched on a fingerprint of the subject and the issue, so the same issue is recognised across visits rather than counted as new.`,
                              onSelect: () => setBaselineId(b.id),
                              selected: baselineId === b.id,
                              keepOpen: true,
                            })),
                            {
                              id: 'baseline-record',
                              label: 'Record this as a baseline',
                              hint: 'Stores the current findings so a later visit can show what was fixed. It does not become the selected comparison: a set of findings compared against itself produces a delta of zero, which reads as "nothing changed" on the day the work starts.',
                              onSelect: () => { void handleCreateBaseline(selectedReport); },
                              keepOpen: true,
                            },
                            // A read failure is offered as a disabled row rather
                            // than left out. An empty list and a list that could
                            // not be read look identical in a menu, and the
                            // difference decides whether "No comparison" means
                            // "you have not taken one" or "this export may be
                            // missing one you did".
                            ...(baselineError ? [{
                              id: 'baseline-error',
                              label: 'Stored baselines could not be read',
                              hint: baselineError,
                              onSelect: () => { void refreshBaselines(); },
                              disabledReason: baselineError,
                              keepOpen: true,
                            }] : []),
                          ],
                        },
                      ]}
                    />

                    {/* Separated from the exports, deliberately. */}
                    <span className="w-px h-6 bg-space-500/30 mx-1" aria-hidden="true" />
                    <button
                      onClick={() => handleDelete(selectedReport.id)}
                      title="Permanently delete this archive and everything in it. This cannot be undone."
                      className="px-4 py-2 bg-risk-critical/10 hover:bg-risk-critical/20 border border-risk-critical/30 rounded text-xs font-tactical tracking-wider text-risk-critical transition-colors"
                    >
                      PURGE
                    </button>
                  </div>
                </div>

                {/* Wraps as whole fields, never mid-value: a timestamp split
                    across two lines reads as two facts. */}
                <div className="mt-3 flex flex-wrap items-center gap-x-8 gap-y-1 text-xs font-mono text-gray-400">
                  <span className="whitespace-nowrap">DATETIME: {new Date(selectedReport.timestamp).toLocaleString()}</span>
                  <span className="whitespace-nowrap">TYPE: {selectedReport.type}</span>
                  {/*
                    Three sources, not two.

                    This read `simulated ? 'HARDWARE SIMULATOR' : 'LIVE
                    HARDWARE'`, so an archive imported from a file — whose
                    provenance this installation cannot vouch for at all —
                    announced itself as LIVE HARDWARE. An IMPORTED badge
                    elsewhere used to cover for that; it is gone now, so the
                    line says it itself. The PDF has always flagged imported
                    archives on the cover and in a banner; this is the screen
                    catching up with the document.
                  */}
                  <span className={`whitespace-nowrap ${
                    selectedReport.simulated || selectedReport.origin === 'IMPORTED'
                      ? 'text-amber-300 font-bold'
                      : 'text-signal-strong'
                  }`}>
                    SOURCE: {
                      selectedReport.simulated && selectedReport.origin === 'IMPORTED'
                        ? 'IMPORTED SIMULATOR ARCHIVE'
                        : selectedReport.simulated ? 'HARDWARE SIMULATOR'
                        : selectedReport.origin === 'IMPORTED' ? 'IMPORTED — NOT THIS RIG'
                        : 'LIVE HARDWARE'
                    }
                  </span>
                </div>
              </div>

              {/* PROVENANCE / DISCLOSURE STRIPS — a simulated archive must never
                  read as field evidence, in the UI or in the PDF. */}
              {selectedReport.simulated && (
                <div className="px-6 py-2 bg-amber-400/15 border-b border-amber-400/40 flex items-center gap-3">
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-amber-300 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
                  <span className="text-[11px] font-tactical tracking-widest text-amber-300">SIMULATED DATA</span>
                  <span className="text-[11px] font-mono text-amber-200/80">
                    This archive was produced by the hardware simulator. Its findings are NOT field-verified and must not be cited as evidence of real exposure. Exported PDFs are marked accordingly on every page.
                  </span>
                </div>
              )}
              {discloseCredentials && (
                <div className="px-6 py-2 bg-risk-critical/15 border-b border-risk-critical/40 flex items-center gap-3">
                  <span className="w-2 h-2 rounded-full bg-risk-critical animate-pulse shrink-0" />
                  <span className="text-[11px] font-tactical tracking-widest text-risk-critical">FULL DISCLOSURE ARMED</span>
                  <span className="text-[11px] font-mono text-risk-critical/80">
                    Exported PDFs will contain recovered passwords in cleartext and will be labelled as a credential store. Switch back to CREDS: MASKED before sharing a report.
                  </span>
                </div>
              )}

              <div className="flex-1 overflow-y-auto no-scrollbar p-6 space-y-6 flex flex-col">

                {/* Tactical Summary */}
                <div>
                  <h4 className="text-xs font-tactical text-gray-500 mb-4 tracking-widest border-b border-space-500/20 pb-2">EXECUTIVE SUMMARY</h4>
                  {/*
                    The two figures line up.

                    They did not: "CRITICAL + HIGH FINDINGS" wraps to two lines
                    while "TOTAL APs" does not, so the numbers sat at different
                    heights and one card carried a footnote the other lacked.
                    Two numbers presented side by side as a comparison have to
                    share a baseline, or the eye reads the lower one as
                    subordinate. The label and footnote rows are given the same
                    reserved height in both, so the figures cannot drift apart
                    again when a label changes length.
                  */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 items-stretch">
                    <div className="bg-space-800/50 border border-space-500/20 rounded-lg p-4 flex flex-col">
                      <div className="text-xs font-mono text-gray-500 leading-tight min-h-[2rem]">
                        {isWirelessReport(selectedReport) ? 'TOTAL APs' : 'TOTAL NODES'}
                      </div>
                      <div className="text-4xl font-tech tracking-wider text-white tabular-nums drop-shadow-md">{computedTotal}</div>
                      <div className="text-[9px] font-mono text-gray-500 mt-1 leading-tight min-h-[1.5rem]">
                        {isWirelessReport(selectedReport) ? 'access points seen' : 'hosts that answered'}
                      </div>
                    </div>
                    <div
                      className="bg-risk-critical/5 border border-risk-critical/20 rounded-lg p-4 flex flex-col"
                      title="Findings rated CRITICAL or HIGH by the single risk rule set. This number and every severity label in the exported PDF come from the same rules."
                    >
                      <div className="text-xs font-mono text-risk-critical leading-tight min-h-[2rem]">CRITICAL + HIGH FINDINGS</div>
                      <div className="text-4xl font-tech tracking-wider text-risk-critical tabular-nums drop-shadow-md">{computedSignificant}</div>
                      <div className="text-[9px] font-mono text-gray-500 mt-1 leading-tight min-h-[1.5rem]">
                        {selectedSummary.total} finding(s) in total
                        {selectedSummary.byConfidence.SUSPECTED > 0
                          ? ` - ${selectedSummary.byConfidence.SUSPECTED} suspected only`
                          : ''}
                      </div>
                    </div>

                    {/* Donut Chart / Network Area */}
                    <div className="col-span-2 bg-space-800/10 border border-space-500/20 rounded-lg p-4 flex items-center justify-between">
                      <div>
                        <div className="text-xs font-mono text-gray-500 mb-1">NETWORK LAYER</div>
                        <div className="text-lg font-mono text-white pt-1">{isWirelessReport(selectedReport) ? '802.11 / Wi-Fi' : 'LAN / Subnet'}</div>
                      </div>

                      {isWirelessReport(selectedReport) && computedTotal > 0 && (
                        <div className="relative w-16 h-16 flex items-center justify-center">
                          <svg viewBox="0 0 36 36" className="w-16 h-16 transform -rotate-90">
                            <path
                              className="text-space-600"
                              strokeDasharray="100, 100"
                              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                              fill="none" stroke="currentColor" strokeWidth="3"
                            />
                            <path
                              className="text-risk-critical"
                              strokeDasharray={`${Math.min(100, (computedTotal ? significantSubjectCount / computedTotal : 0) * 100)}, 100`}
                              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                              fill="none" stroke="currentColor" strokeWidth="3"
                            />
                          </svg>
                          <div
                            className="absolute flex items-center justify-center font-mono text-[10px] text-gray-400"
                            title="Share of access points carrying at least one HIGH or CRITICAL finding."
                          >
                            {computedTotal ? Math.round((significantSubjectCount / computedTotal) * 100) : 0}%
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Data View Tabs */}
                {/*
                  One box, one height, for all three views.

                  DATA TABLE, TACTICAL MAP and RAW JSON each render with
                  `h-full` inside the pane below, so they are the same height by
                  construction and switching tabs cannot make the page jump.
                  What was wrong was the box: a 300px floor inside a scrolling
                  column left about a third of a screen for a table of 167
                  access points and for a map you are meant to read positions
                  off.

                  Viewport-relative so it uses a large display, with a floor so
                  it stays usable on a small one. The parent scrolls, so a tall
                  pane on a short window costs a scroll rather than a clipped
                  view.
                */}
                <div className="flex-1 flex flex-col overflow-hidden">
                  {/* Fixed height: the search box renders only on the table
                      tab and is taller than the tab buttons, so the row grew
                      there and took the difference out of the pane below —
                      the three views came out 478 / 483 / 483. */}
                  <div className="flex justify-between items-end mb-2 h-10 shrink-0 border-space-500/50">
                    <div className="flex gap-2">
                      <button onClick={() => setViewMode('TABLE')} className={`px-4 py-1.5 text-xs font-tactical tracking-widest rounded-t-lg border-t border-l border-r transition-colors ${viewMode === 'TABLE' ? 'bg-[#0d1017] border-space-500/50 text-white' : 'bg-transparent border-transparent hover:bg-space-800 text-gray-500 hover:text-gray-300'}`}>DATA TABLE</button>
                      <button onClick={() => setViewMode('MAP')} className={`px-4 py-1.5 text-xs font-tactical tracking-widest rounded-t-lg border-t border-l border-r transition-colors ${viewMode === 'MAP' ? 'bg-[#0d1017] border-space-500/50 text-white' : 'bg-transparent border-transparent hover:bg-space-800 text-gray-500 hover:text-gray-300'}`}>TACTICAL MAP</button>
                      <button onClick={() => setViewMode('JSON')} className={`px-4 py-1.5 text-xs font-tactical tracking-widest rounded-t-lg border-t border-l border-r transition-colors ${viewMode === 'JSON' ? 'bg-[#0d1017] border-space-500/50 text-white' : 'bg-transparent border-transparent hover:bg-space-800 text-gray-500 hover:text-gray-300'}`}>RAW JSON</button>
                    </div>
                    {viewMode === 'TABLE' && (
                      <div className="relative mb-1 mr-1">
                        <input
                          type="text"
                          placeholder="Search targets..."
                          value={searchQuery}
                          onChange={(e) => setSearchQuery(e.target.value)}
                          className="bg-space-900/80 border border-space-500/50 rounded pl-8 pr-3 py-1.5 text-xs font-mono text-white focus:border-neon-500 focus:bg-space-900 outline-none w-48 md:w-56 lg:w-64 transition-colors shadow-sm"
                        />
                        <svg className="w-3.5 h-3.5 text-gray-500 absolute left-2.5 top-1/2 -translate-y-1/2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8" /><path d="m21 21-4.3-4.3" /></svg>
                      </div>
                    )}
                  </div>

                  <div className="flex-1 min-h-[max(520px,60vh)] border border-space-500/50 rounded-b-lg rounded-tr-lg overflow-hidden bg-[#0d1017] relative">
                    {viewMode === 'MAP' && (
                      <ReportMap report={selectedReport} focusBssid={focusBssid} />
                    )}
                    {viewMode === 'JSON' && (
                      <div className="p-4 overflow-y-auto text-xs font-mono text-neon-400/80 leading-relaxed whitespace-pre h-full custom-scrollbar">
                        {JSON.stringify(selectedReport.rawData, null, 2)}
                      </div>
                    )}
                    {viewMode === 'TABLE' && (
                      <div className="overflow-auto h-full custom-scrollbar">
                        <table className="w-full text-left text-xs font-mono text-gray-300 relative">
                          <thead className="bg-[#080b11] border-b border-space-500/50 sticky top-0 shadow-sm z-10">
                            {isWirelessReport(selectedReport) ? (
                              <tr>
                                {/*
                                  One column for the network, not two.

                                  The BSSID is the identifier and the SSID is
                                  the name, and a reader scanning the table
                                  wants them together anyway — the pairing is
                                  what identifies an access point when several
                                  share a name. Stacking them returns a whole
                                  column's width to POSITION, which is the
                                  column that was actually being squeezed.

                                  Both sorts survive: the header offers each.
                                */}
                                <th className="p-3 font-tactical text-gray-500 tracking-widest">
                                  <button
                                    onClick={() => handleSort('ssid')}
                                    className="hover:text-white transition-colors font-tactical tracking-widest"
                                    title="Sort by network name"
                                  >
                                    SSID {sortConfig?.key === 'ssid' ? (sortConfig.direction === 'asc' ? '▲' : '▼') : ''}
                                  </button>
                                  <span className="text-space-500 mx-1">/</span>
                                  <button
                                    onClick={() => handleSort('bssid')}
                                    className="hover:text-white transition-colors font-tactical tracking-widest"
                                    title="Sort by BSSID"
                                  >
                                    BSSID {sortConfig?.key === 'bssid' ? (sortConfig.direction === 'asc' ? '▲' : '▼') : ''}
                                  </button>
                                </th>
                                <th className="p-3 font-tactical text-gray-500 tracking-widest cursor-pointer hover:text-white transition-colors" onClick={() => handleSort('encryption')}>
                                  ENCRYPTION {sortConfig?.key === 'encryption' ? (sortConfig.direction === 'asc' ? '▲' : '▼') : ''}
                                </th>
                                <th className="p-3 font-tactical text-gray-500 tracking-widest text-center" title="WPS exposure. An unlocked WPS PIN yields the passphrase regardless of its strength.">
                                  WPS
                                </th>
                                <th className="p-3 font-tactical text-gray-500 tracking-widest text-center" title="Rogue / evil-twin verdict. SUSPECTED means indicators were present, not that the access point is hostile.">
                                  ROGUE
                                </th>
                                <th className="p-3 font-tactical text-gray-500 tracking-widest cursor-pointer hover:text-white transition-colors" onClick={() => handleSort('latitude')} title="Estimated position, the radius containing roughly 95% of the estimate, and the estimator that produced it. Not a surveyed location. A row marked AMBIGUOUS has a second, equally good position on the other side of the route.">
                                  POSITION (95%) {sortConfig?.key === 'latitude' ? (sortConfig.direction === 'asc' ? '▲' : '▼') : ''}
                                </th>
                                <th className="p-3 font-tactical text-gray-500 tracking-widest text-center" title="Worst severity from the single risk rule set, with the confidence attached to it.">
                                  SEVERITY
                                </th>
                                <th className="p-3 font-tactical text-gray-500 tracking-widest text-right cursor-pointer hover:text-white transition-colors" onClick={() => handleSort('rssi')}>
                                  RSSI {sortConfig?.key === 'rssi' ? (sortConfig.direction === 'asc' ? '▲' : '▼') : ''}
                                </th>
                              </tr>
                            ) : (
                              <tr>
                                <th className="p-3 font-tactical text-gray-500 tracking-widest cursor-pointer hover:text-white transition-colors" onClick={() => handleSort('ip')}>
                                  IP ADDRESS {sortConfig?.key === 'ip' ? (sortConfig.direction === 'asc' ? '▲' : '▼') : ''}
                                </th>
                                <th className="p-3 font-tactical text-gray-500 tracking-widest cursor-pointer hover:text-white transition-colors" onClick={() => handleSort('hostname')}>
                                  HOSTNAME {sortConfig?.key === 'hostname' ? (sortConfig.direction === 'asc' ? '▲' : '▼') : ''}
                                </th>
                                <th className="p-3 font-tactical text-gray-500 tracking-widest cursor-pointer hover:text-white transition-colors" onClick={() => handleSort('os')}>
                                  OS {sortConfig?.key === 'os' ? (sortConfig.direction === 'asc' ? '▲' : '▼') : ''}
                                </th>
                                <th className="p-3 font-tactical text-gray-500 tracking-widest">
                                  SERVICES
                                </th>
                                <th className="p-3 font-tactical text-gray-500 tracking-widest text-center" title="Worst severity from the single risk rule set, with the confidence attached to it.">
                                  SEVERITY
                                </th>
                                <th className="p-3 font-tactical text-gray-500 tracking-widest text-right">
                                  DETAILS
                                </th>
                              </tr>
                            )}
                          </thead>
                          <tbody className="divide-y divide-space-500/20">
                            {isWirelessReport(selectedReport) ? (
                              tableData.map((ap: any, i: number) => {
                                const sev = subjectSeverity(ap.bssid);
                                const rogue = rogueVerdictOf(ap).verdict;
                                return (
                                  <tr key={i} className="hover:bg-space-800/30 transition-colors cursor-pointer" onClick={() => { setFocusBssid(ap.bssid); setViewMode('MAP'); }}>
                                    <td className="p-3 max-w-[240px]">
                                      <div className={`font-bold truncate ${SEVERITY_ORDER[sev.severity] >= SEVERITY_ORDER.HIGH ? 'text-risk-critical' : 'text-white'}`}>
                                        {ap.ssid || '<Hidden>'}
                                      </div>
                                      {/* Never truncated: a partial MAC address
                                          identifies nothing, and this is the
                                          field a reader uses to match a row
                                          against a capture or an audit line. */}
                                      <div className="text-[10px] text-neon-400 font-mono tracking-tight mt-0.5">
                                        {ap.bssid}
                                      </div>
                                    </td>
                                    <td className="p-3">
                                      <span className={`px-2 py-0.5 rounded text-[10px] ${SEVERITY_ORDER[sev.severity] >= SEVERITY_ORDER.HIGH ? 'bg-risk-critical/20 text-risk-critical' : 'bg-space-800 text-gray-400'}`}>
                                        {ap.encryption}
                                      </span>
                                    </td>
                                    <td className="p-3 text-center">
                                      {wpsObserved(ap) ? (
                                        <span
                                          title={ap.wps_locked
                                            ? 'WPS is advertised but the access point is rate-limiting PIN attempts. Lockout behaviour varies between firmware versions.'
                                            : 'WPS is advertised without lockout. The PIN is effectively recoverable, which yields the passphrase however strong it is.'}
                                          className={`px-1.5 py-0.5 rounded text-[9px] font-tactical border ${ap.wps_locked
                                            ? 'bg-amber-400/10 text-amber-300 border-amber-400/40'
                                            : 'bg-risk-critical/15 text-risk-critical border-risk-critical/40'}`}
                                        >
                                          {ap.wps_locked ? 'LOCKED' : 'OPEN PIN'}
                                        </span>
                                      ) : (
                                        <span
                                          className="text-gray-600 text-[9px] font-tactical"
                                          title="WPS was not measured for this access point. The WPS scan is a separate operation from the survey, so this is an absent measurement, not an access point confirmed to have WPS disabled."
                                        >
                                          not measured
                                        </span>
                                      )}
                                    </td>
                                    <td className="p-3 text-center">
                                      {rogue && rogue !== 'CLEAR' ? (
                                        <span
                                          title="Rogue-AP indicators were observed. SUSPECTED is not an accusation: transition-mode, mesh and hotspot deployments produce the same pattern. See the PDF's rogue-AP section for the indicator reasons."
                                          className={`px-1.5 py-0.5 rounded text-[9px] font-tactical border ${rogue === 'CONFIRMED'
                                            ? 'bg-risk-critical/20 text-risk-critical border-risk-critical/50'
                                            : 'bg-amber-400/10 text-amber-300 border-amber-400/40'}`}
                                        >
                                          {rogue}
                                        </span>
                                      ) : (
                                        <span className="text-gray-600">-</span>
                                      )}
                                    </td>
                                    <td className="p-3 text-[10px]">
                                      {typeof ap.latitude === 'number' && typeof ap.longitude === 'number' ? (
                                        <span
                                          className="text-gray-300"
                                          title={[
                                            `${locationMethodLabel(ap.location_method)} (confidence figure ${formatLocationConfidence(ap.location_confidence)}, derived from the radius below - not a probability).`,
                                            `Uncertainty: ${formatErrorRadius(ap.location_error_m)}, the radius containing roughly 95% of the posterior.`,
                                            locationMethodNote(ap.location_method),
                                            ...positionCaveats(ap),
                                          ].join('\n\n')}
                                        >
                                          {formatCoord(ap.latitude, ap.longitude)}
                                          {/* The radius belongs with the coordinate, not in a tooltip.
                                              A lat/lon with no stated uncertainty reads as a surveyed fix. */}
                                          <span className={`block ${finiteNumber(ap.location_error_m) === null ? 'text-amber-400/80' : 'text-gray-400'}`}>
                                            {formatErrorRadius(ap.location_error_m)}
                                          </span>
                                          <span className="block text-gray-500">
                                            {locationMethodLabel(ap.location_method)} / {formatLocationConfidence(ap.location_confidence)}
                                          </span>
                                          {isMirrorAmbiguous(ap) && (
                                            <span className="mt-1 block">
                                              <span
                                                className="inline-block px-1.5 py-0.5 rounded text-[9px] font-tactical border bg-amber-400/10 text-amber-300 border-amber-400/40"
                                                title="The route past this access point was effectively a straight line, so the measurements fit a position on either side of it equally well. Which side is correct cannot be determined from this data. Re-driving with at least one turn in the route resolves it."
                                              >
                                                {AMBIGUOUS_FLAG}
                                              </span>
                                              <span className="mt-0.5 block text-[9px] text-amber-200/80 leading-snug">
                                                1 of 2 candidates
                                                {apMirror(ap)
                                                  ? `, other at ${formatCoord(apMirror(ap)!.lat, apMirror(ap)!.lon)} (${formatMetres(apMirror(ap)!.distanceM)} apart)`
                                                  : ' - the alternative was not recorded'}
                                              </span>
                                            </span>
                                          )}
                                          {/* The estimator writes its caveats for the reader; show them. */}
                                          {locationNotesOf(ap).length > 0 && (
                                            <span className="mt-1 block text-[9px] text-gray-500 leading-snug">
                                              {locationNotesOf(ap).map((note, n) => (
                                                <span key={n} className="block">- {note}</span>
                                              ))}
                                            </span>
                                          )}
                                        </span>
                                      ) : (
                                        <span className="text-gray-600" title="Detected without a usable GPS fix. It was seen; it simply cannot be placed on a map.">no fix</span>
                                      )}
                                    </td>
                                    <td className="p-3 text-center">
                                      <span
                                        title={sev.confidence
                                          ? `Severity ${sev.severity} at ${sev.confidence} confidence. Severity is how serious the issue would be; confidence is how sure this tool is that it is real.`
                                          : 'No finding was raised against this access point by the risk rule set.'}
                                        className={`px-1.5 py-0.5 rounded text-[9px] font-tactical border ${severityClasses(sev.severity).chip}`}
                                      >
                                        {sev.severity}{sev.confidence ? ` / ${sev.confidence.slice(0, 4)}` : ''}
                                      </span>
                                    </td>
                                    <td className={`p-3 text-right font-tech tabular-nums tracking-wider ${getSignalColor(ap.rssi)}`}>{ap.rssi} dBm</td>
                                  </tr>
                                );
                              })
                            ) : (
                              tableData.map((h: any, i: number) => (
                                <tr key={i} className="hover:bg-space-800/30 transition-colors">
                                  <td className="p-3 text-neon-400 font-mono tracking-tight">{h.ip}</td>
                                  <td className="p-3 text-white truncate max-w-[200px]">{h.hostname || '<Unknown>'}</td>
                                  <td className="p-3 text-gray-400 truncate max-w-[150px]" title={h.os}>{h.os || '<Unknown>'}</td>
                                  <td className="p-3">
                                    <div className="flex flex-wrap gap-1 max-w-[150px]">
                                      {(h.open_ports || []).slice(0, 3).map((p: any, portIdx: number) => (
                                        <span key={portIdx} className="px-1.5 py-0.5 bg-space-800 text-gray-300 rounded text-[9px] font-mono border border-space-500/30">
                                          {p.port}
                                        </span>
                                      ))}
                                      {(h.open_ports || []).length > 3 && (
                                        <span className="px-1.5 py-0.5 bg-space-800 text-gray-500 rounded text-[9px] font-mono border border-space-500/10">
                                          +{(h.open_ports.length - 3)}
                                        </span>
                                      )}
                                    </div>
                                  </td>
                                  <td className="p-3 text-center">
                                    {(() => {
                                      const sev = subjectSeverity(h.ip);
                                      return (
                                        <span
                                          title={sev.confidence
                                            ? `Severity ${sev.severity} at ${sev.confidence} confidence, from the single risk rule set. This replaces a filter on a risk_score column that nothing ever wrote, which made this count permanently zero.`
                                            : 'No finding was raised against this host by the risk rule set.'}
                                          className={`px-1.5 py-0.5 rounded text-[9px] font-tactical border ${severityClasses(sev.severity).chip}`}
                                        >
                                          {sev.severity}{sev.confidence ? ` / ${sev.confidence.slice(0, 4)}` : ''}
                                        </span>
                                      );
                                    })()}
                                  </td>
                                  <td className="p-3 text-right">
                                    <div className="flex flex-col items-end gap-1">
                                      {(h.snmp_communities || []).length > 0 && (
                                        <span className="text-[9px] text-amber-400 bg-amber-400/10 px-1.5 rounded border border-amber-400/20">SNMP DISCOVERED</span>
                                      )}
                                      {credentialsOf(selectedReport).some((c: any) => c && String(c.target_ip) === String(h.ip)) && (
                                        <span className="text-[9px] text-risk-critical bg-risk-critical/10 px-1.5 rounded border border-risk-critical/20 animate-pulse">CREDENTIALS RECOVERED</span>
                                      )}
                                    </div>
                                  </td>
                                </tr>
                              ))
                            )}
                            {tableData.length === 0 && (
                              <tr>
                                <td colSpan={10} className="p-10 text-center text-gray-600 font-mono italic">No targets matching your criteria.</td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="h-full flex flex-col items-center justify-center p-10 text-center">
              <img src="/cat-intel-archive.svg" alt="No Archive Selected" className="w-24 h-24 opacity-40 mb-6" />
              <h3 className="text-xl font-tactical text-gray-500 tracking-widest mb-2">NO ARCHIVE SELECTED</h3>
              <p className="text-sm font-mono text-gray-600 max-w-sm">Select a classified report from the index on the left to view detailed tactical telemetry and raw data dumps.</p>
            </div>
          )}
        </div>
      </div>

      {/* TACTICAL NOTIFICATION TOAST */}
      <AnimatePresence>
        {notification.show && (
          <motion.div
            initial={{ opacity: 0, y: 50, x: 50 }}
            animate={{ opacity: 1, y: 0, x: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 20 }}
            onClick={() => {
              if (notification.onClickAction) {
                notification.onClickAction();
                setNotification(prev => ({ ...prev, show: false }));
              }
            }}
            className={`fixed bottom-6 right-6 z-50 flex items-center gap-3 px-4 py-3 rounded border shadow-lg backdrop-blur-md ${notification.onClickAction ? 'cursor-pointer hover:scale-105 transition-all' : ''} ${notification.type === 'success' ? 'bg-signal-strong/20 border-signal-strong/50' :
                notification.type === 'error' ? 'bg-risk-critical/20 border-risk-critical/50' :
                  'bg-space-800/80 border-space-500/50'
              }`}
          >
            {notification.type === 'success' ? (
              <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5 text-signal-strong" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
            ) : notification.type === 'error' ? (
              <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5 text-risk-critical" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>
            ) : (
              <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5 text-neon-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
            )}
            <div className="flex flex-col">
              <span className={`text-[10px] font-tactical tracking-widest ${notification.type === 'success' ? 'text-signal-strong' :
                  notification.type === 'error' ? 'text-risk-critical' : 'text-neon-400'
                }`}>
                SYSTEM MESSAGE
              </span>
              <span className="text-sm font-mono text-white">{notification.message}</span>
            </div>
            <button onClick={(e) => { e.stopPropagation(); setNotification(prev => ({ ...prev, show: false })); }} className="ml-4 text-gray-500 hover:text-white transition-colors">
              <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* PDF PREVIEW MODAL */}
      <AnimatePresence>
        {previewPdfUrl && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[100] bg-space-900/90 backdrop-blur-sm flex items-center justify-center p-4 md:p-8"
          >
            <div className="bg-space-800 border border-space-500/50 shadow-2xl rounded-lg w-full h-full max-w-6xl flex flex-col overflow-hidden relative">
              <div className="flex items-center justify-between px-4 py-3 border-b border-space-500/30 bg-space-900/50">
                <div className="flex items-center gap-2">
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5 text-signal-strong" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                  <span className="text-white font-tactical tracking-wider text-sm">PDF REPORT PREVIEW</span>
                </div>
                <button onClick={() => setPreviewPdfUrl(null)} className="text-gray-400 hover:text-risk-critical transition-colors bg-space-700/50 hover:bg-risk-critical/20 rounded p-1">
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                </button>
              </div>
              <div className="flex-1 w-full bg-white relative">
                <iframe src={previewPdfUrl} className="w-full h-full border-none" title="PDF Preview" />
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
