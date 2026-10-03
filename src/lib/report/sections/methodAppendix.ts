/**
 * LOCKON EWAC — the report's method and limitations appendix.
 *
 * The largest single section of the document, and the one that decides whether
 * the rest of it is evidence. Every severity above it is a label; this is where
 * a reader finds the rule that produced the label, the vintage of the CVE data
 * behind it, which estimator placed a coordinate on the map, and — the part
 * that is easy to leave out — what this hardware was *unable* to test.
 *
 * That last part is the reason the section is this long. A capture that could
 * not run, a CVE list that is three years old and a monitor mode that could not
 * be confirmed are each indistinguishable from a clean result unless the
 * document says so in its own words. The appendix says so.
 *
 * Moved out of `buildAndSavePDF` verbatim, by script rather than by hand:
 * retyping 450 lines of report prose is how a refactor quietly changes what a
 * document claims. `pdfdiff` confirmed the output is unchanged, string for
 * string.
 */
import autoTable from 'jspdf-autotable';
import { describeLocalizationMethodology, radiusToConfidence } from '../../localization';
import { LOCATION_METHOD_LABEL, LOCATION_METHOD_NOTE, SEVERITY_RGB, ascii } from '../archive';
import type { Severity } from '../../riskEngine';
import type { ReportData } from '../assemble';
import { TABLE_MARGIN } from '../geometry';
import type { PdfLayout } from '../layout';

/**
 * Write the appendix onto the document.
 *
 * Takes the whole `ReportData` rather than a narrowed set of fields on purpose:
 * this section reads from nearly every part of it, and a parameter list that
 * tracked exactly which parts would have to change every time a sentence in the
 * appendix starts citing one more thing.
 */
export function renderMethodAppendix(layout: PdfLayout, data: ReportData): void {
  const { doc, tocEntries, fit, sectionHeading, paragraph, callout } = layout;
  const {
    activeScope, allSimulated, anySimulated, appVersion, capabilities, cveData,
    engineMethodology, engineVersion, evidenceRows, evilTwinMethod, gatedCommands, methodology,
    reportsArray, simulatedReports,
  } = data;

  // This is what makes every severity above auditable. A label a reader cannot
  // trace to a rule is not evidence.
  doc.addPage();
  tocEntries.push({ title: 'APPENDIX: METHOD AND LIMITATIONS', page: (doc as any).internal.getNumberOfPages() });
  let appY = sectionHeading('APPENDIX: METHOD AND LIMITATIONS');

  appY = paragraph(
    'Everything below travels with the document on purpose. A severity that cannot be traced back to a rule, a CVE finding with no data vintage, and a capture that could not run are all indistinguishable from a clean result unless they are stated.',
    appY, { size: 9.5 }
  );
  appY += 4;

  // -- Versions --
  autoTable(doc, {
    startY: appY,
    head: [['TOOLING AND RULE SET', '']],
    body: [
      ['Application version', ascii(appVersion || 'not stamped into this build')],
      ['Engine version', ascii(engineVersion || 'engine not reachable at export time')],
      ['Engine platform', ascii(engineMethodology?.platform || 'not reported')],
      ['Risk rule set', `${methodology.id} version ${methodology.version}`],
      // Named explicitly so a reader can see the boundary's shape rather than
      // inferring it from the word "offensive".
      ['Scope-gated commands', gatedCommands.length > 0
        ? ascii(gatedCommands.join(', '))
        : 'engine not reachable at export time; the gated set could not be read'],
      ['Rogue-AP rule set', evilTwinMethod?.name
        ? ascii(`${evilTwinMethod.name} version ${evilTwinMethod.version ?? '?'}`)
        : 'engine not reachable at export time; the rogue-AP verdicts above were read from the archived observations'],
      ['Report generated', new Date().toISOString()],
      ['Archives consolidated', String(reportsArray.length)],
    ],
    theme: 'grid',
    headStyles: { fillColor: [15, 23, 42], textColor: 255, fontStyle: 'bold', fontSize: 8.5 },
    styles: { fontSize: 8.5, cellPadding: 2.2, overflow: 'linebreak', textColor: [0, 0, 0] },
    columnStyles: { 0: { cellWidth: 48, fontStyle: 'bold' } },
    margin: TABLE_MARGIN,
  });
  appY = (doc as any).lastAutoTable.finalY + 8;

  // -- Severity bands --
  appY = fit(appY, 20);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(0, 0, 0);
  doc.text('SEVERITY SCALE', layout.left(), appY);
  appY += 4;

  autoTable(doc, {
    startY: appY,
    head: [['Level', 'Score range (0-100)']],
    body: methodology.bands.map((band, idx) => {
      const upper = idx === 0 ? 100 : methodology.bands[idx - 1].min - 1;
      return [band.level, `${band.min} - ${upper}`];
    }),
    theme: 'grid',
    headStyles: { fillColor: [30, 41, 59], textColor: 255, fontSize: 8 },
    styles: { fontSize: 8.5, cellPadding: 2, textColor: [0, 0, 0] },
    columnStyles: { 0: { cellWidth: 30, fontStyle: 'bold' }, 1: { cellWidth: 40, font: 'courier' } },
    margin: TABLE_MARGIN,
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 0) {
        const level = data.cell.text[0] as Severity;
        if (SEVERITY_RGB[level]) data.cell.styles.textColor = SEVERITY_RGB[level];
      }
    }
  });
  appY = (doc as any).lastAutoTable.finalY + 8;

  // -- Rule scores --
  appY = fit(appY, 20);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(0, 0, 0);
  doc.text('RULE SCORES', layout.left(), appY);
  appY += 4;

  const ruleRows: string[][] = [];
  for (const [key, value] of Object.entries(methodology.rules.encryption)) {
    ruleRows.push(['encryption', key, String(value.score), value.level]);
  }
  for (const [key, value] of Object.entries(methodology.rules.wps)) {
    ruleRows.push(['wps', key, String(value), '']);
  }
  for (const [key, value] of Object.entries(methodology.rules.rogue_ap)) {
    ruleRows.push(['rogue_ap', key, String(value), '']);
  }
  for (const [key, value] of Object.entries(methodology.rules.exposed_service)) {
    ruleRows.push(['exposed_service', `port ${key} (${value.name})`, String(value.score), '']);
  }
  for (const [key, value] of Object.entries(methodology.rules.service_cve)) {
    ruleRows.push(['service_cve', `CVE rated ${key}`, String(value), '']);
  }
  for (const [key, value] of Object.entries(methodology.rules.credentials)) {
    ruleRows.push(['credentials', key, String(value), '']);
  }
  for (const [key, value] of Object.entries(methodology.rules.snmp)) {
    ruleRows.push(['snmp', key, String(value), '']);
  }
  // The level column is only filled where the rule set states it; derive the rest
  // from the bands so every row can be checked.
  for (const row of ruleRows) {
    if (!row[3]) {
      const score = Number(row[2]);
      row[3] = methodology.bands.find(b => score >= b.min)?.level ?? 'INFO';
    }
  }

  autoTable(doc, {
    startY: appY,
    head: [['Rule', 'Condition', 'Score', 'Level']],
    body: ruleRows,
    theme: 'grid',
    headStyles: { fillColor: [30, 41, 59], textColor: 255, fontSize: 8 },
    styles: { fontSize: 7.5, cellPadding: 1.6, textColor: [0, 0, 0], overflow: 'linebreak' },
    columnStyles: {
      0: { cellWidth: 34, font: 'courier' },
      1: { cellWidth: 60 },
      2: { cellWidth: 16, halign: 'center', font: 'courier' },
      3: { cellWidth: 24, halign: 'center', fontStyle: 'bold' },
    },
    margin: TABLE_MARGIN,
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 3) {
        const level = data.cell.text[0] as Severity;
        if (SEVERITY_RGB[level]) data.cell.styles.textColor = SEVERITY_RGB[level];
      }
    }
  });
  appY = (doc as any).lastAutoTable.finalY + 8;

  // -- Confidence definitions --
  appY = fit(appY, 20);
  autoTable(doc, {
    startY: appY,
    head: [['CONFIDENCE', 'MEANING IN THIS DOCUMENT']],
    body: Object.entries(methodology.confidence_meaning).map(([k, v]) => [k, ascii(v)]),
    theme: 'grid',
    headStyles: { fillColor: [15, 23, 42], textColor: 255, fontStyle: 'bold', fontSize: 8.5 },
    styles: { fontSize: 8.5, cellPadding: 2.2, overflow: 'linebreak', textColor: [0, 0, 0] },
    columnStyles: { 0: { cellWidth: 32, fontStyle: 'bold' } },
    margin: TABLE_MARGIN,
  });
  appY = (doc as any).lastAutoTable.finalY + 8;

  // -- Evil twin methodology --
  appY = fit(appY, 20);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(0, 0, 0);
  doc.text('ROGUE AP / EVIL TWIN METHODOLOGY', layout.left(), appY);
  appY += 5;

  if (evilTwinMethod) {
    const thresholds = evilTwinMethod.thresholds ?? {};
    appY = paragraph(
      ascii(
        `Access points sharing a non-hidden SSID are grouped, and each is scored for how far it deviates from the rest of its group. Indicator weights are summed; the verdict thresholds are `
        + Object.entries(thresholds).map(([k, v]) => `${k} at ${v}`).join(', ')
        + `. An access point is reported as an evil twin at ${evilTwinMethod.reported_as_evil_twin_at ?? 'LIKELY'} or above. Indicator weights used in this build: `
        + Object.entries(evilTwinMethod.weights ?? {}).map(([k, v]) => `${k}=${v}`).join(', ') + '.'
      ),
      appY, { size: 8.5 }
    );
    appY += 3;

    if (evilTwinMethod.legitimate_encryption_pairs?.length) {
      appY = paragraph(
        ascii(`Encryption combinations treated as legitimate and scored at zero: ${evilTwinMethod.legitimate_encryption_pairs.map(pair => pair.join(' + ')).join('; ')}. These are normal transition and mixed-mode deployments and must not be reported as rogue activity.`),
        appY, { size: 8.5, color: [80, 80, 80] }
      );
      appY += 3;
    }

    const limits = evilTwinMethod.limitations ?? [];
    if (limits.length) {
      appY = paragraph('Stated limitations of this detection:', appY, { size: 8.5, bold: true, color: [0, 0, 0] });
      appY += 1;
      for (const limit of limits) {
        appY = paragraph(ascii(`- ${limit}`), appY, { size: 8.5, color: [80, 80, 80] });
      }
      appY += 3;
    }
  } else {
    appY = paragraph(
      'The engine was not reachable when this report was generated, so its rogue-AP indicator weights and thresholds could not be printed here. The verdicts in the rogue-AP section were read from the archived observations as recorded at scan time. A reader who needs the exact weights should re-export with the engine running.',
      appY, { size: 8.5, color: [161, 98, 7] }
    );
    appY += 3;
    appY = paragraph(
      'What can be stated without the engine: the analysis is beacon-only, with no client-side or over-the-air authentication check; WPA2/WPA3 transition mode and legacy mixed mode are treated as legitimate; a clone that matches vendor, channel and signal profile can score below the reporting threshold; and hidden or blank SSIDs are excluded from twin grouping entirely.',
      appY, { size: 8.5, color: [80, 80, 80] }
    );
    appY += 3;
  }

  // -- Position estimation --
  appY = fit(appY, 20);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(0, 0, 0);
  doc.text('POSITION ESTIMATION', layout.left(), appY);
  appY += 5;
  appY = paragraph(
    'No coordinate in this document is a surveyed position. An access point is never observed directly: what is recorded is where the operator was and how strong the signal was there, and a position is inferred from that. The estimators used in this build are:',
    appY, { size: 8.5 }
  );
  appY += 2;
  for (const key of Object.keys(LOCATION_METHOD_LABEL)) {
    appY = paragraph(ascii(`- ${LOCATION_METHOD_LABEL[key]}: ${LOCATION_METHOD_NOTE[key]}`), appY, { size: 8, color: [80, 80, 80] });
  }
  appY += 2;
  appY = paragraph(
    'Each access point row states which estimator produced its position, the radius containing roughly 95% of the posterior for that position, and a display confidence figure. The radius is the number to read. The confidence figure is derived from it and is not a probability.',
    appY, { size: 8.5, color: [80, 80, 80] }
  );
  appY += 4;

  // -- The model behind every radius in this document --
  const loc = describeLocalizationMethodology();
  appY = fit(appY, 20);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(0, 0, 0);
  doc.text('SIGNAL MODEL AND UNCERTAINTY', layout.left(), appY);
  appY += 5;
  appY = paragraph(
    'Range is inferred from received power using a log-distance path loss model. Its constants, which every radius in this document depends on, are:',
    appY, { size: 8.5 }
  );
  appY += 1;
  for (const line of [
    `Reference power at 1 m, 2.4 GHz: ${loc.reference_power_2g4_dbm} dBm`,
    `Path loss exponent: ${loc.path_loss_exponent}`,
    `Shadowing sigma: ${loc.shadowing_sigma_db} dB`,
    `Band correction: ${loc.band_correction}`,
    `Route is treated as a line, and the position as mirror-ambiguous, below a cross-track / along-track ratio of ${loc.linearity_ambiguous_below}.`,
    `Error radius: ${loc.error_radius_meaning}`,
    'Confidence figure: a display value derived from the error radius alone, clamped to 1-99. It is not a probability.',
  ]) {
    appY = paragraph(ascii(`- ${line}`), appY, { size: 8, color: [80, 80, 80], lead: 3.4 });
  }
  appY += 2;
  appY = paragraph(
    ascii(
      'Every confidence figure in this document can therefore be read back as a distance. The mapping below was produced by calling the same function that generated those figures, so it is exact for this build:'
    ),
    appY, { size: 8, color: [80, 80, 80], lead: 3.4 }
  );
  appY += 1;
  appY = paragraph(
    ascii('   ' + [2, 5, 10, 25, 50, 100, 250, 500]
      .map(r => `${r} m -> ${radiusToConfidence(r)}`).join('     ')),
    appY, { size: 8, color: [80, 80, 80], lead: 3.4 }
  );
  appY = paragraph(
    ascii('Two positions with the same figure are not equally likely to be correct; they merely have the same radius. Where a position is mirror-ambiguous the radius covers both candidates, so the figure is low by design and must not be read as a poor measurement.'),
    appY, { size: 8, color: [80, 80, 80], lead: 3.4 }
  );
  appY += 3;

  appY = fit(appY, 18);
  appY = paragraph(
    ascii(
      'Gaussian-process regression, specifically: it smooths the measured signal field over the surveyed track and reports the location of the modelled maximum. That maximum lies on or near the path the operator drove by construction, because that is where the measurements are - the method has no information about anywhere else and cannot place a transmitter off the route. It is a description of the signal field, not a transmitter fix, and where the engine returns one it also returns an error radius, the distance to the nearest measurement and its own notes, which are carried into this document.'
    ),
    appY, { size: 8.5, color: [80, 80, 80] }
  );
  appY += 3;

  appY = fit(appY, 18);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(0, 0, 0);
  doc.text('LIMITATIONS OF THESE POSITIONS', layout.left(), appY);
  appY += 5;
  for (const limitation of loc.limitations) {
    appY = paragraph(ascii(`- ${limitation}`), appY, { size: 8, color: [80, 80, 80], lead: 3.4 });
  }
  appY += 4;

  // -- CVE data vintage --
  appY = fit(appY, 20);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(0, 0, 0);
  doc.text('CVE DATA VINTAGE', layout.left(), appY);
  appY += 5;

  if (cveData) {
    const ageDays = cveData.age_days ?? null;
    const stale = !!cveData.stale;
    appY = callout(
      appY,
      stale ? 'CVE DATA IS STALE - FINDINGS REFLECT AN OLD VINTAGE' : 'CVE DATA VINTAGE',
      ascii(
        `The CVE matches in this document were produced against a data set generated ${cveData.generated_at ?? 'at an unrecorded time'}`
        + (ageDays !== null ? `, which was ${ageDays} day(s) old when this report was generated` : '')
        + `. It holds ${cveData.entry_count ?? 'an unrecorded number of'} entr(ies)`
        + (cveData.source ? ` and came from ${cveData.source}` : '') + '. '
        + (cveData.coverage_note ? `${cveData.coverage_note} ` : '')
        + 'Findings therefore reflect that vintage and nothing later: a vulnerability published after that date cannot appear in this report, however serious it is, and an entry later withdrawn or rescored may still appear here. '
        + (stale
          ? 'This data set is past its freshness threshold. Update it and re-run before treating the absence of a CVE finding as meaningful.'
          : 'Re-run against updated data before treating the absence of a CVE finding as meaningful.')
      ),
      stale ? [254, 242, 242] : [239, 246, 255],
      stale ? [220, 38, 38] : [37, 99, 235],
      stale ? [220, 38, 38] : [37, 99, 235]
    );
  } else {
    appY = callout(
      appY,
      'CVE DATA VINTAGE UNKNOWN',
      'The age and provenance of the CVE data could not be established when this report was generated, because the engine was not reachable and no vintage was cached. Any CVE finding in this document is therefore of unknown vintage and the absence of a CVE finding says nothing at all. Re-export with the engine running to record the vintage.',
      [254, 252, 232], [234, 179, 8], [161, 98, 7]
    );
  }

  // -- Hardware capability --
  appY = fit(appY, 20);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(0, 0, 0);
  doc.text('ADAPTER AND HARDWARE CAPABILITY', layout.left(), appY);
  appY += 5;

  if (capabilities) {
    const caps = capabilities as any;
    const monitorSupported = caps.monitor_mode?.supported;
    const yesNo = (value: unknown) =>
      value === true ? 'YES' : value === false ? 'NO' : 'UNKNOWN';

    autoTable(doc, {
      startY: appY,
      head: [['CAPABILITY PROBE (at export time)', '']],
      body: [
        ['Platform', ascii(`${caps.platform ?? 'unknown'}${caps.platform_release ? ` ${caps.platform_release}` : ''}`)],
        ['Running elevated', yesNo(caps.elevated)],
        ['Packet library (scapy)', ascii(caps.scapy?.available ? `available${caps.scapy.version ? ` ${caps.scapy.version}` : ''}` : `NOT AVAILABLE${caps.scapy?.error ? ` - ${caps.scapy.error}` : ''}`)],
        ['Capture driver (Npcap)', ascii(caps.npcap?.available === true ? 'present' : caps.npcap?.available === false ? 'NOT PRESENT' : 'UNKNOWN')],
        ['Raw socket', yesNo(caps.raw_socket?.available)],
        ['Monitor mode', ascii(monitorSupported === true ? 'supported'
          : monitorSupported === false ? 'NOT SUPPORTED'
            : `UNKNOWN - could not be determined${caps.monitor_mode?.reason ? ` (${caps.monitor_mode.reason})` : ''}`)],
        ['Interfaces seen', ascii(Array.isArray(caps.interfaces) && caps.interfaces.length
          ? caps.interfaces.map((i: any) => i.name).join(', ')
          : 'none reported')],
        ['Probe summary', ascii(caps.summary ?? 'not reported')],
      ],
      theme: 'grid',
      headStyles: { fillColor: [15, 23, 42], textColor: 255, fontStyle: 'bold', fontSize: 8.5 },
      styles: { fontSize: 8.5, cellPadding: 2.2, overflow: 'linebreak', textColor: [0, 0, 0] },
      columnStyles: { 0: { cellWidth: 48, fontStyle: 'bold' } },
      margin: TABLE_MARGIN,
      didParseCell: (data) => {
        if (data.section !== 'body' || data.column.index !== 1) return;
        const text = data.cell.text.join(' ');
        if (/NOT AVAILABLE|NOT PRESENT|NOT SUPPORTED/.test(text)) {
          data.cell.styles.textColor = [220, 38, 38];
          data.cell.styles.fontStyle = 'bold';
        } else if (/UNKNOWN/.test(text)) {
          data.cell.styles.textColor = [161, 98, 7];
          data.cell.styles.fontStyle = 'bold';
        }
      }
    });
    appY = (doc as any).lastAutoTable.finalY + 8;

    const unavailable: string[] = Array.isArray(caps.unavailable_features) ? caps.unavailable_features : [];
    if (unavailable.length > 0) {
      const features = caps.features && typeof caps.features === 'object' ? caps.features : {};
      appY = callout(
        appY,
        `${unavailable.length} 802.11 FEATURE(S) WERE UNAVAILABLE - A COVERAGE LIMITATION`,
        ascii(
          'The following capabilities could not run on this rig during this engagement: '
          + unavailable.map(name => {
            const requires = features[name]?.requires;
            return `${name}${requires ? ` (requires ${requires})` : ''}`;
          }).join('; ')
          + '. A test that could not be performed produces a result indistinguishable from a clean one, so read every absence in this document against this list. It is a limit of the equipment and privilege level, not evidence that the targets are secure.'
        ),
        [254, 252, 232], [234, 179, 8], [161, 98, 7]
      );
    } else {
      appY = paragraph(
        'Every 802.11 capability this build probes for was available on this rig, so no finding in this document is limited by adapter capability.',
        appY, { size: 8.5, color: [13, 148, 136] }
      );
      appY += 3;
    }

    if (monitorSupported === null || monitorSupported === undefined) {
      appY = paragraph(
        ascii(`Monitor-mode support could not be determined on this platform${caps.monitor_mode?.reason ? ` (${caps.monitor_mode.reason})` : ''}, and is reported as unknown rather than guessed. Anything that depends on frame capture - handshake capture, PMKID capture, client association observation - may therefore have been silently unable to run.`),
        appY, { size: 8.5, color: [161, 98, 7] }
      );
      appY += 3;
    }
  } else {
    appY = callout(
      appY,
      'HARDWARE CAPABILITY NOT RECORDED',
      'No capability probe was available when this report was generated, so this document cannot state which 802.11 features the rig could actually exercise. Any absence of a capture-based finding is therefore unexplained: it may mean the target was sound, or it may mean the adapter could never have produced the result. Re-export with the engine running to record the capability report.',
      [254, 252, 232], [234, 179, 8], [161, 98, 7]
    );
  }

  // -- What this assessment did not cover --
  appY = fit(appY, 20);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(0, 0, 0);
  doc.text('WHAT THIS ASSESSMENT DID NOT COVER', layout.left(), appY);
  appY += 5;

  const notCovered: string[] = [
    ...methodology.limitations,
    evidenceRows.length > 0
      ? ascii(`No passphrase was cracked and no encrypted traffic was decrypted as part of producing this document; where a handshake or PMKID was captured, that is recorded as evidence and not as a compromise. The ${evidenceRows.length} artifact(s) behind that statement are listed with their SHA-256 digests in the evidence register.`)
      : 'No passphrase was cracked and no encrypted traffic was decrypted as part of producing this document. No capture artifact is recorded against this installation either, so nothing in this document rests on one.',
    'Wired infrastructure, cloud services, physical security, social engineering and application-layer testing were all out of scope.',
    'Client devices were observed passively only. Probe requests indicate presence; they are not evidence of a connection, and a randomised MAC address is not a stable device identity.',
    'Anything outside the surveyed area and the observation window was not assessed. See the survey coverage section for the extent that was.',
    'Access points that were switched off, out of range, or not beaconing during the survey do not appear anywhere in this document.',
    'Severity here is a property of what is observable over the radio and the network. It does not account for the value of the asset behind an access point, nor for compensating controls that are invisible from outside.',
    // The boundary's shape, stated plainly. A reader who assumes the scope
    // gated everything would draw a stronger conclusion from the audit trail
    // than it supports.
    gatedCommands.length > 0
      ? `The engagement scope is enforced on the commands that can disrupt a network, authenticate against it, or intercept its traffic — in this build: ${gatedCommands.join(', ')}. Reconnaissance and capture commands (port sweeps, service inspection, SMB and TLS enumeration, traceroute, directory enumeration, handshake and PMKID capture) are not gated, so the audit trail does not record an authorization decision for them. They still emit packets. Read the audit trail as evidence about the gated set, not as a complete log of everything the tool did.`
      : 'The engine was not reachable at export time, so this document cannot state which commands the engagement scope was enforced on. Do not read the audit trail as covering every command until that is established.',
    'Passive observation is not restricted by the engagement scope at all, and findings are not filtered by it. An access point belonging to a neighbouring tenant can therefore appear in this report. Nothing in this document marks a finding as in or out of scope; the authorized-target list above is what the scope covered, not a statement about which findings fall inside it.',
  ];
  if (anySimulated) {
    notCovered.unshift(
      allSimulated
        ? 'Every operation in this report came from the hardware simulator. Nothing in it is field-verified and nothing in it evidences real exposure.'
        : `${simulatedReports.length} of the ${reportsArray.length} operations in this report came from the hardware simulator and are not field-verified.`
    );
  }
  if (!activeScope) {
    notCovered.unshift('No engagement scope record existed at export time, so this document carries no authorization evidence of its own.');
  }
  for (const item of notCovered) {
    appY = paragraph(ascii(`- ${item}`), appY, { size: 8.5, color: [80, 80, 80] });
  }
  appY += 3;

  appY = fit(appY, 16);
  appY = paragraph(
    'INTEGRITY OF THIS FILE: a digest cannot appear inside the bytes it measures. The short digest stamped on the cover and in the page footers is the SHA-256 of this document as built, before that stamp was applied. The digest of the file as delivered is computed after stamping and recorded in the local archive against this report id, where the application displays it in full; that recorded value is the one to verify a received copy against.',
    appY, { size: 8.5, color: [37, 99, 235] }
  );
}
