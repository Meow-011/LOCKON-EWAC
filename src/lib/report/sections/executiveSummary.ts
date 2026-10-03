/**
 * Section 3 of the report: the executive summary.
 *
 * Moved out of `buildAndSavePDF` verbatim: the body below is the code that was
 * inline, unchanged. The only edits are the values it now takes as parameters
 * instead of reading them from the closure, and `npm run test:export` was run
 * before and after to confirm the document says exactly what it said.
 */
import autoTable from 'jspdf-autotable';

import { ascii, isWirelessReport } from '../archive';
import { SEVERITY_ORDER, type Severity } from '../../riskEngine';
import { SEVERITY_RGB } from '../../severityStyle';
import { geometry, TABLE_MARGIN } from '../geometry';
import type { ReportData } from '../assemble';
import type { PdfLayout } from '../layout';

export interface ExecutiveSummaryOptions {
  /** The document's own identifier, as the cover prints it. */
  reportIdStr: string;
  /**
   * Whether recovered credentials are being exported in the clear.
   *
   * A property of this export rather than of the data, so it is a parameter: the
   * same archive exports masked or disclosed depending on what the operator
   * chose, and the summary has to say which the reader is holding.
   */
  discloseCredentials: boolean;
}

export function renderExecutiveSummary(
  layout: PdfLayout,
  data: ReportData,
  { reportIdStr, discloseCredentials }: ExecutiveSummaryOptions,
): void {
  const { doc, tocEntries, fit, paragraph, callout } = layout;
  const {
    reportsArray, isMulti, simulatedReports, fieldReports, anySimulated, allSimulated,
    isMixedProvenance, allFindings, overall, totalAPs, totalNodes, allCredentials,
    findingsDbError, methodology,
  } = data;
      // --- 3. EXECUTIVE SUMMARY PAGE ---
      doc.addPage();
      tocEntries.push({ title: 'EXECUTIVE SUMMARY', page: (doc as any).internal.getNumberOfPages() });

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(22);
      doc.setTextColor(0, 0, 0);
      doc.text('EXECUTIVE SUMMARY', 14, 25);

      // THREAT LEVEL BADGE REMOVED
      // "Critical" now means the rule set said so, at CRITICAL or HIGH.
      const hasCritical = overall.significant > 0 || allCredentials.length > 0;

      doc.setDrawColor(220, 38, 38);
      doc.setLineWidth(1);
      doc.line(geometry(doc).left, 28.5, geometry(doc).right, 28.5);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(11);
      doc.setTextColor(50, 50, 50);
      const execText = isMulti
        ? `This document serves as a Comprehensive Intelligence Report, consolidating data from ${reportsArray.length} independent reconnaissance operations conducted by the LOCKON Early Warning And Control (EWAC) system. The primary objective of these automated sweeps was to passively and actively map the external and internal attack surfaces, identify misconfigurations, and highlight critical vulnerabilities across multiple operational domains.\n\nThe findings detailed below are intended for authorized security personnel to facilitate immediate risk assessment, patch management, and infrastructure hardening. Data within this report must be handled in accordance with strict confidentiality protocols.`
        : `This Tactical Intelligence Report details the findings of an automated ${isWirelessReport(reportsArray[0]) ? 'wireless network reconnaissance (WLAN)' : 'local network intrusion sweep (LAN)'} executed by the LOCKON Early Warning And Control (EWAC) system against the designated target: ${reportsArray[0].targetName}.\n\nThe objective of this operation was to assess the security posture of the target environment, identify exposed assets, and detect potential vulnerabilities. The telemetry and analysis provided below are intended for authorized personnel to guide immediate remediation efforts.`;
      const splitText = doc.splitTextToSize(execText, 180);
      let currentY = 40;
      doc.text(splitText, 14, currentY);
      currentY += (splitText.length * 6) + 5;

      /*
        What this report is made of, by archive id.

        A consolidated report's own identifier is derived from these ids, and the
        per-archive figures elsewhere in the document refer to them — but they
        appeared nowhere in the PDF, so a recipient could not tell which archives
        they were holding a report about, and could not ask for one of them
        specifically. Origin and provenance are in the same row because they are
        the two things that decide how much any of the rest is worth.
      */
      if (isMulti) {
        autoTable(doc, {
          startY: currentY,
          head: [['#', 'Archive id', 'Operation', 'Recorded', 'Source']],
          body: reportsArray.map((r, i) => [
            String(i + 1),
            ascii(r.id),
            ascii(r.targetName),
            new Date(r.timestamp).toLocaleString(),
            r.origin === 'IMPORTED' ? 'IMPORTED FILE' : (r.simulated ? 'SIMULATOR' : 'live hardware'),
          ]),
          theme: 'grid',
          styles: { fontSize: 7.5, cellPadding: 2, overflow: 'linebreak', textColor: [0, 0, 0] },
          headStyles: { fillColor: [30, 41, 59], textColor: 255, fontStyle: 'bold', fontSize: 8 },
          columnStyles: { 0: { cellWidth: 8 }, 1: { font: 'courier', fontSize: 6.5, cellWidth: 44 } },
          didParseCell: (data: any) => {
            if (data.section !== 'body' || data.column.index !== 4) return;
            const text = String(data.cell.raw ?? '');
            if (text === 'IMPORTED FILE' || text === 'SIMULATOR') {
              data.cell.styles.textColor = [161, 98, 7];
              data.cell.styles.fontStyle = 'bold';
            }
          },
        });
        currentY = (doc as any).lastAutoTable.finalY + 6;
        currentY = paragraph(
          ascii(`This report's identifier, ${reportIdStr}, is derived from the archive ids above: the same selection always produces the same identifier, and a different selection produces a different one.`),
          currentY, { size: 8, color: [110, 110, 110] }
        );
        currentY += 4;
      }

      // ── Simulated-data statement, in the summary a manager actually reads ──
      if (anySimulated) {
        const simNames = simulatedReports.map(r => r.targetName).join(', ');
        const fieldNames = fieldReports.map(r => r.targetName).join(', ');
        const simSentence = allSimulated
          ? `DATA PROVENANCE - SIMULATED: ${isMulti ? 'All ' + reportsArray.length + ' operations in this report' : 'This operation'} (${simNames}) ${isMulti ? 'were' : 'was'} produced by the LOCKON hardware simulator, not by a live radio or a live network interface. The findings below are NOT field-verified: they demonstrate what the toolchain reports, and must not be cited as evidence that the named targets are exposed. Re-run against live hardware before any remediation decision is taken on this basis.`
          : `DATA PROVENANCE - MIXED: ${simulatedReports.length} of the ${reportsArray.length} operations consolidated here came from the LOCKON hardware simulator and are NOT field-verified - namely: ${simNames}. The remaining ${fieldReports.length} operation(s) were captured from live hardware: ${fieldNames}. Findings attributed to the simulated operations must not be cited as evidence of real-world exposure.`;

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        const simLines = doc.splitTextToSize(simSentence, 172);
        const simBoxHeight = simLines.length * 4.6 + 12;
        currentY = fit(currentY, simBoxHeight);

        doc.setFillColor(254, 252, 232); // amber-50
        doc.setDrawColor(234, 179, 8);
        doc.setLineWidth(0.8);
        doc.rect(geometry(doc).left, currentY, geometry(doc).contentWidth, simBoxHeight, 'FD');

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(10);
        doc.setTextColor(161, 98, 7); // amber-700
        doc.text(allSimulated ? 'SIMULATED OPERATION - NOT FIELD-VERIFIED' : 'CONTAINS SIMULATED OPERATIONS - NOT FIELD-VERIFIED', 19, currentY + 7);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        doc.setTextColor(50, 50, 50);
        doc.text(simLines, 19, currentY + 13);

        currentY += simBoxHeight + 8;
        doc.setLineWidth(0.5);
      }

      if (isMulti) {
        currentY = fit(currentY, 18);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(10);
        doc.setTextColor(0, 0, 0);
        doc.text('TARGETS IN SCOPE:', 14, currentY);
        currentY += 6;

        if (isMixedProvenance) {
          doc.setFont('helvetica', 'bold');
          doc.setFontSize(9);
          doc.setTextColor(161, 98, 7);
          doc.text('This export mixes live field data with simulated data. Each target below is tagged with its provenance.', 18, currentY);
          currentY += 6;
          doc.setFontSize(10);
        }

        doc.setFont('helvetica', 'normal');
        doc.setTextColor(50, 50, 50);
        reportsArray.forEach((r, idx) => {
          currentY = fit(currentY, 6);
          const label = `[${idx + 1}] ${r.targetName} (${isWirelessReport(r) ? 'WLAN' : 'LAN'})`;
          doc.setFontSize(10);
          doc.setTextColor(50, 50, 50);
          doc.setFont('helvetica', 'normal');
          doc.text(label, 18, currentY);

          const tagX = 18 + doc.getTextWidth(label) + 3;
          doc.setFont('helvetica', 'bold');
          if (r.simulated) {
            doc.setTextColor(161, 98, 7);
            doc.text('[SIMULATED - NOT FIELD-VERIFIED]', tagX, currentY);
          } else {
            doc.setTextColor(13, 148, 136);
            doc.text('[FIELD DATA]', tagX, currentY);
          }
          currentY += 5;
        });
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(50, 50, 50);
        currentY += 5;
      }

      // Asset counts. Deliberately no "vulnerable" column here: a single number
      // cannot carry a five-level scale, and the old one disagreed with the table
      // it sat above.
      currentY = fit(currentY, 30);
      autoTable(doc, {
        startY: currentY,
        margin: TABLE_MARGIN,
        head: [['ACCESS POINTS', 'LAN NODES', 'FINDINGS RAISED', 'CRITICAL + HIGH']],
        body: [[
          totalAPs.toString(),
          totalNodes.toString(),
          overall.total.toString(),
          overall.significant.toString(),
        ]],
        theme: 'grid',
        headStyles: { fillColor: [15, 23, 42], textColor: 255, fontStyle: 'bold', halign: 'center', fontSize: 8.5 },
        bodyStyles: { font: 'courier', halign: 'center', fontSize: 18, fontStyle: 'bold', textColor: [0, 0, 0] },
        didParseCell: function (data) {
          if (data.section === 'body' && data.column.index === 3 && parseInt(data.cell.text[0] || '0') > 0) {
            data.cell.styles.textColor = [220, 38, 38];
          }
        }
      });

      let summaryFinalY = (doc as any).lastAutoTable.finalY + 12;

      // --- FINDINGS BY SEVERITY AND CONFIDENCE ---
      // Both axes, side by side, because they answer different questions: how bad
      // it would be, and how sure this tool is. A SUSPECTED rogue access point is a
      // high-severity finding at low confidence, not a low-severity one.
      summaryFinalY = fit(summaryFinalY, 40);
      autoTable(doc, {
        startY: summaryFinalY,
        margin: TABLE_MARGIN,
        head: [['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']],
        body: [[
          String(overall.bySeverity.CRITICAL), String(overall.bySeverity.HIGH),
          String(overall.bySeverity.MEDIUM), String(overall.bySeverity.LOW),
          String(overall.bySeverity.INFO),
        ]],
        theme: 'grid',
        headStyles: { fillColor: [15, 23, 42], textColor: 255, fontStyle: 'bold', halign: 'center', fontSize: 8.5 },
        bodyStyles: { font: 'courier', halign: 'center', fontSize: 16, fontStyle: 'bold', textColor: [0, 0, 0] },
        didParseCell: (data) => {
          if (data.section !== 'body') return;
          const levels: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
          const level = levels[data.column.index];
          if (level && parseInt(data.cell.text[0] || '0') > 0) {
            data.cell.styles.textColor = SEVERITY_RGB[level];
          }
        }
      });
      summaryFinalY = (doc as any).lastAutoTable.finalY + 8;

      autoTable(doc, {
        startY: summaryFinalY,
        margin: TABLE_MARGIN,
        head: [['CONFIRMED (observed directly)', 'LIKELY (strong evidence, not exercised)', 'SUSPECTED (needs verification)']],
        body: [[
          String(overall.byConfidence.CONFIRMED),
          String(overall.byConfidence.LIKELY),
          String(overall.byConfidence.SUSPECTED),
        ]],
        theme: 'grid',
        headStyles: { fillColor: [30, 41, 59], textColor: 255, fontStyle: 'bold', halign: 'center', fontSize: 7.5 },
        bodyStyles: { font: 'courier', halign: 'center', fontSize: 14, fontStyle: 'bold', textColor: [0, 0, 0] },
      });
      summaryFinalY = (doc as any).lastAutoTable.finalY + 6;

      // `overall.worst` is null when nothing was assessed. Printing "INFO" there
      // stated a verdict where none was possible, so the two cases are now two
      // different sentences.
      const worstSentence = overall.worst === null
        ? 'No finding was raised, so there is no highest severity to report. That is not the same as an assessment that found nothing of concern: check the coverage section for what was actually surveyed before reading this as a clean result.'
        : `Highest severity present: ${overall.worst}.`;
      summaryFinalY = paragraph(
        // The previous wording claimed severity and confidence "neither modifies
        // the other", which the rogue-AP rule does not honour: its verdict scales
        // the score as well as the confidence. Stating the exception rather than
        // denying it, since the appendix publishes the ladder either way.
        ascii(`${worstSentence} Every severity in this document was produced by rule set ${methodology.id} version ${methodology.version}; the score bands and the individual rule scores are printed in the method appendix at the end, so any label here can be checked against the rule that produced it. Severity and confidence are reported as separate columns and a low confidence never raises a severity. For most rules the two are independent; the rogue-AP rule is the exception, where the strength of the verdict scales the score as well, so a SUSPECTED rogue is deliberately ranked below a CONFIRMED one.`),
        summaryFinalY, { size: 9, color: [80, 80, 80] }
      );
      summaryFinalY += 4;

      if (findingsDbError) {
        summaryFinalY = callout(
          summaryFinalY,
          'FINDING HISTORY COULD NOT BE READ',
          ascii(`The findings database could not be read, so this document cannot say which of these issues were already known, already closed, or have regressed since a previous visit. Error reported: ${findingsDbError}. The severities themselves are unaffected: they are computed from the archived observations by the rule set named above.`),
          [254, 252, 232], [234, 179, 8], [161, 98, 7]
        );
      }

      // --- KEY CRITICAL FINDINGS ---
      // Driven off the rule set's own categories, so this list cannot say something
      // the tables further down contradict.
      const countByCategory = (category: string, atLeast: Severity = 'HIGH') =>
        allFindings.filter(f => f.category === category && SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[atLeast]).length;

      if (hasCritical) {
        const findings: string[] = [];
        const encHigh = countByCategory('encryption');
        const wpsHigh = countByCategory('wps');
        const rogueAny = allFindings.filter(f => f.category === 'rogue_ap').length;
        const cveHigh = countByCategory('service_cve');
        const svcHigh = countByCategory('exposed_service');
        if (encHigh > 0) {
          findings.push(`\u2022 ${encHigh} access point(s) run encryption rated HIGH or CRITICAL by this rule set.`);
        }
        if (wpsHigh > 0) {
          findings.push(`\u2022 ${wpsHigh} access point(s) advertise WPS without effective lockout, which yields the passphrase regardless of its strength.`);
        }
        if (rogueAny > 0) {
          const confirmed = allFindings.filter(f => f.category === 'rogue_ap' && f.confidence === 'CONFIRMED').length;
          const suspected = allFindings.filter(f => f.category === 'rogue_ap' && f.confidence === 'SUSPECTED').length;
          findings.push(`\u2022 ${rogueAny} possible rogue access point(s) flagged (${confirmed} confirmed, ${suspected} suspected only - see the rogue-AP section).`);
        }
        if (cveHigh > 0) {
          findings.push(`\u2022 ${cveHigh} HIGH or CRITICAL CVE match(es) on internal services, from banner version matching only.`);
        }
        if (svcHigh > 0) {
          findings.push(`\u2022 ${svcHigh} exposed service(s) whose reachability is itself the finding.`);
        }
        if (allCredentials.length > 0) {
          findings.push(
            discloseCredentials
              ? `\u2022 Recovered ${allCredentials.length} working credentials; they are listed in cleartext in this document.`
              : `\u2022 Recovered ${allCredentials.length} working credentials; they are listed masked in this document.`
          );
        }
        if (anySimulated) {
          findings.push(
            allSimulated
              ? '\u2022 PROVENANCE: every finding above is SIMULATED and is not field-verified.'
              : `\u2022 PROVENANCE: findings from ${simulatedReports.length} simulated operation(s) are included above and are not field-verified.`
          );
        }

        const findingsBoxHeight = 12 + findings.length * 6;
        summaryFinalY = fit(summaryFinalY, findingsBoxHeight);
        doc.setFillColor(254, 242, 242); // very light red
        doc.setDrawColor(220, 38, 38);
        doc.setLineWidth(0.5);
        doc.rect(geometry(doc).left, summaryFinalY, geometry(doc).contentWidth, findingsBoxHeight, 'FD');

        doc.setFontSize(11);
        doc.setTextColor(220, 38, 38);
        doc.setFont('helvetica', 'bold');
        doc.text('KEY CRITICAL FINDINGS', 18, summaryFinalY + 7);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(10);
        doc.setTextColor(50, 50, 50);

        let findingY = summaryFinalY + 14;
        findings.forEach((line) => {
          if (line.includes('PROVENANCE')) {
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(161, 98, 7);
          } else {
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(50, 50, 50);
          }
          doc.text(line, 18, findingY);
          findingY += 6;
        });
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(50, 50, 50);

        summaryFinalY += findingsBoxHeight + 10;

        // --- ACTIONABLE REMEDIATION MATRIX ---
        summaryFinalY = fit(summaryFinalY, 40);
        doc.setFontSize(14);
        doc.setTextColor(0, 0, 0);
        doc.setFont('helvetica', 'bold');
        doc.text('ACTIONABLE REMEDIATION MATRIX', 14, summaryFinalY);

        // One row per distinct issue the rule set actually raised, carrying the
        // remediation text the rule itself supplies. The old matrix had three
        // hardcoded rows and never mentioned WPS or a rogue access point.
        const remSeen = new Set<string>();
        const remBody: string[][] = [];
        for (const f of [...allFindings].sort((a, b) => b.risk_score - a.risk_score)) {
          if (SEVERITY_ORDER[f.severity] < SEVERITY_ORDER['MEDIUM']) continue;
          const key = `${f.category}|${f.remediation ?? ''}`;
          if (remSeen.has(key)) continue;
          remSeen.add(key);
          /*
            The findings this row is actually about.

            This counted the whole category at every severity — including the
            sub-threshold findings the `continue` above has just excluded from the
            matrix — and one category legitimately produces several rows, because
            `ENCRYPTION_RULES` supplies different remediation text per mode. So three
            encryption rows each printed the same whole-category total: 3 OPEN + 2 WEP
            + 1 WPA1 + 12 unrecognised-mode gave "Findings: 18" three times, summing to
            54 in a document whose FINDINGS RAISED tile says 18, and the CRITICAL row
            claimed 18 access points needed "Enable WPA2-Enterprise or WPA3" when 3
            did.

            Keyed the same way the row is, so the number and the row describe the same
            set, and filtered to the same severity floor the matrix uses.
          */
          const affected = allFindings.filter(
            x => SEVERITY_ORDER[x.severity] >= SEVERITY_ORDER['MEDIUM']
              && `${x.category}|${x.remediation ?? ''}` === key,
          ).length;
          remBody.push([
            f.severity,
            ascii(f.category.replace(/_/g, ' ').toUpperCase()),
            `${affected}`,
            ascii(f.remediation || 'No remediation text is attached to this rule.'),
          ]);
        }
        if (remBody.length === 0) {
          remBody.push(['INFO', 'NONE AT MEDIUM OR ABOVE', '0', 'No finding reached MEDIUM, so no remediation is proposed here.']);
        }

        autoTable(doc, {
          startY: summaryFinalY + 5,
          head: [['Severity', 'Issue class', 'Findings', 'Recommended remediation (from the rule that raised it)']],
          body: remBody,
          theme: 'grid',
          margin: TABLE_MARGIN,
          headStyles: { fillColor: [220, 38, 38], textColor: 255, fontSize: 8.5 },
          styles: { fontSize: 8.5, cellPadding: 2.4, overflow: 'linebreak', textColor: [0, 0, 0] },
          columnStyles: {
            0: { cellWidth: 20, fontStyle: 'bold', halign: 'center' },
            1: { cellWidth: 36, fontStyle: 'bold' },
            2: { cellWidth: 16, halign: 'center' },
          },
          didParseCell: (data) => {
            if (data.section !== 'body' || data.column.index !== 0) return;
            const level = data.cell.text[0] as Severity;
            if (SEVERITY_RGB[level]) data.cell.styles.textColor = SEVERITY_RGB[level];
          }
        });

        summaryFinalY = (doc as any).lastAutoTable.finalY + 15;
      } else {
        summaryFinalY = fit(summaryFinalY, 18);
        doc.setFillColor(240, 253, 244); // light green
        doc.setDrawColor(16, 185, 129);
        doc.setLineWidth(0.5);
        doc.rect(geometry(doc).left, summaryFinalY, geometry(doc).contentWidth, 15, 'FD');
        doc.setFontSize(10);
        doc.setTextColor(16, 185, 129);
        doc.setFont('helvetica', 'bold');
        doc.text('No finding reached HIGH or CRITICAL under the rule set named above.', 18, summaryFinalY + 9);
        summaryFinalY += 20;
        summaryFinalY = paragraph(
          'This is not a statement that the environment is secure. It means nothing observed during this operation met the HIGH threshold. Read it together with the survey coverage section, which states where the operator actually went, and with the method appendix, which states which 802.11 features this hardware could exercise at all.',
          summaryFinalY, { size: 9, color: [80, 80, 80] }
        );
        summaryFinalY += 5;
      }
}
