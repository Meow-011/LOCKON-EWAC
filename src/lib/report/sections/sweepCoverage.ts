/**
 * LOCKON EWAC — how much of each subnet the sweep actually touched.
 *
 * This section exists because of a specific way the tool could mislead. The LAN
 * sweep pre-filters a /24 with an ARP pass and probes only the addresses that
 * answered — on a wireless guest network that cut 254 addresses to 2 — and the
 * only number that used to leave the module was the filtered one. The report
 * said "swept the subnet, 0 hosts found", which is true of the two addresses it
 * looked at and reads as a statement about 254.
 *
 * So the three populations are kept apart here and never summed into a single
 * "scanned" figure: addresses in range, addresses actually probed, and
 * addresses never contacted at all. "Asked and silent" is a weak observation;
 * "never asked" is not an observation of anything, and a reader has to be able
 * to tell which one a blank line represents.
 *
 * Moved out of `buildAndSavePDF` verbatim by script; `pdfdiff` confirmed the
 * document is unchanged.
 */
import autoTable from 'jspdf-autotable';
import { ascii, dirbusterOf, isWirelessReport, smbEnumOf, segmentationOf, sweepScopesOf, tlsInspectionOf, traceroutePathOf } from '../archive';
import { type Report as IntelReport } from '../../../stores/reportStore';
import type { ReportData } from '../assemble';
import type { PdfLayout } from '../layout';

export function renderSweepCoverage(layout: PdfLayout, data: ReportData): void {
  const { doc, tocEntries, fit, sectionHeading, paragraph, callout } = layout;
  const { reportsArray } = data;

    // --- 6b. SUBNET SWEEP COVERAGE ---
  //
  // The LAN equivalent of the section above, and it answers the same question:
  // was this subnet swept, or were six addresses out of 253 contacted?
  //
  // The engine has always emitted these figures as `intrusion_scope`, with the
  // caveat that "absence here is not evidence that nothing is there". Nothing
  // subscribed to the event, so the numbers never reached the operator or this
  // document, and a narrow sweep read exactly like a thorough one.
  const lanReports = reportsArray.filter(r => !isWirelessReport(r));
  if (lanReports.length > 0) {
    doc.addPage();
    tocEntries.push({ title: 'SUBNET SWEEP COVERAGE', page: (doc as any).internal.getNumberOfPages() });
    let swY = sectionHeading('SUBNET SWEEP COVERAGE');

    swY = paragraph(
      'A host only appears in this report if it was probed, and a sweep does not necessarily probe every address in a subnet. Outside DEEP mode the engine first asks which addresses answered ARP and probes only those, so a host that is powered on but silent, firewalled against ARP, or slow to answer is skipped. Separately, the sweep that populates the ARP table is capped per subnet — every datagram it sends to an unused address causes an ARP broadcast that the whole segment must process, and on a large range that would degrade the network being assessed. Addresses beyond that cap were never contacted at all. The two are counted separately below, because "asked and silent" is a weak observation while "never asked" is not an observation of anything.',
      swY, { size: 9.5 }
    );
    swY += 4;

    for (const r of lanReports) {
      const scopes = sweepScopesOf(r);
      swY = fit(swY, 24);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10.5);
      doc.setTextColor(30, 41, 59);
      doc.text(ascii(`OPERATION: ${r.targetName.toUpperCase()}`), layout.left(), swY);
      swY += 6;

      if (scopes.length === 0) {
        // Older archives predate the recording. Saying so is the point: an
        // absent measurement must not read as a complete sweep.
        swY = callout(
          swY,
          'SWEEP COVERAGE WAS NOT RECORDED FOR THIS ARCHIVE',
          'This archive carries no per-subnet coverage figures, so this report cannot state how much of the subnet was probed. Do not read the host count below as a complete picture of the subnet: the sweep may have contacted only the addresses that answered ARP. Re-run the sweep to capture coverage.',
          [254, 252, 232], [234, 179, 8], [161, 98, 7]
        );
        swY += 4;
        continue;
      }

      autoTable(doc, {
        startY: swY,
        // "Silent" and "never contacted" are separate columns because they are
        // separate claims. An address that was asked and did not answer is a
        // weak observation; one that was never asked is not an observation at
        // all, and only the second kind can be caused by the sweep's own cap.
        head: [['Subnet', 'Mode', 'In range', 'Probed', 'Asked, silent', 'Never contacted', '% probed']],
        body: scopes.map((s: any) => {
          const inRange = Number(s.addressesInRange) || 0;
          const probed = Number(s.addressesProbed) || 0;
          const neverSwept = Number(s.addressesNeverSwept) || 0;
          const silent = Math.max(0, inRange - probed - neverSwept);
          return [
            ascii(String(s.subnet ?? 'unknown')),
            ascii(String(s.scanMode ?? '')),
            String(inRange),
            String(probed),
            String(silent),
            String(neverSwept),
            inRange > 0 ? `${Math.round((probed / inRange) * 100)}%` : 'n/r',
          ];
        }),
        theme: 'grid',
        styles: { fontSize: 8, cellPadding: 2 },
        headStyles: { fillColor: [30, 41, 59], textColor: 255, fontStyle: 'bold', fontSize: 8 },
        didParseCell: (data: any) => {
          if (data.section !== 'body') return;
          // Flag a materially incomplete sweep in the row itself, so it cannot
          // be skimmed past.
          if (data.column.index === 6) {
            const pct = parseInt(String(data.cell.raw), 10);
            if (Number.isFinite(pct) && pct < 25) {
              data.cell.styles.textColor = [220, 38, 38];
              data.cell.styles.fontStyle = 'bold';
            }
          }
          // Any address that was never contacted is worth the reader's eye.
          if (data.column.index === 5 && parseInt(String(data.cell.raw), 10) > 0) {
            data.cell.styles.textColor = [220, 38, 38];
            data.cell.styles.fontStyle = 'bold';
          }
        },
      });
      swY = (doc as any).lastAutoTable.finalY + 6;

      // A failed ARP read is not a coverage figure — it invalidates the
      // figures. Said before them, not after.
      const arpFailures = scopes.filter((s: any) => s.arpReadError);
      if (arpFailures.length > 0) {
        swY = callout(
          swY,
          'THE PRE-FILTER FAILED ON AT LEAST ONE SUBNET',
          ascii(`The ARP table could not be read for ${arpFailures.map((s: any) => s.subnet).join(', ')} `
            + `(${arpFailures[0].arpReadError}). The pre-filter that decides which addresses to probe is built from that table, so `
            + 'those sweeps covered only a fallback sample of the range. The host counts for those '
            + 'subnets describe the sample, not the subnet, and no absence of findings in them '
            + 'means anything. Re-run in DEEP mode, which ignores the pre-filter entirely.'),
          [254, 242, 242], [220, 38, 38], [220, 38, 38]
        );
        swY += 4;
      }

      const worst = scopes.reduce((acc: any, s: any) => {
        const inRange = Number(s.addressesInRange) || 0;
        const probed = Number(s.addressesProbed) || 0;
        // Carried through, because the callout has to separate them. See below.
        const neverSwept = Number(s.addressesNeverSwept) || 0;
        const silent = Math.max(0, inRange - probed - neverSwept);
        const ratio = inRange > 0 ? probed / inRange : 1;
        return ratio < acc.ratio
          ? { ratio, subnet: s.subnet, inRange, probed, neverSwept, silent }
          : acc;
      }, { ratio: 1, subnet: '', inRange: 0, probed: 0, neverSwept: 0, silent: 0 });

      if (worst.ratio < 1) {
        swY = callout(
          swY,
          worst.probed === 0
            ? 'AT LEAST ONE SUBNET WAS NOT PROBED AT ALL'
            : 'THIS SWEEP DID NOT COVER EVERY ADDRESS',
          ascii(worst.probed === 0
            ? `No address in ${worst.subnet} was probed: nothing answered ARP within the settle window. This is also what a failed ARP read looks like from here. Nothing in this report describes what is present on that subnet.`
            /*
              The remainder is broken out rather than summed.

              This said "The remaining ${inRange - probed} were never contacted",
              which is `silent + neverSwept` — the two quantities the table sixty
              lines above computes as separate columns, and that this module's own
              header and intro paragraph both say must never be added together. In
              the ordinary ARP-prefilter case (254 in range, 2 probed, 252
              asked-and-silent, 0 never contacted) the callout asserted 252 addresses
              were never contacted while the table on the same page said 0. The
              callout is the part a reader skims, so it was the headline making the
              one claim this section exists to prevent.
            */
            : `${worst.subnet} was the narrowest sweep in this export: ${worst.probed} of ${worst.inRange} addresses were probed`
              + (worst.silent > 0
                  ? `, ${worst.silent} were asked and stayed silent`
                  : '')
              + (worst.neverSwept > 0
                  ? `, and ${worst.neverSwept} were never contacted at all`
                  : '')
              + `. No statement in this report — including the absence of findings — applies to the ${worst.inRange - worst.probed} that were not probed.`),
          [254, 252, 232], [234, 179, 8], [161, 98, 7]
        );
        swY += 4;
      }

      swY = paragraph(
        ascii(scopes[0]?.caveat
          ? `Engine caveat, recorded at scan time: ${scopes[0].caveat}`
          : 'Addresses that did not answer ARP in time were not probed.'),
        swY, { size: 8, color: [110, 110, 110] }
      );
      swY += 6;

      /*
        The same question for directory enumeration: was the wordlist
        exhausted, or stopped?

        A path that responded is evidence either way. A path that is *absent*
        from the results only means something if it was actually requested, and
        an operator who pressed stop has learned nothing about the remainder of
        the list. Recorded here because it is the same kind of claim as sweep
        coverage, and it belongs beside it.
      */
      const db = dirbusterOf(r);
      if (db.hits.length > 0 && db.complete !== true) {
        swY = callout(
          swY,
          db.complete === false
            ? 'A DIRECTORY ENUMERATION WAS STOPPED BEFORE IT FINISHED'
            : 'DIRECTORY ENUMERATION COMPLETENESS WAS NOT RECORDED',
          ascii(db.complete === false
            ? `${db.hits.length} responding path(s) are listed in this report, and each one was observed. The scan was halted before the wordlist was exhausted, so the paths it had not yet requested are unexamined — not absent. Re-run the enumeration to completion before treating this list as the full picture of what is exposed.`
            : `${db.hits.length} responding path(s) are listed in this report, and each one was observed. This archive does not record whether the wordlist was exhausted, so this report cannot state that the list is complete. Treat it as a sample.`),
          [254, 252, 232], [234, 179, 8], [161, 98, 7]
        );
        swY += 4;
      }

      /*
        And for SMB: which checks failed to answer.

        The engine reports three states per check. `signing_required: null`
        means the negotiation never completed — a firewalled host looks
        identical to a hardened one from here. Those checks produce no
        finding, which is correct, but silence in the findings table would then
        read as a pass. This names them.
      */
      const smbForReport = smbEnumOf(r);
      const smbUnanswered: string[] = Array.isArray(smbForReport?.inconclusive)
        ? smbForReport!.inconclusive.map((v: any) => String(v))
        : [];
      if (smbForReport && smbUnanswered.length > 0) {
        swY = callout(
          swY,
          'AN SMB CHECK COULD NOT ANSWER',
          ascii(`On ${String(smbForReport.target ?? 'the enumerated host')} the following check(s) did not complete: ${smbUnanswered.join(', ')}`
            + `${smbForReport.error ? ` (${String(smbForReport.error).slice(0, 160)})` : ''}. `
            + 'No finding was raised for them, and none should be read into their absence: a host that refused the negotiation is indistinguishable here from one that is correctly configured. Re-run the enumeration, or verify the setting on the host itself, before recording either answer.'),
          [254, 252, 232], [234, 179, 8], [161, 98, 7]
        );
        swY += 4;
      }

      /*
        The same for TLS, and it needs saying at least as plainly.

        `ssl_check.py` builds its `inconclusive` list on an explicit rule -- "a
        check that did not run produces an entry in `inconclusive`, never a
        finding" -- because a TLS check that could not complete looks exactly
        like one that found nothing wrong. A port that refused the handshake, a
        cipher enumeration that saw only the negotiated suite, an HSTS probe that
        never got a response: each leaves the findings table empty for a reason
        that is not "this service is sound".

        Entries are objects with `check` and `reason`, unlike SMB's strings, so
        they are rendered as a pair rather than stringified -- `String(obj)`
        would have printed [object Object] into the report.
      */
      const tlsForReport = tlsInspectionOf(r);
      const tlsUnanswered: string[] = Array.isArray(tlsForReport?.inconclusive)
        ? tlsForReport!.inconclusive.map((v: any) =>
            v && typeof v === 'object'
              ? `${String(v.check ?? 'unnamed check')} (${String(v.reason ?? 'no reason given')})`
              : String(v))
        : [];
      if (tlsForReport && tlsUnanswered.length > 0) {
        swY = callout(
          swY,
          'A TLS CHECK COULD NOT ANSWER',
          ascii(`On ${String(tlsForReport.target ?? 'the inspected host')}`
            + `${tlsForReport.port ? ` port ${tlsForReport.port}` : ''}`
            + ` the following check(s) did not complete: ${tlsUnanswered.join('; ')}. `
            + 'No finding was raised for them, and none should be read into their absence. A service that refused the handshake is indistinguishable here from one that is correctly configured, and a cipher audit that saw only the negotiated suite has not established what else the server would accept. Re-run the inspection, or verify at the service itself, before recording either answer.'),
          [254, 252, 232], [234, 179, 8], [161, 98, 7]
        );
        swY += 4;
      }
    }
  }

  /*
    --- 6b2. NETWORK PATH CONTEXT ---

    Traceroute results, as context rather than as findings.

    The path analysis is genuinely useful to a reader — it says whether the
    target sits behind a NAT boundary, whether something is dropping probes
    partway, and whether the target answered at all — and until now it lived
    only in the operator's session and vanished when the drawer closed.

    It is deliberately kept out of the findings table. "NAT boundary detected
    at hop 4" is a fact about the route, not a weakness in it, and the number
    of findings in this document is a figure management acts on. Padding it
    with routing facts would make the report look worse without making the
    organisation any less safe.
  */
  const pathReports = reportsArray
    .map(r => ({ report: r, path: traceroutePathOf(r) }))
    .filter((e): e is { report: IntelReport; path: NonNullable<ReturnType<typeof traceroutePathOf>> } => !!e.path);

  if (pathReports.length > 0) {
    doc.addPage();
    tocEntries.push({ title: 'NETWORK PATH CONTEXT', page: (doc as any).internal.getNumberOfPages() });
    let ptY = sectionHeading('NETWORK PATH CONTEXT');

    ptY = paragraph(
      'The routes below were traced during the assessment. They are recorded as context, not as findings: a NAT boundary or a filtering hop describes the shape of the network between the operator and the target, and neither is a vulnerability. They matter to a reader for a different reason — they say how much of the path is under the organisation\'s own control, and whether a target that produced no findings was actually reachable at the time. A trace only covers the one host it was aimed at; the absence of a trace for a host says nothing about that host.',
      ptY, { size: 9.5 }
    );
    ptY += 4;

    for (const { report: r, path } of pathReports) {
      const analysis = Array.isArray(path.analysis) ? path.analysis : [];
      const hops = Array.isArray(path.hops) ? path.hops : [];
      const reached = hops.some((h: any) => h?.is_target);

      ptY = fit(ptY, 24);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10.5);
      doc.setTextColor(30, 41, 59);
      doc.text(ascii(`${r.targetName.toUpperCase()} — PATH TO ${String(path.target ?? 'UNKNOWN TARGET')}`), layout.left(), ptY);
      ptY += 6;

      if (hops.length > 0) {
        autoTable(doc, {
          startY: ptY,
          head: [['Hop', 'Address', 'Reverse name', 'Avg RTT', 'Answered']],
          body: hops.map((h: any) => [
            String(h?.hop ?? '?'),
            ascii(String(h?.ip ?? '(no reply)')),
            ascii(String(h?.hostname ?? '-')),
            // A hop that never answered has no latency. Printing 0 ms for it
            // would invent a measurement.
            // Three states. A figure, an upper bound the tool gave instead of
            // a figure, or no measurement at all — printing 0 ms or a
            // midpoint for either of the last two invents a measurement.
            typeof h?.avg_rtt === 'number' ? `${h.avg_rtt} ms`
              : h?.rtt_below_1ms ? '< 1 ms'
              : 'n/r',
            h?.timeout ? 'no' : (h?.ip ? 'yes' : 'no'),
          ]),
          theme: 'grid',
          styles: { fontSize: 8, cellPadding: 2 },
          headStyles: { fillColor: [30, 41, 59], textColor: 255, fontStyle: 'bold', fontSize: 8 },
          didParseCell: (data: any) => {
            if (data.section === 'body' && data.column.index === 4 && String(data.cell.raw) === 'no') {
              data.cell.styles.textColor = [161, 98, 7];
            }
          },
        });
        ptY = (doc as any).lastAutoTable.finalY + 6;
      }

      if (analysis.length > 0) {
        autoTable(doc, {
          startY: ptY,
          head: [['Observation', 'Detail']],
          body: analysis.map((a: any) => [
            ascii(String(a?.type ?? 'info').toUpperCase()),
            ascii(String(a?.message ?? '')),
          ]),
          theme: 'plain',
          styles: { fontSize: 8.5, cellPadding: 2 },
          headStyles: { fillColor: [241, 245, 249], textColor: [30, 41, 59], fontStyle: 'bold', fontSize: 8 },
          columnStyles: { 0: { cellWidth: 26, fontStyle: 'bold' } },
        });
        ptY = (doc as any).lastAutoTable.finalY + 6;
      }

      // Said explicitly, because it changes how every other statement about
      // this host should be read.
      if (!reached && hops.length > 0) {
        ptY = callout(
          ptY,
          'THE TRACE DID NOT REACH THIS TARGET',
          ascii(`The path to ${String(path.target ?? 'the target')} stopped before the target answered. Something between the operator and the host dropped the probes, or the host was down at that moment. Findings recorded for this host from other checks still stand on their own evidence, but the absence of findings here does not mean the host is clean — it may simply not have been reachable.`),
          [254, 252, 232], [234, 179, 8], [161, 98, 7]
        );
        ptY += 4;
      }
    }
  }

  /*
    --- 6b3. NETWORK SEGMENTATION CONTEXT ---

    The same treatment as the path above, and it needs it more.

    Of everything `start_vlan_detect` returns, exactly one field per subnet is a
    measurement: whether the assumed gateway answered a ping. The VLAN id is the
    third octet of the range. The gateway is the first usable address by
    convention, which the engine labels as assumed rather than discovered. A
    table that printed "VLAN 20" beside a real measurement would launder a guess
    into a record, and a reader has no way to tell them apart afterwards -- so
    every inferred value is printed with the basis the engine shipped with it,
    and the section says so before the table rather than in a footnote under it.

    Kept out of the findings table for the reason the traceroute section gives,
    and one more: a flat network is a design choice an organisation may have made
    deliberately, and this check cannot tell a deliberate flat network from an
    accidental one. The rogue-DHCP result is the exception that proves it -- that
    one IS measured, two servers answering one discover, and it appears in the
    findings list the engine builds rather than in this map.
  */
  const segReports = reportsArray
    .map(r => ({ report: r, seg: segmentationOf(r) }))
    .filter((e): e is { report: IntelReport; seg: NonNullable<ReturnType<typeof segmentationOf>> } => !!e.seg);

  if (segReports.length > 0) {
    doc.addPage();
    tocEntries.push({ title: 'NETWORK SEGMENTATION CONTEXT', page: (doc as any).internal.getNumberOfPages() });
    let sgY = sectionHeading('NETWORK SEGMENTATION CONTEXT');

    sgY = paragraph(
      ascii('The segmentation below is inferred from the address ranges that were swept, not read from any switch. The VLAN column is the third octet of each range, which is a common convention and nothing more; the gateway column is the first usable address of each prefix, assumed rather than discovered. Only the final column was measured — one ICMP echo to that assumed address. Nothing here establishes how the network is actually segmented, and a segment this sweep never touched does not appear at all. Confirm against the switch configuration before treating any of it as the network\'s design.'),
      sgY, { size: 9.5 }
    );
    sgY += 4;

    for (const { report: r, seg } of segReports) {
      const map = Array.isArray(seg.vlan_map) ? seg.vlan_map : [];
      const findings = Array.isArray(seg.findings) ? seg.findings : [];

      sgY = fit(sgY, 24);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10.5);
      doc.setTextColor(30, 41, 59);
      doc.text(ascii(`${r.targetName.toUpperCase()} — ${map.length} SUBNET(S) ANALYSED`), layout.left(), sgY);
      sgY += 6;

      if (map.length > 0) {
        autoTable(doc, {
          startY: sgY,
          head: [['Subnet', 'VLAN (inferred)', 'Gateway (assumed)', 'Gateway answered']],
          body: map.map((v: any) => [
            ascii(String(v?.subnet ?? '?')),
            // The basis travels with the number, in the same cell, because a
            // column header can be skimmed past and a cell cannot.
            v?.error ? 'could not be read'
              : v?.vlan_id != null ? ascii(`${v.vlan_id} (${String(v.vlan_id_basis ?? 'basis not stated')})`)
              : 'not inferred',
            v?.error ? '-'
              : v?.gateway ? ascii(String(v.gateway))
              : 'no first usable address',
            // Three states, and the third is not "no". A subnet with no address
            // to probe was never asked, and printing "no" for it would record a
            // gateway that failed to answer.
            v?.gateway_alive === true ? 'yes'
              : v?.gateway_alive === false ? 'no'
              : 'not probed',
          ]),
          theme: 'grid',
          styles: { fontSize: 8, cellPadding: 2 },
          headStyles: { fillColor: [30, 41, 59], textColor: 255, fontStyle: 'bold', fontSize: 8 },
          margin: { left: layout.left(), right: layout.left() },
        });
        sgY = (doc as any).lastAutoTable.finalY + 6;
      }

      const unreadable = map.filter((v: any) => v?.error);
      if (unreadable.length > 0) {
        sgY = callout(
          sgY,
          'A SUBNET COULD NOT BE READ',
          ascii(`${unreadable.length} of the ${map.length} range(s) handed to this check could not be parsed as a CIDR and were analysed no further: ${unreadable.map((v: any) => String(v?.subnet)).join(', ')}. They are listed above rather than dropped, because a map missing a segment reads as a network that has fewer.`),
          [254, 252, 232], [234, 179, 8], [161, 98, 7]
        );
        sgY += 4;
      }

      if (findings.length > 0) {
        sgY = fit(sgY, 16);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        doc.setTextColor(60, 60, 60);
        for (const f of findings) {
          sgY = fit(sgY, 10);
          sgY = paragraph(
            ascii(`[${String(f?.severity ?? 'INFO')}] ${String(f?.message ?? 'no message')}`),
            sgY, { size: 9 }
          );
        }
        sgY += 2;
      }
    }
  }
}
