/**
 * Section 6 of the report: survey coverage and the survey figure.
 *
 * Moved out of `buildAndSavePDF` verbatim: the body below is the code that was
 * inline, unchanged. The only edits are the values it now takes as parameters
 * instead of reading them from the closure, and `npm run test:export` was run
 * before and after to confirm the document says exactly what it said.
 */
import autoTable from 'jspdf-autotable';

import { ascii } from '../archive';
import { formatCoverage } from '../../coverageDB';
import { SEVERITY_LEVELS, severityRgb } from '../../severityStyle';
import { geometry, TABLE_MARGIN } from '../geometry';
import type { SurveyMapResult } from '../surveyMap';
import type { ReportData } from '../assemble';
import type { PdfLayout } from '../layout';

export interface SurveyCoverageOptions {
  /**
   * The survey figure, already rendered to a bitmap.
   *
   * Drawn by the caller because it needs a live WebGL context and a network
   * round trip for tiles, which has to happen once before any page is laid out;
   * by the time this section runs it is just an image.
   *
   * Always a result, never null: a failed capture comes back with `image: null`
   * and a `reason`, which is an ordinary case the section states and carries on
   * from. A missing figure must never cost the document, and an optional
   * parameter would have let a caller omit the reason along with the figure.
   */
  surveyMap: SurveyMapResult;
}

export function renderSurveyCoverage(
  layout: PdfLayout,
  data: ReportData,
  { surveyMap }: SurveyCoverageOptions,
): void {
  const { doc, tocEntries, fit, sectionHeading, paragraph, callout } = layout;
  const { coverageSections } = data;
      // --- 6. SURVEY COVERAGE ---
      // What was actually surveyed. Without this, "no vulnerable networks on the
      // north side" cannot be distinguished from "never drove the north side", and
      // that is the first hole a sceptical reader finds in a wardrive report.
      if (coverageSections.length > 0) {
        doc.addPage();
        tocEntries.push({ title: 'SURVEY COVERAGE', page: (doc as any).internal.getNumberOfPages() });
        let covY = sectionHeading('SURVEY COVERAGE');

        covY = paragraph(
          'This section states where and for how long the survey physically went. An absence of findings inside the area below is a result; an absence of findings outside it is not, because the area was never observed. Coverage is computed from the recorded GPS track and scan log at export time and then frozen, so it still stands if the underlying rows are later purged.',
          covY, { size: 9.5 }
        );
        covY += 4;

        for (const section of coverageSections) {
          covY = fit(covY, 24);
          doc.setFont('helvetica', 'bold');
          doc.setFontSize(10.5);
          doc.setTextColor(30, 41, 59);
          doc.text(ascii(`OPERATION: ${section.report.targetName.toUpperCase()}`), 14, covY);
          covY += 6;

          if (section.error) {
            covY = callout(
              covY,
              'COVERAGE COULD NOT BE COMPUTED',
              ascii(`The survey coverage for mission ${section.missionId} could not be computed or read. Error reported: ${section.error}. Treat the spatial extent of this operation as unestablished: nothing in this document states where the operator did and did not go.`),
              [254, 242, 242], [220, 38, 38], [220, 38, 38]
            );
            continue;
          }

          if (!section.missionId) {
            covY = callout(
              covY,
              'NO COVERAGE DATA FOR THIS OPERATION',
              'This archive carries no mission identifier, so its GPS track and scan log cannot be located and no coverage figures can be given. The distance surveyed, duration, fix quality and GPS dropouts for this operation are therefore unknown. Nothing below should be read as evidence that a given area contains no networks: only that no network was recorded here.',
              [245, 245, 245], [150, 150, 150], [80, 80, 80]
            );
            continue;
          }

          if (!section.row) {
            covY = callout(
              covY,
              'NO COVERAGE DATA WAS RECORDED',
              ascii(`No coverage row exists for mission ${section.missionId} and none could be computed, which normally means no GPS fix was ever logged for it. Spatial coverage cannot be established for this operation.`),
              [254, 252, 232], [234, 179, 8], [161, 98, 7]
            );
            continue;
          }

          const lines = formatCoverage(section.row).map(l => ascii(l));
          autoTable(doc, {
            startY: covY,
            head: [['COVERAGE EVIDENCE', '']],
            body: lines.map(line => {
              const idx = line.indexOf(':');
              return idx > 0 ? [line.slice(0, idx), line.slice(idx + 1).trim()] : ['Note', line];
            }),
            theme: 'grid',
            headStyles: { fillColor: [15, 23, 42], textColor: 255, fontStyle: 'bold', fontSize: 8.5 },
            styles: { fontSize: 8.5, cellPadding: 2.2, overflow: 'linebreak', textColor: [0, 0, 0] },
            columnStyles: { 0: { cellWidth: 52, fontStyle: 'bold' } },
            margin: TABLE_MARGIN,
            didParseCell: (data) => {
              if (data.section !== 'body') return;
              const label = data.row.cells[0]?.text?.join(' ') ?? '';
              if (/dropout/i.test(label) && (section.row?.gap_count ?? 0) > 0) {
                data.cell.styles.textColor = [161, 98, 7];
                data.cell.styles.fontStyle = 'bold';
              }
            }
          });
          covY = (doc as any).lastAutoTable.finalY + 6;

          if ((section.row.gap_count ?? 0) > 0) {
            covY = callout(
              covY,
              `${section.row.gap_count} GPS DROPOUT(S) - A COVERAGE LIMITATION`,
              ascii(`The GPS track contains ${section.row.gap_count} gap(s) longer than ${section.row.gap_threshold_seconds}s, the longest ${section.row.max_gap_seconds}s. Ground covered during a dropout is not represented in the figures above, and distance across a dropout is deliberately excluded rather than drawn as a straight line. A thin patch of results next to a long gap is a gap in observation, not evidence that no networks are present there.`),
              [254, 252, 232], [234, 179, 8], [161, 98, 7]
            );
          }

          covY = paragraph(
            ascii(`Per-band counts above should be read together with the adapter capability report in the method appendix: a band this hardware cannot tune will always show zero access points, which is a limit of the equipment and not a property of the environment. Coverage computed at ${section.row.computed_at} for mission ${section.missionId}.`),
            covY, { size: 8, color: [110, 110, 110] }
          );
          covY += 6;
        }
      }

      /*
        --- 6a2. SURVEY MAP ---

        A wardriving report had no picture of the drive. Every position was in a
        table and in the KML, and a reader who wanted to know where the survey
        actually went had to open a second file in another application. The route
        and the access points against it are the most legible thing this document
        can show, and they were the one thing it did not.

        The figure is rendered offscreen from the archived data, not captured from
        the preview map — see `surveyMap.ts` for why that distinction matters. It
        is drawn once for the whole export rather than per target, because the
        question it answers ("where did this go?") is about the survey.
      */
      if (surveyMap.image) {
        doc.addPage();
        tocEntries.push({ title: 'SURVEY MAP', page: (doc as any).internal.getNumberOfPages() });
        let mapY = sectionHeading('SURVEY MAP');

        const geo = geometry(doc);
        const drawW = geo.contentWidth;
        const drawH = Math.min(
          drawW * (surveyMap.height / Math.max(1, surveyMap.width)),
          geo.bottom - mapY - 34,
        );
        doc.addImage(surveyMap.image, 'JPEG', geo.left, mapY, drawW, drawH);
        doc.setDrawColor(180, 180, 180);
        doc.setLineWidth(0.3);
        doc.rect(geo.left, mapY, drawW, drawH, 'S');
        mapY += drawH + 6;

        /*
          The key is drawn, not described.

          It used to be a sentence naming the colours ("blue where ... amber
          where ..."), which asks a reader to hold a colour in their head, look
          back at the figure and match it. Severity has five levels; a sentence
          doing that is a sentence nobody finishes. Drawing the mark beside its
          label means the comparison is already made on the page.

          Only levels that actually occur are listed, with their counts, so the key
          doubles as the figure's own census and cannot imply a severity is present
          when it is not.
        */
        /*
          Only levels that occur, worst first, with 'no finding' last.

          It is last and it is grey rather than green on purpose. Green would read
          as "this one is safe", and that is a claim this document spends a whole
          appendix refusing to make: a survey is a short pass, and the method
          section says in terms that the absence of a finding is not evidence of
          absence. Grey says what actually happened - nothing was raised against
          this radio - and leaves green for a LOW finding, which is a judgment the
          rule set did reach.
        */
        /*
          What the GPS log actually shows, which is not always a drive.

          `routeFixes` counts samples and `routeSpanM` measures ground. They came
          apart badly on the survey this was written against - 280 fixes, 7.6 m of
          ground - and the figure used to report the first as if it were the
          second. A stationary survey is a legitimate thing to have done; printing
          it as a route is not, and the distinction is the explanation for most of
          the position quality section.
        */
        const routeSentence = surveyMap.hasRoute
          ? `The route shown is the recorded GPS track, spanning ${Math.round(surveyMap.routeSpanM)} m end to end.`
          : surveyMap.routeFixes > 1
            ? `No route is drawn. ${surveyMap.routeFixes} GPS fixes were recorded but they span only ${surveyMap.routeSpanM.toFixed(1)} m end to end - the receiver did not move. These positions were therefore inferred from a stationary vantage point, which is why so many of them are mirror-ambiguous: resolving which side of the receiver a transmitter sits on requires movement across a baseline, and there was none.`
            : 'No GPS track was recorded, so no route is drawn.';

        const presentLevels = [...SEVERITY_LEVELS, 'NONE' as const]
          .filter(l => (surveyMap.counts[l] ?? 0) > 0);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(6.5);
        doc.setTextColor(110, 110, 110);
        doc.text('KEY', geo.left, mapY + 2.6);
        let keyX = geo.left + 11;
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.5);
        for (const level of presentLevels) {
          const [r, g, b] = severityRgb(level);
          doc.setFillColor(r, g, b);
          doc.circle(keyX + 1.3, mapY + 1.6, 1.3, 'F');
          doc.setTextColor(60, 60, 60);
          const label = `${level === 'NONE' ? 'no finding' : level} ${surveyMap.counts[level]}`;
          doc.text(label, keyX + 4, mapY + 2.6);
          keyX += 4 + doc.getTextWidth(label) + 6;
        }

        // Second row: the two marks that are about certainty rather than severity,
        // plus the route - and the route only when one was actually recorded.
        let keyY = mapY + 7;
        let kx = geo.left + 11;
        const keyItem = (draw: () => void, label: string) => {
          draw();
          doc.setTextColor(60, 60, 60);
          doc.setFontSize(7.5);
          doc.text(label, kx + 4, keyY + 2.6);
          kx += 4 + doc.getTextWidth(label) + 6;
        };
        keyItem(() => {
          doc.setDrawColor(120, 120, 120);
          doc.setLineWidth(0.4);
          doc.circle(kx + 1.3, keyY + 1.6, 1.3, 'S');
        }, surveyMap.unresolved > 0 && surveyMap.ambiguous === 0
          ? 'position not resolved'
          : 'hollow: mirror candidate, or not resolved');
        keyItem(() => {
          doc.setDrawColor(150, 150, 150);
          doc.setLineWidth(0.3);
          doc.circle(kx + 1.3, keyY + 1.6, 1.8, 'S');
        }, '95% radius');
        if (surveyMap.hasRoute) {
          keyItem(() => {
            doc.setDrawColor(21, 128, 61);
            doc.setLineWidth(0.9);
            doc.line(kx, keyY + 1.6, kx + 2.6, keyY + 1.6);
          }, 'route driven');
        }
        mapY = keyY + 7;
        mapY = paragraph(
          ascii(
            `${surveyMap.plotted} access point(s) plotted, coloured by the same severity `
            + `the findings table gives them. `
            /*
              `mirrorsDrawn`, not `ambiguous`.

              `ambiguous` counts the APs the estimator flagged, and the flag column is
              independent of the mirror coordinate columns - which is why
              `isMirrorAmbiguous` ORs them. A twin is only drawn when both coordinates
              are present and finite, so this sentence used to claim more double dots
              than the figure has, and a reader counting them found the caption wrong.
              The flagged-but-undrawable case is named separately rather than folded in.
            */
            + (surveyMap.mirrorsDrawn > 0
              ? `${surveyMap.mirrorsDrawn} are mirror-ambiguous and so are drawn twice - a filled `
                + `dot and a hollow twin - because the measurements fit either position equally well `
                + `and this tool will not pick one for you. `
              : '')
            + (surveyMap.ambiguous > surveyMap.mirrorsDrawn
              ? `${surveyMap.ambiguous - surveyMap.mirrorsDrawn} further access point(s) are flagged `
                + `mirror-ambiguous but carry no second coordinate, so only one mark is drawn for each `
                + `- that mark is one of two equally good answers and the other was not recorded. `
              : '')
            + (surveyMap.unresolved > 0
              ? `${surveyMap.unresolved} are drawn hollow because no position could be derived for them `
                + `at all - the receiver never moved far enough for any estimator to run, so the mark is `
                + `where it stood and the radius is the only claim being made. `
              : '')
            + `${routeSentence} `
            + `No dot is a surveyed position; every one is inferred from signal strength `
            + `measured ${surveyMap.hasRoute ? 'along the route' : 'from where the receiver stood'}, `
            + `and the radius is the part to read. An area with no dots was not necessarily `
            + `empty - it may simply not have been ${surveyMap.hasRoute ? 'driven' : 'within range of the receiver'}.`
            + (surveyMap.ringsOmitted > 0
              ? ` ${surveyMap.ringsOmitted} radius ring(s) are wider than 120 m and are not drawn: at this scale each would span more of the frame than the survey does and hide the map. Those positions are still plotted, and every radius - drawn or not - is listed in POSITION QUALITY.`
              : '')
          ),
          mapY, { size: 8, color: [110, 110, 110], lead: 3.4 }
        );

        if (surveyMap.basemap === 'offline-grid') {
          mapY += 2;
          callout(
            mapY,
            'BASEMAP UNAVAILABLE - THIS IS A GRID, NOT CARTOGRAPHY',
            ascii(
              'The basemap could not be fetched when this document was generated, so the '
              + 'backdrop is the offline grid. Street layout, buildings and landmarks are '
              + 'absent for that reason and not because the area has none. The route and '
              + 'the access point positions are unaffected: they come from the survey, not '
              + 'from the basemap.'
            ),
            [254, 252, 232], [234, 179, 8], [161, 98, 7]
          );
        }
      }
}
