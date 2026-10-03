/**
 * Section 11 of the report: recovered credentials, masked unless the operator disclosed them.
 *
 * Moved out of `buildAndSavePDF` verbatim: the body below is the code that was
 * inline, unchanged. The only edits are the values it now takes as parameters
 * instead of reading them from the closure, and `npm run test:export` was run
 * before and after to confirm the document says exactly what it said.
 */
import autoTable from 'jspdf-autotable';
import { maskSecret } from '../archive';
import { geometry, TABLE_MARGIN } from '../geometry';
import type { ReportData } from '../assemble';
import type { PdfLayout } from '../layout';

export interface GlobalCredentialsOptions {
  /**
   * Whether the operator chose to export the secrets in the clear.
   *
   * A property of this export rather than of the data: the same archive exports
   * masked or disclosed, and the footer stamps the page differently for each.
   */
  discloseCredentials: boolean;
}

/**
 * Returns the page the cleartext credentials landed on, or null.
 *
 * The footer needs it: a page carrying real secrets is stamped differently from
 * the rest of the document. It was a `let` in the enclosing closure, read several
 * hundred lines later; returning it keeps that dependency visible instead of
 * leaving it to a variable two sections apart.
 */
export function renderGlobalCredentials(
  layout: PdfLayout,
  data: ReportData,
  { discloseCredentials }: GlobalCredentialsOptions,
): number | null {
  const { doc, tocEntries, callout } = layout;
  const { allCredentials } = data;
      // --- 11. GLOBAL CREDENTIALS (masked by default) ---
      // A report that gets emailed to a manager must not double as a credential
      // dump. Masked output still proves recovery — target, service, account,
      // source, discovery time and secret length are all preserved in full.
  let credentialsPageNum: number | null = null;
      if (allCredentials.length > 0) {
        doc.addPage();
        const credPage = (doc as any).internal.getNumberOfPages() as number;
        credentialsPageNum = credPage;
        tocEntries.push({
          title: `RECOVERED CREDENTIALS [${discloseCredentials ? 'CLEARTEXT' : 'MASKED'}]`,
          page: credPage,
        });

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(16);
        doc.setTextColor(220, 38, 38);
        doc.text('CRITICAL: RECOVERED CREDENTIALS', 14, 25);
        doc.setDrawColor(220, 38, 38);
        doc.setLineWidth(1);
        doc.line(geometry(doc).left, 28.5, geometry(doc).right, 28.5);
        doc.setLineWidth(0.5);

        let credY = 38;
        if (discloseCredentials) {
          credY = callout(
            credY,
            'CLEARTEXT DISCLOSURE - THIS PAGE CONTAINS USABLE PASSWORDS',
            `Full-disclosure export was explicitly enabled by the operator, so the ${allCredentials.length} recovered password(s) below appear in full. From this point the file is itself a credential store: it must not be emailed, attached to a ticket, or stored anywhere the accounts it unlocks are not already trusted. If this document is being circulated for remediation sign-off, re-export it with disclosure OFF - the masked version proves the same finding.`,
            [254, 242, 242], [220, 38, 38], [220, 38, 38]
          );
        } else {
          credY = callout(
            credY,
            'PASSWORDS MASKED - SAFE TO CIRCULATE FOR REMEDIATION',
            `Passwords are masked as first character, asterisks, last character, with the true length in parentheses. That is enough to confirm each credential was genuinely recovered and to identify weak or default secrets, without this document becoming a usable credential dump. Everything a reader needs to act - host, service and port, account name, how it was obtained and when - is given in full below. The complete secrets remain in the local credential vault; re-export with FULL DISCLOSURE enabled only if a cleartext copy is genuinely required.`,
            [240, 253, 244], [16, 185, 129], [13, 148, 136]
          );
        }

        /**
         * A credential the vault could not decrypt must never be rendered by
         * maskSecret: it returns "(empty) (len 0)", which reads as "the password
         * is blank" — a confidently wrong statement about a live account, in the
         * one table a reader acts on directly.
         */
        const credentialCell = (c: any): string => {
          if (c.decrypt_error) return 'UNREADABLE - wrong vault key or altered ciphertext';
          if (c.locked || c.password === null || c.password === undefined) {
            return 'NOT EXPORTED - vault locked';
          }
          return discloseCredentials ? String(c.password) : maskSecret(c.password);
        };

        const withheldCount = allCredentials.filter(
          (c: any) => c.decrypt_error || c.locked || c.password === null || c.password === undefined
        ).length;

        if (withheldCount > 0) {
          credY = callout(
            credY,
            `${withheldCount} OF ${allCredentials.length} SECRETS COULD NOT BE READ`,
            `${withheldCount} recovered password(s) are listed without their secret, because the credential vault was locked when this report was generated or the archive was sealed under a different vault's key. The finding still stands - the account, host and service are recorded, and each was verified at the time it was obtained - but this document cannot be used to confirm the secret itself. Unlock the vault and re-export if the passwords are needed.`,
            [254, 252, 232], [234, 179, 8], [161, 98, 7]
          );
        }

        const credsBody = allCredentials.map((c: any) => [
          c.hostname ? `${c.target_ip}\n(${c.hostname})` : String(c.target_ip ?? 'unknown'),
          `${String(c.service ?? 'unknown').toUpperCase()}${c.port ? ` / ${c.port}` : ''}`,
          String(c.username ?? ''),
          credentialCell(c),
          String(c.source ?? 'unknown').toUpperCase().replace(/_/g, ' '),
          c.discovered_at ? String(c.discovered_at) : 'not recorded',
        ]);

        autoTable(doc, {
          startY: credY,
          head: [[
            'Target',
            'Service / Port',
            'Username',
            discloseCredentials ? 'Password (CLEARTEXT)' : 'Password (MASKED)',
            'Source',
            'Discovered',
          ]],
          body: credsBody,
          theme: 'grid',
          headStyles: { fillColor: [220, 38, 38], textColor: 255, fontSize: 8.5 },
          styles: { fontSize: 8.5, font: 'courier', cellPadding: 2, overflow: 'linebreak', textColor: [0, 0, 0] },
          columnStyles: {
            0: { cellWidth: 30 },
            1: { cellWidth: 26 },
            2: { cellWidth: 26 },
            3: { cellWidth: 34, fontStyle: 'bold' },
            4: { cellWidth: 24 },
            5: { cellWidth: 38 },
          },
          margin: TABLE_MARGIN,
          didParseCell: (data) => {
            if (data.section === 'body' && data.column.index === 3 && discloseCredentials) {
              data.cell.styles.textColor = [220, 38, 38];
            }
          }
        });
      }
  return credentialsPageNum;
}
