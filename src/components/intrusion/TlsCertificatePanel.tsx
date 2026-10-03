/**
 * The TLS certificate panel in the node drawer.
 *
 * A move, not a rewrite: the body below is the IIFE that was nested twenty
 * columns deep inside `IntrusionPage`, unchanged apart from reading `cert` from a
 * prop instead of from `selectedHost.ssl_cert`.
 *
 * It was the cleanest thing in that file to take out first: the grade, the badges,
 * the expiry countdown, the cipher audit and the findings list reference almost
 * nothing from the page around them. They are a function of one object.
 *
 * This comment first said the move already had a net under it, because
 * `tests/components/tlsPanel.test.tsx` renders the page and asserts on TLS. It
 * does not cover this. That file drives the *TLS inspection* panel -- the button,
 * the NEGOTIATING state, the inconclusive checks -- which is a different block
 * three hundred lines away in the same drawer. Feeding this panel an empty object
 * left all 76 component tests green, which is how the claim was caught: the
 * extraction was checked by deliberately breaking it, and nothing noticed.
 *
 * `tests/components/tlsCertificatePanel.test.tsx` is the net now, and it exists
 * because the panel became a function of one prop -- which is the whole return on
 * the move. It pins the grade bands, since nothing else states them and a summary
 * a reader trusts without opening the findings underneath it must not drift
 * silently; that an absent expiry figure renders no badge rather than a zero,
 * because 0 there would read as "expires today"; and that an empty cipher audit
 * renders nothing rather than an empty bar that reads as clean.
 */

import { severityClasses } from '../../lib/severityStyle';

export function TlsCertificatePanel({ cert }: { cert: any }) {

      const findings: any[] = cert.findings || [];
    const highCount = findings.filter((f: any) => f.severity === 'HIGH').length;
    const medCount = findings.filter((f: any) => f.severity === 'MEDIUM').length;
    const isClean = findings.length === 1 && findings[0]?.severity === 'OK';

    // Compute SSL Grade
    let grade = 'A+', gradeColor = 'text-signal-strong', gradeBg = 'bg-signal-strong/10 border-signal-strong/30';
    if (highCount >= 2) { grade = 'D'; gradeColor = 'text-risk-critical'; gradeBg = 'bg-risk-critical/10 border-risk-critical/30'; }
    else if (highCount >= 1) { grade = 'C'; gradeColor = 'text-risk-high'; gradeBg = 'bg-risk-high/10 border-risk-high/30'; }
    else if (medCount >= 3) { grade = 'C'; gradeColor = 'text-amber-400'; gradeBg = 'bg-amber-400/10 border-amber-400/30'; }
    else if (medCount >= 1) { grade = 'B'; gradeColor = 'text-amber-300'; gradeBg = 'bg-amber-300/10 border-amber-300/30'; }
    else if (!isClean) { grade = 'A'; }

    const hstsEnabled = cert.hsts?.enabled;
    const weakCiphers: any[] = cert.cipher_audit?.weak || [];
    const strongCiphers: any[] = cert.cipher_audit?.strong || [];
    const daysLeft = cert.days_until_expiry;

    return (
      <div className="bg-space-950/30 border border-space-500/20 rounded-lg overflow-hidden">
        {/* Header with Grade */}
        <div className="flex items-center justify-between p-4 pb-3">
          <h4 className="text-[10px] font-tactical text-gray-400 tracking-wider flex items-center gap-2">
            <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            SSL/TLS CERTIFICATE
          </h4>
          <div className={`${gradeBg} border rounded-md px-2.5 py-1 flex items-center gap-1.5`}>
            <span className={`text-lg font-mono font-bold leading-none ${gradeColor}`}>{grade}</span>
            <span className="text-[7px] font-tactical text-gray-500 leading-tight">SSL<br/>GRADE</span>
          </div>
        </div>

        {/* Status Badges Row */}
        <div className="flex flex-wrap gap-1.5 px-4 pb-3">
          <span className={`text-[9px] font-tactical px-2 py-0.5 rounded border ${hstsEnabled ? 'border-signal-strong/40 bg-signal-strong/10 text-signal-strong' : 'border-amber-500/30 bg-amber-500/10 text-amber-400'}`}>
            {hstsEnabled ? '✓ HSTS' : '✗ HSTS'}
          </span>
          {cert.protocol && (
            <span className="text-[9px] font-tactical px-2 py-0.5 rounded border border-space-500/30 bg-space-900 text-gray-400">{cert.protocol}</span>
          )}
          {cert.self_signed && (
            <span className="text-[9px] font-tactical px-2 py-0.5 rounded border border-amber-500/30 bg-amber-500/10 text-amber-400">⚠ SELF-SIGNED</span>
          )}
          {weakCiphers.length > 0 && (
            <span className="text-[9px] font-tactical px-2 py-0.5 rounded border border-risk-critical/30 bg-risk-critical/10 text-risk-critical">⚠ WEAK CIPHER</span>
          )}
        </div>

        {/* Certificate Details */}
        {(cert.issuer || cert.cn) && (
          <div className="px-4 pb-3 text-[10px] font-mono text-gray-400 space-y-1.5">
            {cert.cn && (
              <div className="flex justify-between"><span className="text-gray-500 shrink-0">Subject:</span> <span className="text-gray-300 truncate ml-2">{cert.cn}</span></div>
            )}
            {cert.issuer && (
              <div className="flex justify-between"><span className="text-gray-500 shrink-0">Issuer:</span> <span className="text-gray-300 truncate ml-2">{cert.issuer}</span></div>
            )}
            {cert.protocol && cert.cipher_name && (
              <div className="flex justify-between"><span className="text-gray-500 shrink-0">Cipher:</span> <span className="text-gray-300 truncate ml-2">{cert.cipher_name}{cert.cipher_bits ? ` (${cert.cipher_bits}-bit)` : ''}</span></div>
            )}
            {/* Expiry with countdown badge */}
            {cert.expires && (
              <div className="flex justify-between items-center">
                <span className="text-gray-500 shrink-0">Expires:</span>
                <span className="flex items-center gap-2 ml-2">
                  <span className={cert.expired ? 'text-risk-critical' : 'text-gray-300'}>{cert.expires}</span>
                  {daysLeft != null && (
                    <span className={`text-[8px] font-tactical px-1.5 py-0.5 rounded border ${
                      cert.expired ? 'border-risk-critical/50 bg-risk-critical/10 text-risk-critical animate-pulse' :
                      daysLeft <= 30 ? 'border-risk-critical/50 bg-risk-critical/10 text-risk-critical' :
                      daysLeft <= 90 ? 'border-amber-500/30 bg-amber-500/10 text-amber-400' :
                      'border-signal-strong/30 bg-signal-strong/10 text-signal-strong'
                    }`}>
                      {cert.expired ? 'EXPIRED' : `${daysLeft}d LEFT`}
                    </span>
                  )}
                </span>
              </div>
            )}
          </div>
        )}

        {/* Cipher Audit Bar */}
        {(weakCiphers.length > 0 || strongCiphers.length > 0) && (
          <div className="px-4 pb-3">
            <div className="text-[9px] font-mono text-gray-600 mb-1.5 uppercase tracking-wider">Cipher Suite Audit</div>
            <div className="flex h-1.5 rounded-full overflow-hidden bg-space-800 border border-space-500/10">
              {strongCiphers.length > 0 && <div className="bg-signal-strong transition-all" style={{ width: `${(strongCiphers.length / (strongCiphers.length + weakCiphers.length)) * 100}%` }} />}
              {weakCiphers.length > 0 && <div className="bg-risk-critical transition-all" style={{ width: `${(weakCiphers.length / (strongCiphers.length + weakCiphers.length)) * 100}%` }} />}
            </div>
            <div className="flex justify-between mt-1 text-[8px] font-mono">
              <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-sm bg-signal-strong" />STRONG: {strongCiphers.length}</span>
              {weakCiphers.length > 0 && <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-sm bg-risk-critical" />WEAK: {weakCiphers.length}</span>}
            </div>
          </div>
        )}

        {/* Security Findings with Detail */}
        {findings.length > 0 && (
          <div className="px-4 pb-4 pt-3 border-t border-space-500/10 space-y-2">
            <div className="text-[9px] font-mono text-gray-600 uppercase tracking-wider">Security Findings</div>
            {findings.map((f: any, idx: number) => (
              <div key={idx} className={`text-[10px] font-mono flex items-start gap-1.5 ${
                f.severity === 'OK' ? 'text-signal-strong'
                  : f.severity === 'HIGH' || f.severity === 'MEDIUM' ? severityClasses(f.severity).text
                    : 'text-gray-400'
              }`}>
                <span className="mt-0.5 shrink-0">{f.severity === 'OK' ? '✓' : f.severity === 'HIGH' ? '✗' : '•'}</span>
                <div>
                  <span>{f.finding}</span>
                  {f.detail && <div className="text-[9px] text-gray-600 mt-0.5 pl-0.5">↳ {f.detail}</div>}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    );
}
