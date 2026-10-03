/**
 * The certificate card in the node drawer.
 *
 *     npm run test:components
 *
 * Why this exists, and why it did not before.
 *
 * This panel grades a certificate A+ to D, counts weak ciphers, flags HSTS and
 * counts down to expiry — and it had no coverage at all. The file it lived in has
 * three component tests, and when it was extracted the assumption was that one of
 * them, `tlsPanel.test.tsx`, was already covering it.
 *
 * It is not. That file drives the *TLS inspection* panel — the button, the
 * NEGOTIATING state, the inconclusive checks — which is a different block three
 * hundred lines away in the same drawer. Feeding this panel an empty object left
 * all 76 component tests green, which is how the mistake was found: the extraction
 * was checked by deliberately breaking it, and nothing noticed.
 *
 * So the net claimed for the move did not exist, and this is it. The panel is a
 * function of one object now, which is what makes it testable without the page.
 */
import { describe, expect, test } from 'vitest';
import { render, screen } from '@testing-library/react';

import { TlsCertificatePanel } from '../../src/components/intrusion/TlsCertificatePanel';

const CERT = (over = {}) => ({
  cn: 'web-01.local',
  issuer: 'Internal CA',
  expires: '2027-01-01',
  days_until_expiry: 400,
  findings: [],
  ...over,
});

const finding = (severity: string) => ({ severity, title: `a ${severity} finding`, detail: 'detail' });

describe('the grade', () => {
  test('a clean certificate is not graded down', () => {
    render(<TlsCertificatePanel cert={CERT({ findings: [{ severity: 'OK', title: 'clean' }] })} />);
    expect(screen.getByText('A+')).toBeTruthy();
  });

  test('one HIGH finding is a C and two are a D', () => {
    /*
      The bands are the panel's own judgement and nothing else states them, so
      they are pinned here. A grade that silently drifts is worse than no grade:
      it is a summary a reader trusts without opening the findings underneath it.
    */
    const { unmount } = render(<TlsCertificatePanel cert={CERT({ findings: [finding('HIGH')] })} />);
    expect(screen.getByText('C')).toBeTruthy();
    unmount();

    render(<TlsCertificatePanel cert={CERT({ findings: [finding('HIGH'), finding('HIGH')] })} />);
    expect(screen.getByText('D')).toBeTruthy();
  });

  test('MEDIUM findings degrade the grade in two steps', () => {
    const { unmount } = render(<TlsCertificatePanel cert={CERT({ findings: [finding('MEDIUM')] })} />);
    expect(screen.getByText('B')).toBeTruthy();
    unmount();

    render(<TlsCertificatePanel cert={CERT({ findings: [finding('MEDIUM'), finding('MEDIUM'), finding('MEDIUM')] })} />);
    expect(screen.getByText('C')).toBeTruthy();
  });

  test('a scan that raised nothing at all is not the same as a clean one', () => {
    /*
      `isClean` requires a single explicit OK finding. An empty list means the
      scan produced nothing, which this tool does not report as a pass — the
      grade drops to A rather than staying at A+.
    */
    render(<TlsCertificatePanel cert={CERT({ findings: [] })} />);
    expect(screen.getByText('A')).toBeTruthy();
    expect(screen.queryByText('A+')).toBeNull();
  });
});

describe('expiry', () => {
  test('an expired certificate says so rather than counting down', () => {
    render(<TlsCertificatePanel cert={CERT({ expired: true, days_until_expiry: -5 })} />);
    expect(screen.getByText('EXPIRED')).toBeTruthy();
    expect(screen.queryByText(/-5d LEFT/)).toBeNull();
  });

  test('a countdown is shown when there is one', () => {
    render(<TlsCertificatePanel cert={CERT({ days_until_expiry: 12 })} />);
    expect(screen.getByText('12d LEFT')).toBeTruthy();
  });

  test('no expiry figure renders no badge rather than a zero', () => {
    // `days_until_expiry` absent is "not reported", and a 0 there would read as
    // "expires today" — the distinction this whole project is built around.
    render(<TlsCertificatePanel cert={CERT({ days_until_expiry: null })} />);
    expect(screen.queryByText(/d LEFT/)).toBeNull();
    expect(screen.queryByText('EXPIRED')).toBeNull();
  });
});

describe('HSTS and ciphers', () => {
  test('HSTS is stated either way, never omitted', () => {
    const { unmount } = render(<TlsCertificatePanel cert={CERT({ hsts: { enabled: true } })} />);
    expect(screen.getByText(/HSTS/)).toBeTruthy();
    unmount();

    render(<TlsCertificatePanel cert={CERT({ hsts: { enabled: false } })} />);
    expect(screen.getByText(/HSTS/)).toBeTruthy();
  });

  test('a weak cipher is counted and flagged', () => {
    /*
      The panel does not name the weak cipher, only counts it — the badge and the
      bar say "one of these is weak" and the operator opens the engine's own
      output for which. That is a deliberate limit of this card and it is asserted
      so the test does not drift into claiming it names them.
    */
    render(<TlsCertificatePanel cert={CERT({
      cipher_audit: {
        weak: [{ name: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA' }],
        strong: [{ name: 'TLS_AES_256_GCM_SHA384' }],
      },
    })} />);
    expect(screen.getByText(/WEAK CIPHER/)).toBeTruthy();
    expect(screen.getByText(/WEAK: 1/)).toBeTruthy();
    expect(screen.getByText(/STRONG: 1/)).toBeTruthy();
  });

  test('no cipher audit renders no bar, rather than an empty one reading as clean', () => {
    render(<TlsCertificatePanel cert={CERT()} />);
    expect(screen.queryByText(/WEAK CIPHER/)).toBeNull();
    expect(screen.queryByText(/STRONG:/)).toBeNull();
  });
});

test('a certificate with almost nothing in it still renders', () => {
  // The panel is handed whatever the engine recorded, and a sweep that reached a
  // service without completing the inspection records very little.
  render(<TlsCertificatePanel cert={{}} />);
  expect(screen.getByText(/SSL\/TLS CERTIFICATE/i)).toBeTruthy();
});
