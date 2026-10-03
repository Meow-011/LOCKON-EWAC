/**
 * LOCKON EWAC — the screenshots in the README, taken from the running program.
 *
 *     npm run previews            # drives the built app
 *     npm run previews -- --dev   # drives `npm run tauri dev`
 *
 * Why this is a script and not a folder of images somebody made.
 *
 * A preview is a claim about what the program looks like. A mockup is that claim
 * without the measurement behind it, and this project does not make claims that
 * way anywhere else. So the pictures come out of the application over the same
 * Chrome DevTools Protocol connection the export and benchmark harnesses use, and
 * they can be retaken in a minute when a surface changes — which is the only way
 * a screenshot in a README stays true.
 *
 * ── Why the survey is simulated ────────────────────────────────────────────
 *
 * Every archive on the machine this was first run on held live field data: real
 * BSSIDs, real SSIDs, and GPS fixes accurate enough to name the street they were
 * recorded on. Publishing that in a README would publish a vulnerability
 * assessment of somebody else's network alongside the coordinates of their
 * building, and the operator's own address with it.
 *
 * `SIMULATION OVERRIDE` in Settings exists for rehearsal and is exactly the right
 * tool here: `engine/scanner/simulator.py` drives a scenario of invented access
 * points — `NBU-CORP`, a planted rogue at `DE:AD:BE:11:22:33` — along a route from
 * `DEFAULT_ORIGIN`, a fixed public coordinate in central Bangkok that has nothing
 * to do with wherever the machine is. Everything it produces is stamped
 * `simulated: True`, and the interface says `SIMULATED SURVEY RUNNING — NOT FIELD
 * EVIDENCE` while it runs, so a reader of these images is not being shown a field
 * result dressed as one.
 *
 * The two pages that have nothing to simulate — INTRUSION and DECRYPTOR — are
 * captured in their resting state rather than against a real LAN sweep.
 *
 * ── One thing is redacted, and the README says so ──────────────────────────
 *
 * INTRUSION shows the network the machine is *currently joined to*, read from
 * `netContext`, so that an operator can see what they are about to sweep. That is
 * the right thing for the application to show and the wrong thing to publish: it
 * is the author's own Wi-Fi, and simulation does not touch it because it is not
 * survey data.
 *
 * The chip is overwritten with a visible marker before the frame is taken, rather
 * than replaced with a plausible-looking fake name. A screenshot quietly edited to
 * read OFFICE-WIFI would be the same kind of claim this project refuses everywhere
 * else; `[network name redacted]` tells the reader a thing was removed and that
 * nothing else was.
 */
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import {
  refuseIfAppAlreadyRunning, waitForDebugger, launchApp, connect, pollFor,
  shutdownApp, Session, RELEASE_EXE,
} from './cdp.mjs';

const DEV = process.argv.includes('--dev');
const PORT = 9224;
const OUT = 'docs/images';

/** 16:10 at 1x. Large enough to read a table, small enough to commit. */
const WIDTH = 1600;
const HEIGHT = 1000;

const log = (...a) => console.log('[previews]', ...a);
const sleep = ms => new Promise(r => setTimeout(r, ms));

class PatientSession extends Session {
  send(method, params = {}, timeoutMs = 120000) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
      setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(`${method} timed out`));
      }, timeoutMs);
    });
  }
}

async function click(session, what, expr) {
  const ok = await session.evaluate(
    `(() => { const el = ${expr}; if (!el) return false; el.click(); return true; })()`);
  if (!ok) throw new Error(`could not click ${what}`);
  await sleep(600);
}

const navLink = (name) =>
  `[...document.querySelectorAll('a')].find(a => /^\\s*${name}\\s*$/i.test((a.textContent || '').trim()))`;

async function shot(session, name) {
  /*
    A frame is requested and then given a moment: framer-motion animates almost
    every surface in, and a capture fired the instant a route changes catches the
    page at 40% opacity mid-transition. Nothing in the screenshot says so — it
    just looks like a washed-out design.
  */
  await sleep(1400);
  const { data } = await session.send('Page.captureScreenshot', { format: 'png' });
  const path = join(OUT, `${name}.png`);
  writeFileSync(path, Buffer.from(data, 'base64'));
  const kb = (Buffer.from(data, 'base64').length / 1024).toFixed(0);
  log(`  wrote ${path} (${kb} KB)`);
  return path;
}

async function main() {
  if (!DEV && !existsSync(RELEASE_EXE)) {
    console.error(`[previews] ${RELEASE_EXE} does not exist. Run \`npm run tauri build\` first.`);
    process.exit(2);
  }
  mkdirSync(OUT, { recursive: true });
  await refuseIfAppAlreadyRunning(PORT, 'previews');

  const { app } = launchApp(PORT, DEV ? 'dev' : 'release');
  const written = [];
  try {
    const page = await waitForDebugger(PORT, 120000);
    const session = await connect(page, PatientSession);
    await session.send('Runtime.enable');
    await session.send('Page.enable');

    /*
      A fixed viewport, so the five images are the same shape and a UI change is
      the only thing that can move between two runs of this script.
    */
    await session.send('Emulation.setDeviceMetricsOverride', {
      width: WIDTH, height: HEIGHT, deviceScaleFactor: 1, mobile: false,
    });

    await pollFor(session, 'the window to render',
      `(() => !!document.body && document.body.innerText.length > 50)()`, 120000, log);
    await pollFor(session, 'engine ONLINE',
      `(() => /Engine:\\s*ONLINE/i.test(document.body.innerText || ''))()`, 120000, log);
    log('engine is up');

    // ── Turn the radio off and the scenario on ──────────────────────────────
    log('--- Settings: enabling SIMULATION OVERRIDE');
    await click(session, 'the Settings nav link', navLink('Settings'));
    await pollFor(session, 'the Settings screen',
      `(() => /SIMULATION OVERRIDE/i.test(document.body.innerText || ''))()`, 30000, log);

    const already = await session.evaluate(`(() => {
      const label = [...document.querySelectorAll('label')]
        .find(l => /SIMULATION OVERRIDE/i.test(l.textContent || ''));
      if (!label) return null;
      const row = label.closest('div')?.parentElement;
      const btn = row?.querySelector('button');
      if (!btn) return null;
      // The toggle's knob sits at translate-x-6 when it is on.
      return /translate-x-6/.test(btn.innerHTML) ? 'on' : 'off';
    })()`);
    if (already === null) throw new Error('could not find the SIMULATION OVERRIDE toggle');
    if (already === 'off') {
      await click(session, 'the SIMULATION OVERRIDE toggle', `(() => {
        const label = [...document.querySelectorAll('label')]
          .find(l => /SIMULATION OVERRIDE/i.test(l.textContent || ''));
        return label.closest('div')?.parentElement?.querySelector('button');
      })()`);
      log('  simulation override turned on');
    } else {
      log('  simulation override was already on');
    }

    // ── Dashboard, with a scenario running ──────────────────────────────────
    log('--- Dashboard: running a simulated survey');
    await click(session, 'the Dashboard nav link', navLink('Dashboard'));
    await sleep(1500);

    await click(session, 'START SCAN', `[...document.querySelectorAll('button')]`
      + `.find(b => /START SCAN/i.test((b.textContent || '').trim()))`);

    /*
      Long enough for the vehicle to move along the route and for the localizer to
      have more than one reading per access point, because a dashboard showing one
      contact and no track is a screenshot of nothing happening.
    */
    log('  letting the scenario run for 70s');
    await sleep(70000);
    written.push(await shot(session, 'dashboard'));

    /*
      Three steps, not one. Pausing stops the radio; the mission is still open, and
      `Archive` does not appear until it is closed. The first version of this
      clicked Pause and went looking for the archive, found the list unchanged, and
      — correctly — refused to photograph the live survey sitting at the top of it.

      Exact label matches throughout: `Archive` and `Mission Archive` are different
      buttons a few pixels apart, and a substring match opens a drawer instead of
      filing a survey.
    */
    const exactButton = (label) => `[...document.querySelectorAll('button')]`
      + `.find(b => (b.textContent || '').trim().toLowerCase() === '${label.toLowerCase()}')`;

    log('  pausing the scan');
    await click(session, 'Pause', exactButton('Pause'));
    await sleep(2500);

    log('  ending the mission, which is what reveals Archive');
    await click(session, 'End Mission', exactButton('End Mission'));
    await sleep(2500);

    log('  filing the archive');
    await click(session, 'Archive', exactButton('Archive'));

    /*
      The button says Saving… then Saved, and only says Saved once the insert
      resolved — its own comment records that it used to claim success before the
      write was attempted. Waiting for the word is waiting for the row.
    */
    await pollFor(session, 'the archive to be written',
      `(() => [...document.querySelectorAll('button')]`
      + `.some(b => /^saved$/i.test((b.textContent || '').trim())))()`, 30000, log);
    log('  archive saved');
    await sleep(1500);

    // ── The other four ──────────────────────────────────────────────────────
    /*
      Returns how many chips it rewrote, so a run that redacted nothing is visible.
      If the markup for that chip changes, this silently stops finding it --- and a
      zero here is the only warning that the next screenshot carries a real SSID.
    */
    const redactJoinedNetwork = `(() => {
      const chips = [...document.querySelectorAll('div')].filter(d =>
        typeof d.className === 'string'
        && d.className.includes('bg-neon-500/10')
        && d.className.includes('font-tactical')
        && d.querySelector('svg')
        && (d.textContent || '').trim().length > 0);
      let n = 0;
      for (const chip of chips) {
        for (const node of [...chip.childNodes]) {
          if (node.nodeType === 3 && node.textContent.trim()) {
            node.textContent = ' [network name redacted] ';
            n++;
          }
        }
      }
      return n;
    })()`;

    for (const [nav, file, settle] of [
      ['INTRUSION', 'intrusion', 2000],
      ['DECRYPTOR', 'decryptor', 2000],
      ['Settings', 'settings', 2000],
    ]) {
      log(`--- ${nav}`);
      await click(session, `the ${nav} nav link`, navLink(nav));
      await sleep(settle);

      if (nav === 'INTRUSION') {
        const n = await session.evaluate(redactJoinedNetwork);
        if (n === 0) {
          throw new Error(
            'the joined-network chip was not found, so nothing was redacted. Its '
            + 'markup has changed; fix the selector before taking this screenshot, '
            + 'because the unredacted version publishes the operator\'s own SSID.');
        }
        log(`  redacted ${n} joined-network chip(s)`);
      }

      written.push(await shot(session, file));
    }

    log('--- Reports: opening the simulated archive');
    await click(session, 'the Reports nav link', navLink('Reports'));
    await pollFor(session, 'the Reports screen',
      `(() => !!document.querySelector('[data-report-row]'))()`, 30000, log);

    /*
      The newest archive is the one the scan above just filed. Asserted rather than
      assumed: opening a live archive here would put real BSSIDs and a real street
      into the README, which is the single thing this script exists to avoid.
    */
    const newest = await session.evaluate(
      `document.querySelector('[data-report-row]')?.getAttribute('data-report-row') ?? null`);
    if (!newest) throw new Error('no archived report to open');
    await click(session, `archive ${newest}`,
      `document.querySelector('[data-report-row="${newest}"]')`);
    await sleep(3000);

    const simulated = await session.evaluate(
      `(() => /SIMULAT/i.test(document.body.innerText || ''))()`);
    if (!simulated) {
      throw new Error(
        `the opened archive ${newest} is not marked as simulated. Refusing to `
        + 'photograph live survey data for the README.');
    }
    log(`  ${newest} is marked simulated`);
    written.push(await shot(session, 'reports'));

    log(`done: ${written.length} image(s)`);
  } finally {
    await shutdownApp(app).catch(() => {});
  }
}

main().catch(e => { console.error('[previews] FAILED —', e.message); process.exit(1); });
