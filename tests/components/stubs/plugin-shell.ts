/**
 * The Tauri shell plugin, for component tests.
 *
 * A component test must never spawn the real sidecar, and it must not quietly behave as
 * though one is attached either: `src/lib/ipc.ts` throws "Engine not connected" when
 * `child` is null, and several of the behaviours worth testing are exactly what the
 * interface does when that happens.
 *
 * So the spawn outcome is settable. `setSpawnBehaviour('fail')` is how a test reaches
 * the path where `engineIPC.send` rejects — the one that used to leave Passive SIGINT
 * showing ACTIVE while nothing was recording.
 */
type Behaviour = 'ok' | 'fail';
let behaviour: Behaviour = 'ok';

export function setSpawnBehaviour(next: Behaviour) {
  behaviour = next;
}

export function resetShellStub() {
  behaviour = 'ok';
  spawned.length = 0;
}

export const spawned: FakeChild[] = [];

class FakeStream {
  private handlers: ((line: string) => void)[] = [];

  on(_event: string, handler: (line: string) => void) {
    this.handlers.push(handler);
  }

  /** Push a line as the engine would. */
  emit(_event: string, line: string) {
    for (const h of [...this.handlers]) h(line);
  }
}

class FakeChild {
  written: string[] = [];
  alive = true;

  async write(data: string) {
    if (!this.alive) throw new Error('stdin closed');
    this.written.push(data);
  }

  async kill() {
    this.alive = false;
  }
}

class FakeCommand {
  stdout = new FakeStream();
  stderr = new FakeStream();
  private handlers: Record<string, ((p: unknown) => void)[]> = {};

  on(event: string, handler: (p: unknown) => void) {
    (this.handlers[event] ??= []).push(handler);
  }

  /** Fire a lifecycle event, e.g. `close`. */
  fire(event: string, payload: unknown) {
    for (const h of this.handlers[event] ?? []) h(payload);
  }

  async spawn() {
    if (behaviour === 'fail') throw new Error('spawn failed: binary not found');
    const child = new FakeChild();
    spawned.push(child);
    (this as unknown as { child: FakeChild }).child = child;
    lastCommand = this;
    return child;
  }
}

/** The most recently constructed command, so a test can push stdout lines. */
export let lastCommand: FakeCommand | null = null;

export const Command = {
  sidecar(_path: string) {
    const c = new FakeCommand();
    lastCommand = c;
    return c;
  },
};
