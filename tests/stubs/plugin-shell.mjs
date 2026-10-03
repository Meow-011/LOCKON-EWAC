/**
 * Stand-in for @tauri-apps/plugin-shell so the real ipc.ts can be exercised
 * under Node. It models the parts that matter for the connection state machine:
 * spawning is asynchronous, and killing a child is what closes the engine's
 * stdin.
 */

// State lives on globalThis so it is shared even if the bundler and the test
// end up with separate instances of this module.
const state = (globalThis.__ewacShellStub ??= { spawned: [], delay: 0, fail: false });

export const spawned = state.spawned;

export function resetShellStub({ delay = 0, fail = false } = {}) {
  state.spawned.length = 0;
  state.delay = delay;
  state.fail = fail;
}

export function liveChildren() {
  return state.spawned.filter(c => c.alive);
}

class FakeChild {
  constructor(id) {
    this.id = id;
    this.alive = true;
    this.written = [];
  }
  async write(data) {
    if (!this.alive) throw new Error('child is dead');
    this.written.push(data);
  }
  async kill() {
    this.alive = false;
    this.killedAt = Date.now();
  }
}

class FakeStream {
  constructor() { this.handlers = {}; }
  on(event, handler) { this.handlers[event] = handler; }
  emit(event, payload) { this.handlers[event]?.(payload); }
}

export class Command {
  constructor(program) {
    this.program = program;
    this.stdout = new FakeStream();
    this.stderr = new FakeStream();
    this.handlers = {};
  }
  static sidecar(program) { return new Command(program); }
  on(event, handler) { this.handlers[event] = handler; }
  async spawn() {
    if (state.delay) await new Promise(r => setTimeout(r, state.delay));
    if (state.fail) {
      state.fail = false;
      throw new Error('spawn failed: binary not found');
    }
    const child = new FakeChild(state.spawned.length + 1);
    child.command = this;
    state.spawned.push(child);
    return child;
  }
}
