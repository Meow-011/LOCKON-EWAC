/**
 * `@tauri-apps/api/core`, for component tests.
 *
 * `invoke` reaches the Rust host, which a browser does not have. Commands are scripted
 * per test; an unscripted one throws rather than resolving undefined, because a
 * component that reads a vitals figure from `undefined` renders something, and a test
 * that passes on that is worse than no test.
 */
const handlers = new Map<string, (args: unknown) => unknown>();
export const invoked: { cmd: string; args: unknown }[] = [];

export function whenInvoke(cmd: string, handler: (args: unknown) => unknown) {
  handlers.set(cmd, handler);
}

export function resetInvokeStub() {
  handlers.clear();
  invoked.length = 0;
}

export async function invoke<T>(cmd: string, args?: unknown): Promise<T> {
  invoked.push({ cmd, args });
  const handler = handlers.get(cmd);
  if (!handler) {
    throw new Error(
      `api-core stub: command '${cmd}' was invoked but not scripted. `
      + 'Script it with `whenInvoke(cmd, handler)`.',
    );
  }
  return handler(args) as T;
}

export function convertFileSrc(path: string) {
  return path;
}
