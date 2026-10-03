/**
 * The Tauri dialog plugin, for component tests.
 *
 * `open()` returns whatever a test sets. The default is null — the operator cancelling —
 * because that is the branch most easily left unhandled, and a stub that always returns
 * a path would hide it.
 */
let nextPath: string | string[] | null = null;

export function setDialogResult(path: string | string[] | null) {
  nextPath = path;
}

export function resetDialogStub() {
  nextPath = null;
}

export async function open(_options?: unknown) {
  return nextPath;
}

export async function save(_options?: unknown) {
  return nextPath;
}
