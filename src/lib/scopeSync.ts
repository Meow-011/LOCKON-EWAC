/**
 * LOCKON EWAC — Push the active engagement scope to the engine.
 *
 * The engine keeps its own copy of the scope and refuses offensive commands
 * against anything outside it. That copy has to be refreshed whenever the
 * engine (re)connects and whenever the operator changes the engagement, or the
 * gate would be running against a stale allowlist.
 */
import { engineIPC } from './ipc';
import { buildScopePayload } from './scopeDB';

/**
 * Send the active scope (or a cleared scope when none is active) to the engine.
 * Returns the payload that was sent so callers can show what is now in force.
 * Throws if the engine is not connected — callers should surface that rather
 * than assume the gate was armed.
 */
export async function pushScopeToEngine(operator?: string | null) {
  const payload = await buildScopePayload(operator);
  await engineIPC.send('set_scope', payload as unknown as Record<string, unknown>);
  return payload;
}

/** Ask the engine what scope it currently believes is in force. */
export async function requestScopeStatus() {
  await engineIPC.send('get_scope');
}
