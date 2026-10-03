/**
 * Single bundle entry for the database tests.
 *
 * One entry for the same reason the vault tests have one: `database.ts` caches
 * the open connection in module state. Bundling each module separately would
 * give each its own cached connection — and its own database — so a row written
 * through one export would be invisible to another, and the tests would pass or
 * fail on bundling order rather than on behaviour.
 */
export * from '../../src/lib/wardrivingDB';
export * from '../../src/lib/coverageDB';
export { getDb, reclaimFreePages } from '../../src/lib/database';
export {
  upsertFindings,
  createBaseline,
  compareToBaseline,
  getFindings,
  setFindingStatus,
  getFindingsSummary,
  recordEvidence,
  listBaselines,
  getEvidence,
  getAllEvidenceForVerification,
  recordClient,
  getClients,
  getClientsForBssid,
} from '../../src/lib/findingsDB';
export * from '../../src/lib/scopeDB';
export * from '../../src/lib/intrusionDB';
export * from '../../src/lib/reportDB';
export * from '../../src/lib/crackingDB';
export {
  createVault,
  openVault,
  getVaultStatus,
  sealLegacyCredentials,
  saveCredential,
  getCredentialsForArchive,
} from '../../src/lib/credentialDB';
export { isUnlocked, lockVault, VaultLockedError } from '../../src/lib/vaultCrypto';
export * from '../../src/lib/scopeSync';
export { engineIPC } from '../../src/lib/ipc';

/*
  The report assembler, tested against the same real SQLite the DB modules use.

  It is here rather than in its own entry because almost everything it does is a
  database read reconciled against another one — deduplicating a finding seen in
  two archives, keeping the better-informed rogue verdict, deciding whether a
  coverage row is the archive's frozen copy or a recomputed one. A stubbed
  select() would prove it calls the right functions and nothing about the
  numbers, which are the whole point.
*/
export { assembleReportData } from '../../src/lib/report/assemble';
export { useEngineStore } from '../../src/stores/engineStore';

/*
  The engine event router, and the stores it writes into.

  Exported here so a test can connect the real `ipc.ts`, register the real
  handlers, feed a line of JSON down the stub child's stdout and assert what
  landed. That whole path was unreachable while the handlers lived inside
  `AppShell`'s closure.
*/
export { registerEngineHandlers } from '../../src/lib/engineRouter';
export { useMissionStore } from '../../src/stores/missionStore';
export { useIntrusionStore } from '../../src/stores/intrusionStore';
export { liveChildren, resetShellStub } from '../stubs/plugin-shell.mjs';

/*
  The four stores that had no tests. Bundled here because `reportStore` writes
  through `reportDB` to SQLite, and the interesting cases are the ones where that
  write fails.
*/
export { useReportStore } from '../../src/stores/reportStore';
export { usePassiveSigintStore } from '../../src/stores/passiveSigintStore';
export { useStrikeStore } from '../../src/stores/strikeStore';
export { useUIStore } from '../../src/stores/uiStore';
