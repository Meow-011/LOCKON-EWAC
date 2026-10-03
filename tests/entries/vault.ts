/**
 * Single bundle entry for the vault tests.
 *
 * vaultCrypto holds the derived key in module state. Bundling it twice — once on
 * its own and once inside credentialDB — would give the test two separate keys,
 * so unlocking through one export would leave the other locked and the archive
 * tests would pass or fail for the wrong reason. One entry, one instance.
 */
export * from '../../src/lib/vaultCrypto';
export { revealArchivedCredentials } from '../../src/lib/credentialDB';
