/**
 * Stand-in for @tauri-apps/plugin-sql.
 *
 * The vault tests exercise the parts of credentialDB that need no database —
 * decrypting credentials carried inside a report snapshot. This exists only so
 * the bundler can resolve the import, and it throws if anything actually
 * reaches for a connection, so a test that starts depending on the database
 * fails loudly rather than appearing to pass against a fake one.
 */
export default {
  load() {
    throw new Error(
      'plugin-sql stub: this test must not touch the database. '
      + 'If a new test needs one, model it explicitly rather than widening this stub.'
    );
  },
};
