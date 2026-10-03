-- Exactly one active engagement, enforced by the file rather than by the UI.
--
-- 008 declared this invariant in a comment and left it to the application, on the
-- stated grounds that "SQLite has no clean partial-unique constraint for it across all
-- supported versions". That is not so: partial indexes have been in SQLite since 3.8.0,
-- released in 2013, which is far below anything `libsqlite3-sys` ships. The constraint
-- below makes two simultaneously-active scopes unrepresentable.
--
-- It matters more than a typical invariant because of what the row is. The active scope
-- is the tool's authorization record: `policy.py` gates every offensive command against
-- it, and the report's refusals section is written from the audit trail it produces. If
-- two were ever active at once, "which authorization covered this command?" would have
-- no answer -- and that question is the whole point of keeping the record.
--
-- There is no live bug to fix here. `activateScope` clears the active flag and then
-- sets it, in that order, so it satisfies this index; and if it failed between the two
-- statements it would leave zero active rows, which fails closed. This moves the
-- guarantee from a convention in TypeScript to something the database refuses to
-- violate, including against a future caller that does the two updates the other way
-- round, or a hand-edited database.
--
-- A separate migration rather than an edit to 018: sqlx checksums each migration over
-- its whole file text, so changing one that has already been applied is fatal at
-- startup for every installation that has it.

CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_engagement
    ON engagement_scope(is_active) WHERE is_active = 1;
