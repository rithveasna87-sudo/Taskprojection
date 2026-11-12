-- Initial schema. Migrations run once, in filename order, each inside a transaction
-- (do not put BEGIN/COMMIT in here). Applied names are recorded in schema_migrations.

-- One row per task. `data` is the task as JSON (the app's own shape), so new task
-- fields never need a schema change. `position` keeps the board order (lowest = top).
CREATE TABLE tasks (
  id         TEXT PRIMARY KEY,
  position   INTEGER NOT NULL,
  data       TEXT NOT NULL,
  rev        INTEGER NOT NULL,      -- database revision at which this task last changed
  updated_at TEXT NOT NULL
);
CREATE INDEX tasks_position ON tasks (position);

-- Shared attachments (max 5 MB each, enforced by the server).
CREATE TABLE files (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  type       TEXT NOT NULL,
  size       INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  content    BLOB NOT NULL
);

-- Small key/value table. `rev` is the database revision: it goes up by one in the same
-- transaction as every task change, and every connected browser is told when it moves.
CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT INTO meta (key, value) VALUES ('rev', '0');
