CREATE TABLE IF NOT EXISTS iam_schema_version (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL);
SELECT version FROM iam_schema_version WHERE id = 1;
CREATE TABLE IF NOT EXISTS iam_migrations (name TEXT PRIMARY KEY, applied_at BIGINT NOT NULL);
SELECT name FROM iam_migrations;
INSERT INTO iam_migrations (name, applied_at) VALUES ($1, $2);
INSERT INTO iam_schema_version (id, version) VALUES (1, 1) ON CONFLICT (id) DO NOTHING;
