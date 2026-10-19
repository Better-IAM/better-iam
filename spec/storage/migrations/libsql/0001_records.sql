CREATE TABLE IF NOT EXISTS iam_records (collection TEXT NOT NULL, id TEXT NOT NULL, tenant_id TEXT NOT NULL, unique_key TEXT, data TEXT NOT NULL, PRIMARY KEY (collection, id), UNIQUE (collection, tenant_id, unique_key));
CREATE INDEX IF NOT EXISTS iam_records_tenant ON iam_records (collection, tenant_id);
