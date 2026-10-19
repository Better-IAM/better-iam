CREATE TABLE IF NOT EXISTS iam_records (collection TEXT COLLATE "C" NOT NULL, id TEXT COLLATE "C" NOT NULL, tenant_id TEXT COLLATE "C" NOT NULL, unique_key TEXT COLLATE "C", data TEXT NOT NULL, PRIMARY KEY (collection, id), UNIQUE (collection, tenant_id, unique_key));
CREATE INDEX IF NOT EXISTS iam_records_tenant ON iam_records (collection, tenant_id);
