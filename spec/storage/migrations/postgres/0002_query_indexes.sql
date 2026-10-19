CREATE INDEX IF NOT EXISTS iam_records_tenant_id ON iam_records (collection, tenant_id, id);
CREATE INDEX IF NOT EXISTS iam_records_unique_key ON iam_records (collection, unique_key, id) WHERE unique_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS iam_records_document ON iam_records USING gin ((data::jsonb) jsonb_path_ops);
