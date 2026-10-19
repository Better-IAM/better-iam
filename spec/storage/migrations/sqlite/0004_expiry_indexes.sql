CREATE INDEX IF NOT EXISTS iam_records_expiry_expiresAt ON iam_records (collection, json_extract(data, '$."expiresAt"'), id) WHERE json_extract(data, '$."expiresAt"') IS NOT NULL;
CREATE INDEX IF NOT EXISTS iam_records_expiry_deliveredAt ON iam_records (collection, json_extract(data, '$."deliveredAt"'), id) WHERE json_extract(data, '$."deliveredAt"') IS NOT NULL;
CREATE INDEX IF NOT EXISTS iam_records_expiry_failedAt ON iam_records (collection, json_extract(data, '$."failedAt"'), id) WHERE json_extract(data, '$."failedAt"') IS NOT NULL;
