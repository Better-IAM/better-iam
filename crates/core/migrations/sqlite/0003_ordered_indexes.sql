CREATE INDEX IF NOT EXISTS iam_records_order_timestamp ON iam_records (collection, tenant_id, json_extract(data, '$."timestamp"'), id) WHERE json_extract(data, '$."timestamp"') IS NOT NULL;
CREATE INDEX IF NOT EXISTS iam_records_order_sequence ON iam_records (collection, tenant_id, json_extract(data, '$."sequence"'), id) WHERE json_extract(data, '$."sequence"') IS NOT NULL;
