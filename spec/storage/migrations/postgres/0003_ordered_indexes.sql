CREATE INDEX IF NOT EXISTS iam_records_order_timestamp ON iam_records (collection, tenant_id, ((data::jsonb) -> 'timestamp'), id) WHERE jsonb_typeof((data::jsonb) -> 'timestamp') = 'number';
CREATE INDEX IF NOT EXISTS iam_records_order_sequence ON iam_records (collection, tenant_id, ((data::jsonb) -> 'sequence'), id) WHERE jsonb_typeof((data::jsonb) -> 'sequence') = 'number';
