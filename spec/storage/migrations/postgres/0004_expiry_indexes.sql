CREATE INDEX IF NOT EXISTS iam_records_expiry_expiresAt ON iam_records (collection, ((data::jsonb) -> 'expiresAt'), id) WHERE jsonb_typeof((data::jsonb) -> 'expiresAt') = 'number';
CREATE INDEX IF NOT EXISTS iam_records_expiry_deliveredAt ON iam_records (collection, ((data::jsonb) -> 'deliveredAt'), id) WHERE jsonb_typeof((data::jsonb) -> 'deliveredAt') = 'number';
CREATE INDEX IF NOT EXISTS iam_records_expiry_failedAt ON iam_records (collection, ((data::jsonb) -> 'failedAt'), id) WHERE jsonb_typeof((data::jsonb) -> 'failedAt') = 'number';
