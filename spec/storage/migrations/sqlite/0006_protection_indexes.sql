CREATE INDEX IF NOT EXISTS iam_records_field_fingerprint ON iam_records (collection, json_extract(data, '$."fingerprint"'), id) WHERE json_extract(data, '$."fingerprint"') IS NOT NULL;
