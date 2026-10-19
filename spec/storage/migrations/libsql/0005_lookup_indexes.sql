CREATE INDEX IF NOT EXISTS iam_records_field_sourceSessionId ON iam_records (collection, json_extract(data, '$."sourceSessionId"'), id) WHERE json_extract(data, '$."sourceSessionId"') IS NOT NULL;
CREATE INDEX IF NOT EXISTS iam_records_field_trustId ON iam_records (collection, json_extract(data, '$."trustId"'), id) WHERE json_extract(data, '$."trustId"') IS NOT NULL;
