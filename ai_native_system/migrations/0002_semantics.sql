-- Canonical documents preserve JSON scalar types and digest bytes.
-- Keys and timestamps remain indexed relational values.
CREATE TABLE ai_native.ontology_releases (
    tenant text NOT NULL,
    namespace text NOT NULL,
    version_key text NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    document text NOT NULL,
    PRIMARY KEY (tenant, namespace, version_key)
);

CREATE TABLE ai_native.identity_mappings (
    tenant text NOT NULL,
    source text NOT NULL,
    source_type text NOT NULL,
    source_id text NOT NULL,
    revision_key text NOT NULL,
    recorded_at timestamptz NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    document text NOT NULL,
    PRIMARY KEY (tenant, source, source_type, source_id, revision_key)
);

CREATE TABLE ai_native.fact_assertions (
    tenant text NOT NULL,
    assertion_id text NOT NULL,
    revision_key text NOT NULL,
    object_type text NOT NULL,
    object_id text NOT NULL,
    field_name text NOT NULL,
    relationship_id text,
    valid_from timestamptz,
    valid_to timestamptz,
    recorded_at timestamptz NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    document text NOT NULL,
    PRIMARY KEY (tenant, assertion_id, revision_key),
    CHECK (valid_to > valid_from)
);
CREATE INDEX fact_assertions_history ON ai_native.fact_assertions
    (tenant, object_type, object_id, field_name, relationship_id, recorded_at);

CREATE TABLE ai_native.source_events (
    tenant text NOT NULL,
    source text NOT NULL,
    event_id text NOT NULL,
    source_epoch text,
    received_at timestamptz NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    document text NOT NULL,
    PRIMARY KEY (tenant, source, event_id)
);
