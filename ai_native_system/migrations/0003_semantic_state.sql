-- Projection references bind the assertion to the exact tenant, object and field.
-- The empty relationship key represents an object property, not a relationship.
ALTER TABLE ai_native.fact_assertions
    ADD COLUMN relationship_key text GENERATED ALWAYS AS (coalesce(relationship_id, '')) STORED,
    ADD CONSTRAINT fact_assertions_nonempty_relationship CHECK (relationship_id <> ''),
    ADD CONSTRAINT fact_assertions_projection_target UNIQUE
        (tenant, object_type, object_id, field_name, relationship_key, assertion_id, revision_key);

CREATE TABLE ai_native.fact_projections (
    tenant text NOT NULL,
    object_type text NOT NULL,
    object_id text NOT NULL,
    field_name text NOT NULL,
    relationship_key text NOT NULL,
    assertion_id text NOT NULL,
    revision_key text NOT NULL,
    PRIMARY KEY (tenant, object_type, object_id, field_name, relationship_key),
    FOREIGN KEY (tenant, object_type, object_id, field_name, relationship_key, assertion_id, revision_key)
        REFERENCES ai_native.fact_assertions
            (tenant, object_type, object_id, field_name, relationship_key, assertion_id, revision_key)
);

CREATE TABLE ai_native.source_cursors (
    tenant text NOT NULL,
    source text NOT NULL,
    stream text NOT NULL,
    epoch text NOT NULL,
    token text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    PRIMARY KEY (tenant, source, stream)
);

CREATE TABLE ai_native.fact_invalidation_outbox (
    tenant text NOT NULL,
    event_id text NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status = 'pending'),
    enqueued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    document text NOT NULL,
    PRIMARY KEY (tenant, event_id)
);
CREATE INDEX fact_invalidation_outbox_pending
    ON ai_native.fact_invalidation_outbox (tenant, enqueued_at, event_id) WHERE status = 'pending';
