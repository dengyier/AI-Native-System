-- Source progress has a stream order separate from the per-record version.
CREATE TABLE ai_native.source_sync_streams (
    tenant text NOT NULL,
    source text NOT NULL,
    stream text NOT NULL,
    epoch text NOT NULL,
    position bigint NOT NULL CHECK (position >= 0),
    token text NOT NULL,
    snapshot_id text,
    status text NOT NULL CHECK (status IN ('ready','partial','blocked')),
    coverage text NOT NULL CHECK (coverage IN ('complete','partial','unknown')),
    updated_at timestamptz NOT NULL,
    fresh_until timestamptz,
    PRIMARY KEY (tenant, source, stream)
);

CREATE TABLE ai_native.source_sync_progress (
    LIKE ai_native.source_sync_streams INCLUDING CONSTRAINTS,
    revision bigint NOT NULL CHECK (revision > 0),
    PRIMARY KEY (tenant, source, stream, revision)
);
CREATE INDEX source_sync_progress_history
    ON ai_native.source_sync_progress (tenant, source, stream, updated_at DESC, revision DESC);

CREATE TABLE ai_native.source_sync_snapshots (
    tenant text NOT NULL,
    source text NOT NULL,
    stream text NOT NULL,
    snapshot_id text NOT NULL,
    epoch text NOT NULL,
    digest text NOT NULL,
    document text NOT NULL,
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant, source, stream, snapshot_id)
);
CREATE INDEX source_sync_snapshots_epoch ON ai_native.source_sync_snapshots (tenant, source, stream, epoch);

CREATE TABLE ai_native.source_sync_deliveries (
    tenant text NOT NULL,
    source text NOT NULL,
    event_id text NOT NULL,
    stream text NOT NULL,
    epoch text,
    position bigint CHECK (position >= 0),
    status text NOT NULL CHECK (status IN ('applied','stale','blocked')),
    snapshot_id text,
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant, source, event_id),
    FOREIGN KEY (tenant, source, event_id) REFERENCES ai_native.source_events(tenant, source, event_id)
);

CREATE TABLE ai_native.source_sync_conflicts (
    tenant text NOT NULL,
    source text NOT NULL,
    stream text NOT NULL,
    conflict_id text NOT NULL,
    event_id text,
    reason text NOT NULL,
    document text NOT NULL,
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant, source, stream, conflict_id)
);

CREATE TABLE ai_native.source_sync_records (
    tenant text NOT NULL,
    source text NOT NULL,
    stream text NOT NULL,
    source_type text NOT NULL,
    source_id text NOT NULL,
    epoch text NOT NULL,
    version_token text NOT NULL,
    version_sequence bigint NOT NULL CHECK (version_sequence >= 0),
    record_digest text NOT NULL,
    object_type text NOT NULL,
    object_id text NOT NULL,
    mapping_revision text NOT NULL,
    tombstone boolean NOT NULL,
    document text NOT NULL,
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant, source, source_type, source_id)
);
CREATE INDEX source_sync_records_stream ON ai_native.source_sync_records (tenant, source, stream);

CREATE TABLE ai_native.fact_observations (
    tenant text NOT NULL,
    assertion_id text NOT NULL,
    revision_key text NOT NULL,
    source text,
    stream text,
    source_type text,
    source_id text,
    mapping_revision text,
    epoch text,
    source_sequence bigint,
    deleted boolean NOT NULL,
    operation_id text,
    PRIMARY KEY (tenant, assertion_id, revision_key),
    FOREIGN KEY (tenant, assertion_id, revision_key)
        REFERENCES ai_native.fact_assertions(tenant, assertion_id, revision_key)
);
CREATE INDEX fact_observations_source_record
    ON ai_native.fact_observations (tenant, source, stream, source_type, source_id, epoch);

CREATE TABLE ai_native.fact_authorities (
    tenant text NOT NULL,
    object_type text NOT NULL,
    object_id text NOT NULL,
    field_name text NOT NULL,
    relationship_key text NOT NULL,
    revision_key text NOT NULL,
    recorded_at timestamptz NOT NULL,
    sources text[] NOT NULL CHECK (cardinality(sources) > 0),
    actor text NOT NULL,
    reason text NOT NULL,
    PRIMARY KEY (tenant, object_type, object_id, field_name, relationship_key, revision_key)
);

-- Optional rule/feedback wiring is bound to the immutable application release.
CREATE TABLE ai_native.fact_rule_bindings (
    tenant text NOT NULL,
    release_digest text NOT NULL,
    rule_name text NOT NULL,
    feedback_source text,
    feedback_stream text,
    bound_by text NOT NULL,
    bound_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant, release_digest),
    FOREIGN KEY (tenant, release_digest) REFERENCES ai_native.application_releases(tenant, digest),
    CHECK ((feedback_source IS NULL) = (feedback_stream IS NULL))
);

CREATE FUNCTION ai_native.require_draft_rule_release() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $function$
BEGIN
    PERFORM 1 FROM ai_native.application_release_lifecycle
        WHERE tenant = NEW.tenant AND digest = NEW.release_digest AND status = 'draft' FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Fact rule binding requires a draft release' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER fact_rule_requires_draft
    BEFORE INSERT ON ai_native.fact_rule_bindings
    FOR EACH ROW EXECUTE FUNCTION ai_native.require_draft_rule_release();
CREATE TRIGGER fact_rule_binding_immutable
    BEFORE UPDATE OR DELETE ON ai_native.fact_rule_bindings
    FOR EACH ROW EXECUTE FUNCTION ai_native.guard_release_content();

-- One intent is compared with ordered evidence from the designated source.
-- Only the existing receipt path may record business effects.
CREATE TABLE ai_native.fact_feedback_expectations (
    tenant text NOT NULL,
    operation_id text NOT NULL,
    source text NOT NULL,
    stream text NOT NULL,
    object_type text NOT NULL,
    object_id text NOT NULL,
    expected_state text NOT NULL,
    request_hash text NOT NULL,
    receipt_status text CHECK (receipt_status IN ('succeeded','rejected')),
    PRIMARY KEY (tenant, operation_id),
    FOREIGN KEY (tenant, operation_id) REFERENCES ai_native.tasks(tenant, id)
);

CREATE TABLE ai_native.fact_feedback_observations (
    tenant text NOT NULL,
    operation_id text NOT NULL,
    source text NOT NULL,
    event_id text NOT NULL,
    matches boolean NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant, operation_id, source, event_id),
    FOREIGN KEY (tenant, operation_id) REFERENCES ai_native.fact_feedback_expectations(tenant, operation_id),
    FOREIGN KEY (tenant, source, event_id) REFERENCES ai_native.source_events(tenant, source, event_id)
);

DO $migration$
DECLARE
    table_name text;
    predicate constant text := $scope$tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), '')$scope$;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'source_sync_streams', 'source_sync_progress', 'source_sync_snapshots', 'source_sync_deliveries',
        'source_sync_conflicts', 'source_sync_records', 'fact_observations', 'fact_authorities',
        'fact_rule_bindings', 'fact_feedback_expectations', 'fact_feedback_observations'
    ] LOOP
        EXECUTE format('ALTER TABLE ai_native.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('CREATE POLICY tenant_scope ON ai_native.%I USING (%s) WITH CHECK (%s)',
                       table_name, predicate, predicate);
    END LOOP;
END
$migration$;
