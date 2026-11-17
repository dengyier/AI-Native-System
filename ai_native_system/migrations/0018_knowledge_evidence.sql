CREATE TABLE ai_native.knowledge_candidates (
    tenant text NOT NULL,
    id text NOT NULL CHECK (id ~ '^[0-9a-f]{64}$'),
    document_id text NOT NULL,
    document_version bigint NOT NULL CHECK (document_version > 0),
    chunk_id text NOT NULL,
    citation jsonb NOT NULL,
    release_digest text NOT NULL,
    ontology_digest text NOT NULL CHECK (ontology_digest ~ '^[0-9a-f]{64}$'),
    object_id text NOT NULL,
    object_type text NOT NULL,
    object_version bigint NOT NULL CHECK (object_version > 0),
    target_kind text NOT NULL CHECK (target_kind IN ('field', 'relation', 'rule')),
    target_name text NOT NULL,
    related_object_id text,
    related_object_version bigint,
    fact_revision text,
    related_fact_revision text,
    value jsonb,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    verdict text CHECK (verdict IN ('supported', 'rejected')),
    reviewed_by text,
    reviewed_at timestamptz,
    invalidated_at timestamptz,
    PRIMARY KEY (tenant, id),
    FOREIGN KEY (tenant, release_digest) REFERENCES ai_native.application_releases (tenant, digest),
    CHECK ((related_object_id IS NULL) = (related_object_version IS NULL)),
    CHECK ((verdict IS NULL) = (reviewed_by IS NULL) AND (verdict IS NULL) = (reviewed_at IS NULL)),
    CHECK (invalidated_at IS NOT NULL OR value IS NOT NULL)
);
CREATE INDEX knowledge_candidates_document ON ai_native.knowledge_candidates
    (tenant, document_id, document_version, chunk_id);
CREATE INDEX knowledge_candidates_object ON ai_native.knowledge_candidates (tenant, object_id);
CREATE INDEX knowledge_candidates_related ON ai_native.knowledge_candidates (tenant, related_object_id)
    WHERE related_object_id IS NOT NULL;

CREATE FUNCTION ai_native.guard_knowledge_candidate_review() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.verdict IS NOT NULL AND (OLD.verdict, OLD.reviewed_by, OLD.reviewed_at)
       IS DISTINCT FROM (NEW.verdict, NEW.reviewed_by, NEW.reviewed_at) THEN
        RAISE EXCEPTION 'Knowledge candidate review is immutable';
    END IF;
    IF (OLD.invalidated_at IS NOT NULL AND OLD.invalidated_at IS DISTINCT FROM NEW.invalidated_at)
       OR (NEW.invalidated_at IS NOT NULL AND NEW.value IS NOT NULL)
       OR (NEW.invalidated_at IS NULL AND OLD.value IS DISTINCT FROM NEW.value) THEN
        RAISE EXCEPTION 'Knowledge candidate changes require one-way invalidation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER knowledge_candidate_review_immutable
    BEFORE UPDATE OF value, verdict, reviewed_by, reviewed_at, invalidated_at ON ai_native.knowledge_candidates
    FOR EACH ROW EXECUTE FUNCTION ai_native.guard_knowledge_candidate_review();

CREATE TABLE ai_native.knowledge_memories (
    tenant text NOT NULL,
    id text NOT NULL CHECK (id ~ '^[0-9a-f]{64}$'),
    actor text NOT NULL,
    service text NOT NULL,
    delegation text NOT NULL,
    scope text NOT NULL CHECK (scope IN ('task', 'cross_task')),
    scope_id text NOT NULL,
    document_id text NOT NULL,
    document_version bigint NOT NULL CHECK (document_version > 0),
    chunk_id text NOT NULL,
    citation jsonb NOT NULL,
    candidate_id text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant, id),
    FOREIGN KEY (tenant, candidate_id) REFERENCES ai_native.knowledge_candidates (tenant, id),
    CHECK (expires_at > created_at)
);
CREATE INDEX knowledge_memories_scope ON ai_native.knowledge_memories (tenant, actor, service, delegation, scope, scope_id);
CREATE INDEX knowledge_memories_evidence ON ai_native.knowledge_memories (tenant, document_version, document_id, chunk_id);
CREATE INDEX knowledge_memories_candidate ON ai_native.knowledge_memories (tenant, candidate_id)
    WHERE candidate_id IS NOT NULL;
CREATE INDEX knowledge_memories_expiry ON ai_native.knowledge_memories (tenant, expires_at);

CREATE TABLE ai_native.knowledge_invalidation_receipts (
    tenant text NOT NULL,
    event_id text NOT NULL,
    processed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant, event_id),
    FOREIGN KEY (tenant, event_id) REFERENCES ai_native.fact_invalidation_outbox (tenant, event_id)
);

CREATE INDEX knowledge_outbox_evidence ON ai_native.fact_invalidation_outbox (
    tenant, ((document::jsonb #>> '{event,evidence_id}')), ((document::jsonb #> '{event,revision}'))
) WHERE document::jsonb ->> 'kind' = 'evidence.revocation';
CREATE INDEX knowledge_outbox_fact_objects ON ai_native.fact_invalidation_outbox (
    tenant, ((document::jsonb #>> '{event,field,subject,object_id}')), enqueued_at DESC, event_id DESC
) WHERE document::jsonb ->> 'kind' = 'fact.change';

DO $rls$
DECLARE
    name text;
    scope text := $scope$tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), '')$scope$;
BEGIN
    FOREACH name IN ARRAY ARRAY['knowledge_candidates', 'knowledge_memories', 'knowledge_invalidation_receipts'] LOOP
        EXECUTE format('ALTER TABLE ai_native.%I ENABLE ROW LEVEL SECURITY', name);
        EXECUTE format('CREATE POLICY tenant_scope ON ai_native.%I USING (%s) WITH CHECK (%s)', name, scope, scope);
    END LOOP;
END
$rls$;
