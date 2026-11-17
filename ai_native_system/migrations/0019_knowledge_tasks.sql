ALTER TABLE ai_native.tasks ADD COLUMN knowledge_citations text;

CREATE FUNCTION ai_native.guard_knowledge_task_citations() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.knowledge_citations IS DISTINCT FROM NEW.knowledge_citations THEN
        RAISE EXCEPTION 'Task knowledge citations are immutable';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER knowledge_task_citations_immutable
    BEFORE UPDATE OF knowledge_citations ON ai_native.tasks
    FOR EACH ROW EXECUTE FUNCTION ai_native.guard_knowledge_task_citations();

CREATE INDEX knowledge_revision_revocations ON ai_native.fact_invalidation_outbox
    (tenant, (document::jsonb#>>'{event,evidence_id}'), (document::jsonb#>'{event,revision}'))
    WHERE document::jsonb->>'kind' = 'evidence.revocation';

-- Runtime roles that read canonical documents need only the boolean result,
-- without SELECT access to the raw invalidation payloads.
CREATE FUNCTION ai_native.knowledge_revision_revoked(document_id text, document_version integer) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1 FROM ai_native.fact_invalidation_outbox ev
        WHERE ev.tenant = NULLIF(current_setting('ai_native.tenant', true), '')
          AND ev.document::jsonb->>'kind' = 'evidence.revocation'
          AND ev.document::jsonb#>>'{event,evidence_id}' = document_id
          AND ev.document::jsonb#>'{event,revision}' = to_jsonb(document_version)
          AND (ev.document::jsonb#>>'{event,revoked_at}')::timestamptz <= statement_timestamp()
          AND ev.enqueued_at <= statement_timestamp()
    )
$$;

CREATE TABLE ai_native.knowledge_evaluations (
    tenant text NOT NULL,
    id text NOT NULL,
    release_digest text NOT NULL,
    report text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant, id),
    FOREIGN KEY (tenant, release_digest) REFERENCES ai_native.application_releases(tenant, digest)
);

ALTER TABLE ai_native.knowledge_evaluations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_native.knowledge_evaluations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON ai_native.knowledge_evaluations
    USING (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''))
    WITH CHECK (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''));
