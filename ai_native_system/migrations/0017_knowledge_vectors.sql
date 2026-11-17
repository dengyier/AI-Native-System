DO $vector$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
                   WHERE e.extname = 'vector' AND n.nspname = 'public') THEN
        RAISE EXCEPTION 'Install the pgvector extension in public before applying knowledge migrations';
    END IF;
END
$vector$;

CREATE TABLE ai_native.knowledge_sources (
    tenant text NOT NULL,
    document_id text NOT NULL,
    source_id text NOT NULL,
    format text NOT NULL CHECK (format IN ('text', 'markdown')),
    status text NOT NULL CHECK (status IN ('active', 'withdrawn', 'deleted')),
    last_version integer NOT NULL CHECK (last_version >= 0),
    PRIMARY KEY (tenant, document_id),
    UNIQUE (tenant, source_id),
    CHECK (status = 'active' OR last_version > 0)
);

CREATE TABLE ai_native.knowledge_vector_spaces (
    tenant text NOT NULL,
    index_id text NOT NULL,
    route text NOT NULL,
    provider text NOT NULL,
    model text NOT NULL,
    model_version text NOT NULL,
    preprocessing_version text NOT NULL,
    dimensions integer NOT NULL CHECK (dimensions BETWEEN 1 AND 4096),
    binding_digest text NOT NULL CHECK (binding_digest ~ '^[0-9a-f]{64}$'),
    metric text NOT NULL CHECK (metric = 'cosine'),
    parser_version text NOT NULL,
    chunk_bytes integer NOT NULL CHECK (chunk_bytes BETWEEN 16 AND 8192),
    state text NOT NULL CHECK (state IN ('staged', 'active', 'retired')),
    PRIMARY KEY (tenant, index_id),
    UNIQUE (tenant, index_id, dimensions)
);

CREATE UNIQUE INDEX knowledge_vector_active_space ON ai_native.knowledge_vector_spaces (tenant)
    WHERE state = 'active';

CREATE TABLE ai_native.knowledge_vector_documents (
    tenant text NOT NULL,
    index_id text NOT NULL,
    document_id text NOT NULL,
    document_version integer NOT NULL CHECK (document_version > 0),
    dimensions integer NOT NULL,
    content_digest text NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    chunk_count integer NOT NULL CHECK (chunk_count BETWEEN 1 AND 4096),
    state text NOT NULL CHECK (state IN ('staged', 'published')),
    base_version integer CHECK (base_version > 0),
    base_digest text CHECK (base_digest ~ '^[0-9a-f]{64}$'),
    write_current boolean NOT NULL,
    draft_text text,
    claim_token text,
    claim_until timestamptz,
    PRIMARY KEY (tenant, index_id, document_id, document_version),
    UNIQUE (tenant, index_id, document_id, document_version, dimensions),
    FOREIGN KEY (tenant, document_id) REFERENCES ai_native.knowledge_sources (tenant, document_id),
    FOREIGN KEY (tenant, index_id, dimensions)
        REFERENCES ai_native.knowledge_vector_spaces (tenant, index_id, dimensions),
    CHECK ((state = 'staged') = (draft_text IS NOT NULL)),
    CHECK ((claim_token IS NULL) = (claim_until IS NULL)),
    CHECK (state = 'staged' OR claim_token IS NULL),
    CHECK ((base_version IS NULL) = (base_digest IS NULL)),
    CHECK (write_current OR base_version IS NOT NULL),
    CHECK (document_version = CASE WHEN write_current THEN coalesce(base_version, 0) + 1 ELSE base_version END)
);

CREATE TABLE ai_native.knowledge_vector_chunks (
    tenant text NOT NULL,
    index_id text NOT NULL,
    document_id text NOT NULL,
    document_version integer NOT NULL,
    dimensions integer NOT NULL,
    chunk_id text NOT NULL CHECK (chunk_id ~ '^[0-9a-f]{64}$'),
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    start_char integer NOT NULL CHECK (start_char >= 0),
    end_char integer NOT NULL,
    start_byte integer NOT NULL CHECK (start_byte >= 0),
    end_byte integer NOT NULL,
    text text NOT NULL,
    content_digest text NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    embedding public.vector,
    PRIMARY KEY (tenant, chunk_id),
    UNIQUE (tenant, index_id, document_id, document_version, ordinal),
    FOREIGN KEY (tenant, index_id, document_id, document_version, dimensions)
        REFERENCES ai_native.knowledge_vector_documents (tenant, index_id, document_id, document_version, dimensions)
        ON DELETE CASCADE,
    CHECK (end_char > start_char AND end_char - start_char = char_length(text)),
    CHECK (end_byte > start_byte AND end_byte - start_byte = octet_length(text)),
    CHECK (embedding IS NULL OR (public.vector_dims(embedding) = dimensions AND public.vector_norm(embedding) > 0))
);

CREATE INDEX knowledge_vector_version_by_document
    ON ai_native.knowledge_vector_documents (tenant, document_id, index_id, document_version);
CREATE INDEX knowledge_vector_reuse
    ON ai_native.knowledge_vector_chunks (tenant, index_id, document_id, content_digest)
    WHERE embedding IS NOT NULL;

DO $rls$
DECLARE
    table_name text;
    scope text := $scope$tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), '')$scope$;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['knowledge_sources', 'knowledge_vector_spaces',
        'knowledge_vector_documents', 'knowledge_vector_chunks'] LOOP
        EXECUTE format('ALTER TABLE ai_native.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('CREATE POLICY tenant_scope ON ai_native.%I USING (%s) WITH CHECK (%s)',
                       table_name, scope, scope);
    END LOOP;
END
$rls$;
