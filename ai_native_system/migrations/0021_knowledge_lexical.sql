CREATE FUNCTION ai_native.knowledge_lexical_normalize_v1(value text)
RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog
RETURN trim(lower(regexp_replace(normalize(value, NFKC) COLLATE "C", '[[:space:]]+', ' ', 'g')));

CREATE FUNCTION ai_native.knowledge_lexical_terms_v1(value text, for_query boolean)
RETURNS TABLE (term text)
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog
AS $terms$
    WITH normalized AS MATERIALIZED (
        SELECT ai_native.knowledge_lexical_normalize_v1(value) COLLATE "C" AS text
    ),
    runs AS MATERIALIZED (
        SELECT capture[1] AS token FROM normalized
        CROSS JOIN LATERAL regexp_matches(text, '[a-z0-9_]+|[㐀-䶿一-鿿豈-﫿𠀀-𲎯]+', 'g') AS capture
    ),
    keys AS (
        SELECT 'w:' || token AS key FROM runs WHERE token ~ '^[a-z0-9_]'
        UNION ALL
        SELECT '1:' || substr(token, position, 1) FROM runs
        CROSS JOIN LATERAL generate_series(1, char_length(token)) AS position
        WHERE token !~ '^[a-z0-9_]' AND (NOT for_query OR char_length(token) = 1)
        UNION ALL
        SELECT '2:' || substr(token, position, 2) FROM runs
        CROSS JOIN LATERAL generate_series(1, char_length(token) - 1) AS position
        WHERE token !~ '^[a-z0-9_]'
        UNION ALL
        SELECT 'c:' || replace(capture[1], ' ', '') FROM normalized
        CROSS JOIN LATERAL regexp_matches(text,
            '(第 ?(?:[0-9]+(?:[.-][0-9]+)*|[〇零一二两三四五六七八九十百千万亿]+) ?[条款项章节](?: ?之 ?(?:[0-9]+(?:[.-][0-9]+)*|[〇零一二两三四五六七八九十百千万亿]+))*)', 'g') AS capture
        WHERE NOT for_query
    )
    SELECT DISTINCT CASE WHEN char_length(key) > 128
        THEN 'h:' || encode(sha256(convert_to(key, 'UTF8')), 'hex') ELSE key END
    FROM keys;
$terms$;

-- B-tree equality remains indexable under tenant row security.
CREATE TABLE ai_native.knowledge_lexical_postings (
    tenant text NOT NULL,
    index_id text NOT NULL,
    term text COLLATE "C" NOT NULL,
    chunk_id text NOT NULL,
    PRIMARY KEY (tenant, index_id, term, chunk_id),
    FOREIGN KEY (tenant, chunk_id) REFERENCES ai_native.knowledge_vector_chunks (tenant, chunk_id) ON DELETE CASCADE
);
CREATE INDEX knowledge_lexical_postings_by_chunk ON ai_native.knowledge_lexical_postings (tenant, chunk_id);
ALTER TABLE ai_native.knowledge_lexical_postings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON ai_native.knowledge_lexical_postings
    USING (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''))
    WITH CHECK (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''));

CREATE FUNCTION ai_native.knowledge_lexical_sync_v1()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $sync$
BEGIN
    IF TG_RELID <> 'ai_native.knowledge_vector_chunks'::regclass OR TG_WHEN <> 'AFTER' THEN
        RAISE EXCEPTION 'Invalid knowledge lexical trigger source';
    END IF;
    IF NOT pg_has_role(session_user, current_user, 'USAGE') AND (
        NEW.tenant IS DISTINCT FROM NULLIF(current_setting('ai_native.tenant', true), '') OR
        (TG_OP = 'UPDATE' AND OLD.tenant IS DISTINCT FROM NEW.tenant)
    ) THEN
        RAISE EXCEPTION 'Invalid tenant for knowledge lexical index';
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.embedding IS NOT NULL THEN
        IF NEW.embedding IS NOT NULL AND
                (OLD.tenant, OLD.index_id, OLD.chunk_id, OLD.text) =
                (NEW.tenant, NEW.index_id, NEW.chunk_id, NEW.text) THEN
            RETURN NEW;
        END IF;
        DELETE FROM ai_native.knowledge_lexical_postings WHERE tenant = OLD.tenant AND chunk_id = OLD.chunk_id;
    END IF;
    IF NEW.embedding IS NOT NULL THEN
        INSERT INTO ai_native.knowledge_lexical_postings (tenant, index_id, term, chunk_id)
        SELECT NEW.tenant, NEW.index_id, term, NEW.chunk_id
        FROM ai_native.knowledge_lexical_terms_v1(NEW.text, false);
    END IF;
    RETURN NEW;
END;
$sync$;

CREATE TRIGGER knowledge_lexical_sync
    AFTER INSERT OR UPDATE OF tenant, index_id, chunk_id, text, embedding
    ON ai_native.knowledge_vector_chunks
    FOR EACH ROW EXECUTE FUNCTION ai_native.knowledge_lexical_sync_v1();

REVOKE ALL ON FUNCTION ai_native.knowledge_lexical_sync_v1() FROM PUBLIC;

INSERT INTO ai_native.knowledge_lexical_postings (tenant, index_id, term, chunk_id)
SELECT c.tenant, c.index_id, t.term, c.chunk_id
FROM ai_native.knowledge_vector_chunks c
CROSS JOIN LATERAL ai_native.knowledge_lexical_terms_v1(c.text, false) t
WHERE c.embedding IS NOT NULL;
