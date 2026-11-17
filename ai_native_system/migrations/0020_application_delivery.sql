ALTER TABLE ai_native.tasks ADD COLUMN expected_object_version integer CHECK (expected_object_version > 0);

CREATE FUNCTION ai_native.guard_expected_object_version() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.expected_object_version IS DISTINCT FROM NEW.expected_object_version THEN
        RAISE EXCEPTION 'Expected task object version is immutable';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER expected_object_version_immutable
    BEFORE UPDATE OF expected_object_version ON ai_native.tasks
    FOR EACH ROW EXECUTE FUNCTION ai_native.guard_expected_object_version();

ALTER TABLE ai_native.events ADD COLUMN task_sequence bigint;

WITH numbered AS (
    SELECT id, row_number() OVER (PARTITION BY task_id ORDER BY id) AS position FROM ai_native.events
)
UPDATE ai_native.events e SET task_sequence = numbered.position FROM numbered WHERE e.id = numbered.id;

ALTER TABLE ai_native.events ALTER COLUMN task_sequence SET NOT NULL;
CREATE UNIQUE INDEX events_by_task_sequence ON ai_native.events (task_id, task_sequence);

CREATE TABLE ai_native.task_event_counters (
    task_id text PRIMARY KEY REFERENCES ai_native.tasks(id),
    last_sequence bigint NOT NULL CHECK (last_sequence > 0)
);

INSERT INTO ai_native.task_event_counters (task_id, last_sequence)
SELECT task_id, max(task_sequence) FROM ai_native.events GROUP BY task_id;

ALTER TABLE ai_native.task_event_counters ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON ai_native.task_event_counters
    USING (EXISTS (SELECT 1 FROM ai_native.tasks t WHERE t.id=task_event_counters.task_id
                  AND t.tenant=NULLIF(pg_catalog.current_setting('ai_native.tenant', true), '')));

-- The locked counter row orders writes to this task by commit. A global event
-- identity may have been allocated before the task row is reached.
CREATE FUNCTION ai_native.assign_task_event_sequence() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, pg_temp AS $$
BEGIN
    INSERT INTO ai_native.task_event_counters AS counter (task_id, last_sequence) VALUES (NEW.task_id, 1)
    ON CONFLICT (task_id) DO UPDATE SET last_sequence = counter.last_sequence + 1
    RETURNING last_sequence INTO NEW.task_sequence;
    RETURN NEW;
END
$$;

CREATE TRIGGER event_task_sequence
    BEFORE INSERT ON ai_native.events FOR EACH ROW EXECUTE FUNCTION ai_native.assign_task_event_sequence();

CREATE TABLE ai_native.task_handover (
    tenant text NOT NULL,
    task_id text NOT NULL,
    assessment_digest text NOT NULL CHECK (assessment_digest ~ '^[0-9a-f]{64}$'),
    actor text NOT NULL,
    verdict text NOT NULL CHECK (verdict IN ('accept', 'reject')),
    reason text NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant, task_id, assessment_digest),
    FOREIGN KEY (tenant, task_id) REFERENCES ai_native.tasks(tenant, id)
);

ALTER TABLE ai_native.task_handover ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_native.task_handover FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON ai_native.task_handover
    USING (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''))
    WITH CHECK (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''));
