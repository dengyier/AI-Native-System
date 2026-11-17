ALTER TABLE ai_native.tasks
    ADD COLUMN graph_version text,
    ADD COLUMN graph_deadline double precision,
    ADD COLUMN graph_last_claim double precision,
    ADD CHECK ((graph_version IS NULL) = (graph_deadline IS NULL)),
    ADD CHECK (graph_last_claim IS NULL OR graph_version IS NOT NULL);

CREATE FUNCTION ai_native.guard_graph_task_binding() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (OLD.graph_version, OLD.graph_deadline) IS DISTINCT FROM (NEW.graph_version, NEW.graph_deadline) THEN
        RAISE EXCEPTION 'Graph task binding is immutable';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER graph_task_binding_immutable
    BEFORE UPDATE OF graph_version, graph_deadline ON ai_native.tasks
    FOR EACH ROW EXECUTE FUNCTION ai_native.guard_graph_task_binding();

CREATE INDEX graph_task_queue ON ai_native.tasks (tenant, graph_last_claim NULLS FIRST, graph_deadline, id)
    WHERE graph_version IS NOT NULL AND status IN ('planning', 'awaiting_approval', 'ready', 'reconciling');
