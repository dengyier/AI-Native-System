-- P4 receipts compare opaque native revision tokens independently of shadow versions.
ALTER TABLE ai_native.fact_feedback_expectations ADD COLUMN expected_source_version text;
ALTER TABLE ai_native.fact_feedback_observations ADD COLUMN source_version_token text;

-- Sequences group individually authorized tasks; the constituent transactions
-- remain independent and completed effects stay visible after a later failure.
CREATE TABLE ai_native.p4_sequences (
    tenant text NOT NULL,
    id text NOT NULL,
    PRIMARY KEY (tenant, id)
);
CREATE TABLE ai_native.p4_sequence_steps (
    tenant text NOT NULL,
    sequence_id text NOT NULL,
    position integer NOT NULL CHECK (position > 0),
    task_id text NOT NULL,
    PRIMARY KEY (tenant, sequence_id, position),
    UNIQUE (tenant, task_id),
    FOREIGN KEY (tenant, sequence_id) REFERENCES ai_native.p4_sequences(tenant, id),
    FOREIGN KEY (tenant, task_id) REFERENCES ai_native.tasks(tenant, id)
);
CREATE TABLE ai_native.p4_compensations (
    tenant text NOT NULL,
    original_task_id text NOT NULL,
    compensation_task_id text NOT NULL,
    PRIMARY KEY (tenant, compensation_task_id),
    FOREIGN KEY (tenant, original_task_id) REFERENCES ai_native.tasks(tenant, id),
    FOREIGN KEY (tenant, compensation_task_id) REFERENCES ai_native.tasks(tenant, id),
    CHECK (original_task_id <> compensation_task_id)
);

DO $migration$
DECLARE
    table_name text;
    predicate constant text := $scope$tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), '')$scope$;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['p4_sequences', 'p4_sequence_steps', 'p4_compensations'] LOOP
        EXECUTE format('ALTER TABLE ai_native.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('CREATE POLICY tenant_scope ON ai_native.%I USING (%s) WITH CHECK (%s)',
                       table_name, predicate, predicate);
        EXECUTE format('CREATE TRIGGER immutable_row BEFORE UPDATE OR DELETE ON ai_native.%I
                        FOR EACH ROW EXECUTE FUNCTION ai_native.guard_owp_ledger()', table_name);
        EXECUTE format('REVOKE ALL ON ai_native.%I FROM PUBLIC', table_name);
    END LOOP;
END
$migration$;
