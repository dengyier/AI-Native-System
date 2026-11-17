-- Delivery workers query prior operations and publish evidence. They never retry writes.
CREATE TABLE ai_native.p4_delivery_jobs (
    tenant text NOT NULL,
    task_id text NOT NULL,
    operation_id text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('reconcile', 'evidence')),
    scope text NOT NULL CHECK (btrim(scope) <> ''),
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'leased', 'completed', 'manual')),
    attempts integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 32),
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_claimed_at timestamptz,
    lease_token text,
    lease_expires_at timestamptz,
    lease_manual boolean NOT NULL DEFAULT false,
    last_error text CHECK (last_error IN ('transient', 'lease_expired', 'retry_limit', 'manual_review')),
    PRIMARY KEY (tenant, operation_id, kind),
    FOREIGN KEY (tenant, task_id) REFERENCES ai_native.tasks(tenant, id),
    CHECK (attempts BETWEEN 0 AND max_attempts),
    CHECK ((status = 'leased') = (lease_token IS NOT NULL)),
    CHECK ((status = 'leased') = (lease_expires_at IS NOT NULL)),
    CHECK (NOT lease_manual OR status = 'leased')
);
CREATE INDEX p4_delivery_due
    ON ai_native.p4_delivery_jobs (tenant, kind, next_attempt_at, operation_id)
    WHERE status = 'queued';
CREATE INDEX p4_delivery_leases
    ON ai_native.p4_delivery_jobs (tenant, kind, lease_expires_at)
    WHERE status = 'leased';
CREATE INDEX p4_delivery_scope
    ON ai_native.p4_delivery_jobs (tenant, kind, scope, last_claimed_at);

-- The bytes stored here can rebuild a lost file from a trusted database backup.
-- Keep access to raw documents separate from any redacted read role.
CREATE TABLE ai_native.p4_proof_records (
    tenant text NOT NULL,
    task_id text NOT NULL,
    operation_id text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('source_receipt', 'runtime_attestation')),
    raw_digest text NOT NULL CHECK (raw_digest ~ '^[0-9a-f]{64}$'),
    redacted_digest text NOT NULL CHECK (redacted_digest ~ '^[0-9a-f]{64}$'),
    raw_document text NOT NULL,
    redacted_document text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant, operation_id, kind),
    FOREIGN KEY (tenant, task_id) REFERENCES ai_native.tasks(tenant, id)
);

DO $migration$
DECLARE
    table_name text;
    predicate constant text := $scope$tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), '')$scope$;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['p4_delivery_jobs', 'p4_proof_records'] LOOP
        EXECUTE format('ALTER TABLE ai_native.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('CREATE POLICY tenant_scope ON ai_native.%I USING (%s) WITH CHECK (%s)',
                       table_name, predicate, predicate);
        EXECUTE format('REVOKE ALL ON ai_native.%I FROM PUBLIC', table_name);
    END LOOP;
END
$migration$;

CREATE TRIGGER p4_proof_records_immutable
    BEFORE UPDATE OR DELETE ON ai_native.p4_proof_records
    FOR EACH ROW EXECUTE FUNCTION ai_native.guard_owp_ledger();
CREATE TRIGGER p4_proof_records_no_truncate
    BEFORE TRUNCATE ON ai_native.p4_proof_records
    FOR EACH STATEMENT EXECUTE FUNCTION ai_native.guard_owp_ledger();
