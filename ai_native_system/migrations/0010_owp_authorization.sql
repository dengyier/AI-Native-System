-- Opt-in cannot be bypassed by selecting an older unprotected release.
CREATE TABLE ai_native.owp_enforced_tenants (
    tenant text PRIMARY KEY
);

-- Every managed task is admitted under the deployment epoch configured outside PostgreSQL.
CREATE TABLE ai_native.owp_task_admissions (
    tenant text NOT NULL,
    task_id text NOT NULL,
    epoch text NOT NULL CHECK (btrim(epoch) <> ''),
    admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant, task_id),
    UNIQUE (tenant, task_id, epoch),
    FOREIGN KEY (tenant, task_id) REFERENCES ai_native.tasks(tenant, id)
);

CREATE TABLE ai_native.owp_authorizations (
    tenant text NOT NULL,
    operation_id text NOT NULL,
    task_id text NOT NULL,
    epoch text NOT NULL,
    nonce text NOT NULL CHECK (btrim(nonce) <> ''),
    authorization_digest text NOT NULL CHECK (authorization_digest ~ '^[0-9a-f]{64}$'),
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    issued_at bigint NOT NULL,
    expires_at bigint NOT NULL,
    envelope text NOT NULL,
    PRIMARY KEY (tenant, operation_id),
    UNIQUE (tenant, nonce),
    UNIQUE (tenant, operation_id, nonce, authorization_digest, request_digest),
    FOREIGN KEY (tenant, task_id, epoch) REFERENCES ai_native.owp_task_admissions(tenant, task_id, epoch),
    CHECK (expires_at > issued_at)
);

CREATE TABLE ai_native.owp_consumptions (
    tenant text NOT NULL,
    operation_id text NOT NULL,
    nonce text NOT NULL,
    authorization_digest text NOT NULL,
    request_digest text NOT NULL,
    remote boolean NOT NULL,
    consumed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant, operation_id),
    UNIQUE (tenant, nonce),
    UNIQUE (tenant, operation_id, authorization_digest),
    FOREIGN KEY (tenant, operation_id, nonce, authorization_digest, request_digest)
        REFERENCES ai_native.owp_authorizations(tenant, operation_id, nonce, authorization_digest, request_digest)
);

CREATE TABLE ai_native.owp_revocations (
    tenant text NOT NULL,
    operation_id text NOT NULL,
    actor text NOT NULL CHECK (btrim(actor) <> ''),
    reason text NOT NULL CHECK (btrim(reason) <> ''),
    revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant, operation_id),
    FOREIGN KEY (tenant, operation_id) REFERENCES ai_native.owp_authorizations(tenant, operation_id)
);

CREATE FUNCTION ai_native.guard_owp_ledger() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $function$
BEGIN
    RAISE EXCEPTION 'OpenWorkProof ledger records are immutable' USING ERRCODE = '23514';
END
$function$;

DO $migration$
DECLARE
    table_name text;
    predicate constant text := $scope$tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), '')$scope$;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'owp_enforced_tenants','owp_task_admissions','owp_authorizations','owp_consumptions','owp_revocations'
    ] LOOP
        EXECUTE format('ALTER TABLE ai_native.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('CREATE POLICY tenant_scope ON ai_native.%I USING (%s) WITH CHECK (%s)',
                       table_name, predicate, predicate);
        EXECUTE format('CREATE TRIGGER immutable_row BEFORE UPDATE OR DELETE ON ai_native.%I
                        FOR EACH ROW EXECUTE FUNCTION ai_native.guard_owp_ledger()', table_name);
        EXECUTE format('CREATE TRIGGER immutable_table BEFORE TRUNCATE ON ai_native.%I
                        FOR EACH STATEMENT EXECUTE FUNCTION ai_native.guard_owp_ledger()', table_name);
        EXECUTE format('REVOKE ALL ON ai_native.%I FROM PUBLIC', table_name);
    END LOOP;
END
$migration$;
