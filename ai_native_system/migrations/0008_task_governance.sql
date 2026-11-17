CREATE TABLE ai_native.governed_tenants (
    tenant text PRIMARY KEY
);

ALTER TABLE ai_native.tasks ADD UNIQUE (tenant, id);

CREATE TABLE ai_native.task_governance (
    tenant text NOT NULL,
    task_id text NOT NULL,
    release_digest text NOT NULL,
    requester_context text NOT NULL,
    approver_context text,
    PRIMARY KEY (tenant, task_id),
    FOREIGN KEY (tenant, task_id) REFERENCES ai_native.tasks(tenant, id),
    FOREIGN KEY (tenant, release_digest) REFERENCES ai_native.application_releases(tenant, digest)
);

DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['governed_tenants', 'task_governance'] LOOP
        EXECUTE format('ALTER TABLE ai_native.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('CREATE POLICY tenant_scope ON ai_native.%I
            USING (tenant = NULLIF(pg_catalog.current_setting(''ai_native.tenant'', true), ''''))
            WITH CHECK (tenant = NULLIF(pg_catalog.current_setting(''ai_native.tenant'', true), ''''))', table_name);
    END LOOP;
END
$$;
