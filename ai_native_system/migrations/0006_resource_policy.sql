CREATE TABLE ai_native.resource_grants (
    tenant text NOT NULL,
    principal text NOT NULL,
    operation text NOT NULL CHECK (length(operation) BETWEEN 1 AND 512),
    kind text NOT NULL CHECK (length(kind) BETWEEN 1 AND 512),
    resource_id text NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 512),
    member text NOT NULL DEFAULT '' CHECK (length(member) <= 512),
    PRIMARY KEY (tenant, principal, operation, kind, resource_id, member),
    FOREIGN KEY (tenant, principal) REFERENCES ai_native.principals (tenant, id) ON DELETE CASCADE
);

ALTER TABLE ai_native.resource_grants ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_scope ON ai_native.resource_grants
    USING (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''))
    WITH CHECK (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''));
