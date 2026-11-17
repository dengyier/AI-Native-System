-- Delegations are provisioned separately from application runtime roles.
CREATE TABLE ai_native.enterprise_delegations (
    tenant text NOT NULL,
    id text NOT NULL,
    actor text NOT NULL,
    service text NOT NULL,
    starts_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    PRIMARY KEY (tenant, id),
    FOREIGN KEY (tenant, actor) REFERENCES ai_native.principals(tenant, id),
    FOREIGN KEY (tenant, service) REFERENCES ai_native.principals(tenant, id),
    CHECK (actor <> service),
    CHECK (expires_at > starts_at)
);

CREATE TABLE ai_native.enterprise_delegation_scopes (
    tenant text NOT NULL,
    delegation_id text NOT NULL,
    operation text NOT NULL,
    kind text NOT NULL,
    resource_id text NOT NULL,
    member text NOT NULL DEFAULT '',
    PRIMARY KEY (tenant, delegation_id, operation, kind, resource_id, member),
    FOREIGN KEY (tenant, delegation_id) REFERENCES ai_native.enterprise_delegations(tenant, id)
);

ALTER TABLE ai_native.enterprise_delegations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON ai_native.enterprise_delegations
    USING (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''))
    WITH CHECK (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''));

ALTER TABLE ai_native.enterprise_delegation_scopes ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON ai_native.enterprise_delegation_scopes
    USING (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''))
    WITH CHECK (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''));
