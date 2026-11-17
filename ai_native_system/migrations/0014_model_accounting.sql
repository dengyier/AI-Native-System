CREATE TABLE ai_native.model_calls (
    tenant text NOT NULL,
    call_id text NOT NULL,
    task_id text,
    purpose text NOT NULL CHECK (purpose IN ('generation', 'embedding')),
    max_active integer NOT NULL CHECK (max_active > 0),
    max_attempts integer NOT NULL CHECK (max_attempts > 0),
    max_tokens bigint NOT NULL CHECK (max_tokens > 0),
    max_cost_nanos bigint NOT NULL CHECK (max_cost_nanos >= 0),
    deadline_seconds double precision NOT NULL CHECK (deadline_seconds > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    deadline_at timestamptz NOT NULL,
    PRIMARY KEY (tenant, call_id),
    FOREIGN KEY (tenant, task_id) REFERENCES ai_native.tasks(tenant, id)
);

CREATE TABLE ai_native.model_attempts (
    tenant text NOT NULL,
    attempt_id text NOT NULL,
    call_id text NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal > 0),
    route text NOT NULL,
    provider text NOT NULL,
    model text NOT NULL,
    model_version text NOT NULL,
    price_version text NOT NULL,
    input_nanos bigint NOT NULL CHECK (input_nanos >= 0),
    output_nanos bigint NOT NULL CHECK (output_nanos >= 0),
    max_input_tokens bigint NOT NULL CHECK (max_input_tokens > 0),
    max_output_tokens bigint NOT NULL CHECK (max_output_tokens >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    deadline_at timestamptz NOT NULL,
    active_until timestamptz NOT NULL CHECK (active_until >= deadline_at),
    outcome text CHECK (outcome IN ('succeeded', 'failed', 'timeout', 'cancelled')),
    finished_at timestamptz,
    actual_provider text,
    actual_model text,
    input_tokens bigint CHECK (input_tokens >= 0),
    output_tokens bigint CHECK (output_tokens >= 0),
    charged_tokens numeric GENERATED ALWAYS AS (
        coalesce(input_tokens, max_input_tokens)::numeric + coalesce(output_tokens, max_output_tokens)::numeric
    ) STORED,
    charged_cost_nanos numeric GENERATED ALWAYS AS (
        coalesce(input_tokens, max_input_tokens)::numeric * input_nanos
        + coalesce(output_tokens, max_output_tokens)::numeric * output_nanos
    ) STORED,
    PRIMARY KEY (tenant, attempt_id),
    UNIQUE (tenant, call_id, ordinal),
    FOREIGN KEY (tenant, call_id) REFERENCES ai_native.model_calls(tenant, call_id),
    CHECK ((outcome IS NULL) = (finished_at IS NULL))
);

ALTER TABLE ai_native.model_calls ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_native.model_attempts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON ai_native.model_calls
    USING (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''))
    WITH CHECK (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''));
CREATE POLICY tenant_scope ON ai_native.model_attempts
    USING (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''))
    WITH CHECK (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''));
REVOKE ALL ON ai_native.model_calls, ai_native.model_attempts FROM PUBLIC;
