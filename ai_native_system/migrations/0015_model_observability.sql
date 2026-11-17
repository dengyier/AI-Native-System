-- Metadata-only delivery state, independent of model accounting and authorization.
CREATE TABLE ai_native.model_trace_outbox (
    tenant text NOT NULL,
    event_id text NOT NULL CHECK (event_id ~ '^[0-9a-f]{64}$'),
    trace_id text NOT NULL CHECK (trace_id ~ '^[0-9a-f]{32}$'),
    tenant_ref text NOT NULL CHECK (tenant_ref ~ '^[0-9a-f]{64}$'),
    call_ref text NOT NULL CHECK (call_ref ~ '^[0-9a-f]{64}$'),
    attempt_ref text NOT NULL CHECK (attempt_ref ~ '^[0-9a-f]{64}$'),
    task_ref text CHECK (task_ref ~ '^[0-9a-f]{64}$'),
    action_ref text CHECK (action_ref ~ '^[0-9a-f]{64}$'),
    evidence_ref text CHECK (evidence_ref ~ '^[0-9a-f]{64}$'),
    provider_ref text CHECK (provider_ref ~ '^[0-9a-f]{64}$'),
    route_ref text CHECK (route_ref ~ '^[0-9a-f]{64}$'),
    kind text NOT NULL CHECK (kind IN ('generation', 'embedding')),
    outcome text NOT NULL CHECK (outcome IN ('succeeded', 'failed', 'timeout', 'cancelled')),
    input_tokens bigint CHECK (input_tokens >= 0),
    output_tokens bigint CHECK (output_tokens >= 0),
    cost_nanos bigint CHECK (cost_nanos >= 0),
    elapsed_ms bigint CHECK (elapsed_ms >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'sending', 'sent', 'failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    lease_token text CHECK (lease_token ~ '^[0-9a-f]{32}$'),
    lease_until timestamptz,
    sent_at timestamptz,
    last_error text CHECK (last_error IN ('export_failed', 'lease_expired')),
    PRIMARY KEY (tenant, event_id),
    CHECK ((state = 'sending') = (lease_token IS NOT NULL)),
    CHECK ((state = 'sending') = (lease_until IS NOT NULL)),
    CHECK ((state = 'sent') = (sent_at IS NOT NULL))
);

CREATE INDEX model_trace_pending ON ai_native.model_trace_outbox (tenant, available_at, event_id)
    WHERE state = 'pending';
CREATE INDEX model_trace_sending ON ai_native.model_trace_outbox (tenant, lease_until, event_id)
    WHERE state = 'sending';

ALTER TABLE ai_native.model_trace_outbox ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON ai_native.model_trace_outbox
    USING (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''))
    WITH CHECK (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''));
REVOKE ALL ON ai_native.model_trace_outbox FROM PUBLIC;
