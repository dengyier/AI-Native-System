-- Persist evidence together with the effect. A separate signer may resume it
-- after failure without access to tools or credentials for those tools.
CREATE TABLE ai_native.owp_effect_evidence (
    tenant text NOT NULL,
    task_id text NOT NULL,
    operation_id text NOT NULL,
    authorization_digest text NOT NULL CHECK (authorization_digest ~ '^[0-9a-f]{64}$'),
    result_digest text NOT NULL CHECK (result_digest ~ '^[0-9a-f]{64}$'),
    observation text NOT NULL CHECK (observation IN ('local_transaction', 'remote_receipt_observed')),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    attempts bigint NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error text CHECK (last_error IN ('signer_unavailable', 'invalid_proof')),
    signed_document text,
    delivered_at timestamptz,
    PRIMARY KEY (tenant, operation_id),
    FOREIGN KEY (tenant, task_id) REFERENCES ai_native.tasks(tenant, id),
    FOREIGN KEY (operation_id) REFERENCES ai_native.effects(operation_id),
    FOREIGN KEY (tenant, operation_id, authorization_digest)
        REFERENCES ai_native.owp_consumptions(tenant, operation_id, authorization_digest),
    -- The current effects schema keys its single operation by task id.
    CHECK (operation_id = task_id),
    CHECK ((signed_document IS NULL) = (delivered_at IS NULL)),
    CHECK (delivered_at IS NULL OR (last_error IS NULL AND attempts > 0 AND delivered_at >= recorded_at))
);

CREATE INDEX owp_effect_evidence_pending
    ON ai_native.owp_effect_evidence (tenant, recorded_at, operation_id)
    WHERE delivered_at IS NULL;

REVOKE ALL ON ai_native.owp_effect_evidence FROM PUBLIC;
ALTER TABLE ai_native.owp_effect_evidence ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON ai_native.owp_effect_evidence
    USING (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''))
    WITH CHECK (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''));

CREATE FUNCTION ai_native.guard_owp_effect_evidence() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $function$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.attempts <> 0 OR NEW.last_error IS NOT NULL OR NEW.signed_document IS NOT NULL THEN
            RAISE EXCEPTION 'New evidence must start pending' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_OP <> 'UPDATE' OR OLD.signed_document IS NOT NULL
       OR (NEW.tenant, NEW.task_id, NEW.operation_id, NEW.authorization_digest,
           NEW.result_digest, NEW.observation, NEW.recorded_at)
          IS DISTINCT FROM
          (OLD.tenant, OLD.task_id, OLD.operation_id, OLD.authorization_digest,
           OLD.result_digest, OLD.observation, OLD.recorded_at)
       OR NEW.attempts <> OLD.attempts + 1 THEN
        RAISE EXCEPTION 'Evidence facts and delivered signatures are immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER owp_effect_evidence_guard
    BEFORE INSERT OR UPDATE OR DELETE ON ai_native.owp_effect_evidence
    FOR EACH ROW EXECUTE FUNCTION ai_native.guard_owp_effect_evidence();
CREATE TRIGGER owp_effect_evidence_no_truncate
    BEFORE TRUNCATE ON ai_native.owp_effect_evidence
    FOR EACH STATEMENT EXECUTE FUNCTION ai_native.guard_owp_ledger();
