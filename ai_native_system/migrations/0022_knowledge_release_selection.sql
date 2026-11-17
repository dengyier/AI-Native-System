CREATE TABLE ai_native.application_release_selection_history (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant text NOT NULL,
    application text NOT NULL,
    previous_digest text,
    digest text NOT NULL,
    changed_by text NOT NULL CHECK (btrim(changed_by) <> ''),
    changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (previous_digest IS DISTINCT FROM digest),
    FOREIGN KEY (tenant, application, previous_digest)
        REFERENCES ai_native.application_releases (tenant, application, digest),
    FOREIGN KEY (tenant, application, digest)
        REFERENCES ai_native.application_releases (tenant, application, digest)
);
CREATE INDEX application_release_selection_history_scope
    ON ai_native.application_release_selection_history (tenant, application, id);
ALTER TABLE ai_native.application_release_selection_history ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON ai_native.application_release_selection_history FOR SELECT
    USING (tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), ''));
REVOKE ALL ON ai_native.application_release_selection_history FROM PUBLIC;

CREATE TRIGGER application_release_selection_history_immutable
    BEFORE UPDATE OR DELETE ON ai_native.application_release_selection_history
    FOR EACH ROW EXECUTE FUNCTION ai_native.guard_release_content();
CREATE TRIGGER application_release_selection_history_no_truncate
    BEFORE TRUNCATE ON ai_native.application_release_selection_history
    FOR EACH STATEMENT EXECUTE FUNCTION ai_native.guard_release_content();

-- Existing control roles can change the pointer without direct audit write privileges.
CREATE FUNCTION ai_native.audit_release_selection() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $function$
DECLARE
    prior text;
BEGIN
    IF TG_RELID <> 'ai_native.application_release_selections'::regclass OR TG_WHEN <> 'AFTER' THEN
        RAISE EXCEPTION 'Invalid release audit trigger source';
    END IF;
    IF NOT pg_has_role(session_user, current_user, 'USAGE')
        AND NEW.tenant IS DISTINCT FROM NULLIF(current_setting('ai_native.tenant', true), '') THEN
        RAISE EXCEPTION 'Invalid release audit tenant';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        prior := OLD.digest;
    END IF;
    IF prior IS DISTINCT FROM NEW.digest THEN
        INSERT INTO ai_native.application_release_selection_history
            (tenant, application, previous_digest, digest, changed_by, changed_at)
        VALUES (NEW.tenant, NEW.application, prior, NEW.digest, NEW.changed_by, NEW.changed_at);
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER application_release_selection_audit
    AFTER INSERT OR UPDATE ON ai_native.application_release_selections
    FOR EACH ROW EXECUTE FUNCTION ai_native.audit_release_selection();
REVOKE EXECUTE ON FUNCTION ai_native.audit_release_selection() FROM PUBLIC;
