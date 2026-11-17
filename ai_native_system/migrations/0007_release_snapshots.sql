-- Canonical, immutable content with a separate tenant-scoped lifecycle and active pointer.
CREATE TABLE ai_native.application_releases (
    tenant text NOT NULL CHECK (btrim(tenant) <> ''),
    digest text NOT NULL CHECK (digest = encode(sha256(convert_to(document, 'UTF8')), 'hex')),
    document text NOT NULL,
    application text GENERATED ALWAYS AS (document::jsonb ->> 'application') STORED NOT NULL,
    ontology_namespace text GENERATED ALWAYS AS (document::jsonb #>> '{ontology,definition,namespace}') STORED NOT NULL,
    ontology_version text GENERATED ALWAYS AS ((document::jsonb #> '{ontology,definition,version}')::text) STORED NOT NULL,
    ontology_digest text GENERATED ALWAYS AS (document::jsonb #>> '{ontology,digest}') STORED NOT NULL,
    created_by text NOT NULL CHECK (btrim(created_by) <> ''),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant, digest),
    UNIQUE (tenant, application, digest)
);
CREATE INDEX application_releases_ontology
    ON ai_native.application_releases (tenant, ontology_namespace, ontology_version);

CREATE TABLE ai_native.application_release_lifecycle (
    tenant text NOT NULL,
    digest text NOT NULL,
    status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'deprecated', 'revoked')),
    migration_ref text CHECK (btrim(migration_ref) <> ''),
    changed_by text NOT NULL CHECK (btrim(changed_by) <> ''),
    changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant, digest),
    FOREIGN KEY (tenant, digest) REFERENCES ai_native.application_releases (tenant, digest)
);

CREATE TABLE ai_native.application_release_selections (
    tenant text NOT NULL,
    application text NOT NULL,
    digest text NOT NULL,
    changed_by text NOT NULL CHECK (btrim(changed_by) <> ''),
    changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant, application),
    FOREIGN KEY (tenant, application, digest)
        REFERENCES ai_native.application_releases (tenant, application, digest)
);

CREATE FUNCTION ai_native.guard_release_content() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $function$
BEGIN
    RAISE EXCEPTION 'Release records are immutable' USING ERRCODE = '23514';
END
$function$;

CREATE TRIGGER application_release_content_immutable
    BEFORE UPDATE OR DELETE ON ai_native.application_releases
    FOR EACH ROW EXECUTE FUNCTION ai_native.guard_release_content();
CREATE TRIGGER application_releases_no_truncate
    BEFORE TRUNCATE ON ai_native.application_releases
    FOR EACH STATEMENT EXECUTE FUNCTION ai_native.guard_release_content();
CREATE TRIGGER application_release_lifecycle_no_delete
    BEFORE DELETE ON ai_native.application_release_lifecycle
    FOR EACH ROW EXECUTE FUNCTION ai_native.guard_release_content();
CREATE TRIGGER application_release_lifecycle_no_truncate
    BEFORE TRUNCATE ON ai_native.application_release_lifecycle
    FOR EACH STATEMENT EXECUTE FUNCTION ai_native.guard_release_content();
CREATE TRIGGER application_release_selections_no_delete
    BEFORE DELETE ON ai_native.application_release_selections
    FOR EACH ROW EXECUTE FUNCTION ai_native.guard_release_content();
CREATE TRIGGER application_release_selections_no_truncate
    BEFORE TRUNCATE ON ai_native.application_release_selections
    FOR EACH STATEMENT EXECUTE FUNCTION ai_native.guard_release_content();

CREATE FUNCTION ai_native.guard_release_lifecycle() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $function$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'draft' OR NEW.migration_ref IS NOT NULL THEN
            RAISE EXCEPTION 'New release must be a draft' USING ERRCODE = '23514';
        END IF;
    ELSIF (NEW.tenant, NEW.digest) IS DISTINCT FROM (OLD.tenant, OLD.digest)
          OR (NEW.status <> 'published' AND NEW.migration_ref IS DISTINCT FROM OLD.migration_ref)
          OR NOT (
                (OLD.status = 'draft' AND NEW.status IN ('published', 'revoked'))
                OR (OLD.status = 'published' AND NEW.status IN ('deprecated', 'revoked'))
                OR (OLD.status = 'deprecated' AND NEW.status = 'revoked')
          ) THEN
        RAISE EXCEPTION 'Invalid release lifecycle transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$function$;
CREATE TRIGGER application_release_lifecycle_transitions
    BEFORE INSERT OR UPDATE ON ai_native.application_release_lifecycle
    FOR EACH ROW EXECUTE FUNCTION ai_native.guard_release_lifecycle();

CREATE FUNCTION ai_native.guard_release_selection() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $function$
BEGIN
    IF TG_OP = 'UPDATE' AND (OLD.tenant, OLD.application) IS DISTINCT FROM (NEW.tenant, NEW.application) THEN
        RAISE EXCEPTION 'Release selection scope is immutable' USING ERRCODE = '23514';
    END IF;
    PERFORM 1 FROM ai_native.application_release_lifecycle
        WHERE tenant = NEW.tenant AND digest = NEW.digest AND status = 'published'
        FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Active release selection requires a published release' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$function$;
CREATE TRIGGER application_release_selection_published
    BEFORE INSERT OR UPDATE ON ai_native.application_release_selections
    FOR EACH ROW EXECUTE FUNCTION ai_native.guard_release_selection();

DO $migration$
DECLARE
    table_name text;
    predicate constant text := $scope$tenant = NULLIF(pg_catalog.current_setting('ai_native.tenant', true), '')$scope$;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'application_releases', 'application_release_lifecycle', 'application_release_selections'
    ] LOOP
        EXECUTE format('ALTER TABLE ai_native.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('CREATE POLICY tenant_scope ON ai_native.%I USING (%s) WITH CHECK (%s)',
                       table_name, predicate, predicate);
        EXECUTE format('REVOKE ALL ON ai_native.%I FROM PUBLIC', table_name);
    END LOOP;
END
$migration$;
