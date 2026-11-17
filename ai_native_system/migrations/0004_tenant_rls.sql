-- A trusted runtime sets ai_native.tenant only for the current transaction.
-- The offline migration owner retains its standard owner bypass. Runtime
-- roles must neither own these tables nor hold a role that bypasses RLS.
DO $migration$
DECLARE
    table_name text;
    task_column text;
    predicate text;
    tenant_scope constant text := $scope$NULLIF(pg_catalog.current_setting('ai_native.tenant', true), '')$scope$;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'principals', 'objects', 'knowledge', 'knowledge_history', 'tasks',
        'ontology_releases', 'identity_mappings', 'fact_assertions', 'source_events',
        'fact_projections', 'source_cursors', 'fact_invalidation_outbox'
    ] LOOP
        predicate := 'tenant = ' || tenant_scope;
        EXECUTE format('ALTER TABLE ai_native.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('CREATE POLICY tenant_scope ON ai_native.%I USING (%s) WITH CHECK (%s)',
                       table_name, predicate, predicate);
    END LOOP;

    FOR table_name, task_column IN VALUES
        ('legacy_task_order', 'task_id'), ('steps', 'task_id'), ('events', 'task_id'),
        ('execution_claims', 'task_id'), ('remote_operations', 'operation_id'), ('effects', 'operation_id')
    LOOP
        predicate := format(
            'EXISTS (SELECT 1 FROM ai_native.tasks AS task
                     WHERE task.id = %I.%I AND task.tenant = %s)',
            table_name, task_column, tenant_scope);
        EXECUTE format('ALTER TABLE ai_native.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('CREATE POLICY tenant_scope ON ai_native.%I USING (%s) WITH CHECK (%s)',
                       table_name, predicate, predicate);
    END LOOP;
END
$migration$;
