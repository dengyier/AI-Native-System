"""Ordered PostgreSQL schema revisions for the explicit migration runner."""

REVISIONS = (
    "0001_legacy", "0002_semantics", "0003_semantic_state", "0004_tenant_rls",
    "0005_enterprise_identity", "0006_resource_policy", "0007_release_snapshots", "0008_task_governance",
    "0009_fact_sync", "0010_owp_authorization", "0011_owp_evidence",
    "0012_p4_delivery", "0013_p4_execution", "0014_model_accounting", "0015_model_observability",
    "0016_graph_tasks",
    "0017_knowledge_vectors", "0018_knowledge_evidence", "0019_knowledge_tasks",
    "0020_application_delivery", "0021_knowledge_lexical", "0022_knowledge_release_selection",
)
