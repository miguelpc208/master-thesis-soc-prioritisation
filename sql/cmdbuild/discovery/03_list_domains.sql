BEGIN TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '60s';

WITH domain_catalog AS MATERIALIZED (
    SELECT relations.relname AS domain_table,
        substring(relations.relname FROM 5) AS domain_id,
        public._cm3_class_comment_get_jsonb(relations.oid::regclass) AS metadata
    FROM pg_class AS relations
    JOIN pg_namespace AS namespaces ON namespaces.oid = relations.relnamespace
    WHERE namespaces.nspname = 'public'
      AND relations.relkind IN ('r', 'p')
      AND left(relations.relname, 4) = 'Map_'
      AND obj_description(relations.oid, 'pg_class') LIKE '%TYPE: domain%'
),
target_classes AS (
    SELECT unnest(ARRAY[
        'Supplier', 'SupplyContract', 'ServiceContract', 'Contract', 'SLA',
        'Service', 'BusinessService', 'Application', 'CI', 'Hardware',
        'SWInstance', 'Server', 'PhysicalServer', 'VirtualServer', 'ITProc',
        'IncidentMgt', 'ChangeMgt'
    ]) AS class_id
)
SELECT domain_id, domain_table, metadata ->> 'LABEL' AS label,
    metadata ->> 'CLASS1' AS source_class,
    metadata ->> 'CLASS2' AS destination_class,
    metadata ->> 'CARDIN' AS cardinality,
    COALESCE(metadata ->> 'ACTIVE', 'true') <> 'false' AS is_active,
    metadata ->> 'DISABLED1' AS disabled_source_classes,
    metadata ->> 'DISABLED2' AS disabled_destination_classes
FROM domain_catalog
WHERE metadata ->> 'TYPE' = 'domain'
  AND metadata ->> 'CLASS1' IN (SELECT class_id FROM target_classes)
  AND metadata ->> 'CLASS2' IN (SELECT class_id FROM target_classes)
ORDER BY source_class, destination_class, domain_id;

ROLLBACK;
