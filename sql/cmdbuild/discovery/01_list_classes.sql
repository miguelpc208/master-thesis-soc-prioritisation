BEGIN TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '60s';

WITH class_catalog AS MATERIALIZED (
    SELECT relations.oid, relations.relname AS class_id,
        public._cm3_class_comment_get_jsonb(relations.oid::regclass) AS metadata
    FROM pg_class AS relations
    JOIN pg_namespace AS namespaces ON namespaces.oid = relations.relnamespace
    WHERE namespaces.nspname = 'public'
      AND relations.relkind IN ('r', 'p')
      AND obj_description(relations.oid, 'pg_class') LIKE '%TYPE: class%'
)
SELECT class_id, metadata ->> 'DESCR' AS description,
    metadata ->> 'MODE' AS access_mode,
    COALESCE(metadata ->> 'SUPERCLASS', 'false') = 'true' AS is_superclass,
    COALESCE(metadata ->> 'WFSAVE', 'false') = 'true' AS is_workflow,
    metadata ->> 'WFSTATUSATTR' AS workflow_status_attribute
FROM class_catalog
WHERE metadata ->> 'TYPE' = 'class'
  AND metadata ->> 'MODE' IS DISTINCT FROM 'reserved'
  AND (
      class_id ~* 'supplier|vendor|company|contract|sla|service|application|server|incident|change'
      OR class_id IN ('CI', 'Hardware', 'SWInstance', 'ITProc', 'Activity')
  )
ORDER BY class_id;

ROLLBACK;
