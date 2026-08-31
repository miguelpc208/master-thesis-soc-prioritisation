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
SELECT classes.class_id AS process_candidate,
    classes.metadata ->> 'DESCR' AS description,
    classes.metadata ->> 'WFSTATUSATTR' AS workflow_status_attribute,
    COALESCE(classes.metadata ->> 'SUPERCLASS', 'false') = 'true' AS is_superclass,
    COALESCE(string_agg(parents.relname, ', ' ORDER BY parents.relname),
        '[no parent]') AS direct_parent_classes
FROM class_catalog AS classes
LEFT JOIN pg_inherits AS inheritance ON inheritance.inhrelid = classes.oid
LEFT JOIN pg_class AS parents ON parents.oid = inheritance.inhparent
WHERE classes.metadata ->> 'TYPE' = 'class'
  AND COALESCE(classes.metadata ->> 'WFSAVE', 'false') = 'true'
  AND NULLIF(classes.metadata ->> 'WFSTATUSATTR', '') IS NOT NULL
GROUP BY classes.class_id, classes.metadata
ORDER BY classes.class_id;

ROLLBACK;
