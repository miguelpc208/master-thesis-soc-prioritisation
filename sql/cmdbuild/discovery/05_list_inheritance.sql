BEGIN TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '60s';

WITH RECURSIVE class_ancestry AS (
    SELECT relations.relname AS concrete_class, relations.oid AS current_relation,
        relations.relname AS ancestor_class, 0 AS inheritance_depth,
        ARRAY[relations.oid] AS visited_relations
    FROM pg_class AS relations
    JOIN pg_namespace AS namespaces ON namespaces.oid = relations.relnamespace
    WHERE namespaces.nspname = 'public'
      AND relations.relname IN (
          'Supplier', 'SupplyContract', 'ServiceContract', 'SLA', 'BusinessService',
          'Application', 'PhysicalServer', 'VirtualServer', 'IncidentMgt', 'ChangeMgt'
      )
    UNION ALL
    SELECT ancestry.concrete_class, parents.oid, parents.relname,
        ancestry.inheritance_depth + 1, ancestry.visited_relations || parents.oid
    FROM class_ancestry AS ancestry
    JOIN pg_inherits AS inheritance ON inheritance.inhrelid = ancestry.current_relation
    JOIN pg_class AS parents ON parents.oid = inheritance.inhparent
    WHERE NOT parents.oid = ANY(ancestry.visited_relations)
)
SELECT concrete_class, inheritance_depth, ancestor_class
FROM class_ancestry
ORDER BY concrete_class, inheritance_depth, ancestor_class;

WITH RECURSIVE class_ancestry AS (
    SELECT relations.relname AS concrete_class, relations.oid AS current_relation,
        relations.relname AS ancestor_class, 0 AS inheritance_depth,
        ARRAY[relations.oid] AS visited_relations
    FROM pg_class AS relations
    JOIN pg_namespace AS namespaces ON namespaces.oid = relations.relnamespace
    WHERE namespaces.nspname = 'public'
      AND relations.relname IN (
          'Supplier', 'SupplyContract', 'ServiceContract', 'SLA', 'BusinessService',
          'Application', 'PhysicalServer', 'VirtualServer', 'IncidentMgt', 'ChangeMgt'
      )
    UNION ALL
    SELECT ancestry.concrete_class, parents.oid, parents.relname,
        ancestry.inheritance_depth + 1, ancestry.visited_relations || parents.oid
    FROM class_ancestry AS ancestry
    JOIN pg_inherits AS inheritance ON inheritance.inhrelid = ancestry.current_relation
    JOIN pg_class AS parents ON parents.oid = inheritance.inhparent
    WHERE NOT parents.oid = ANY(ancestry.visited_relations)
),
domain_catalog AS MATERIALIZED (
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
required_relationships(relationship_id, source_class, destination_class) AS (
    VALUES
        ('vendor_contract', 'Supplier', 'SupplyContract'),
        ('contract_sla', 'SupplyContract', 'SLA'),
        ('sla_business_service', 'SLA', 'BusinessService'),
        ('business_service_application', 'BusinessService', 'Application'),
        ('application_physical_server', 'Application', 'PhysicalServer'),
        ('application_virtual_server', 'Application', 'VirtualServer'),
        ('incident_physical_asset', 'IncidentMgt', 'PhysicalServer'),
        ('incident_virtual_asset', 'IncidentMgt', 'VirtualServer'),
        ('change_incident', 'ChangeMgt', 'IncidentMgt')
), active_domains AS MATERIALIZED (
    SELECT domain_id, metadata ->> 'CLASS1' AS source_class,
        metadata ->> 'CLASS2' AS destination_class,
        COALESCE(metadata ->> 'DISABLED1', '') AS disabled_source_classes,
        COALESCE(metadata ->> 'DISABLED2', '') AS disabled_destination_classes
    FROM domain_catalog
    WHERE metadata ->> 'TYPE' = 'domain'
      AND COALESCE(metadata ->> 'ACTIVE', 'true') <> 'false'
), compatible_domains AS (
    SELECT DISTINCT required.relationship_id, domains.domain_id,
        CASE WHEN domains.source_class = source_ancestry.ancestor_class
                  AND domains.destination_class = destination_ancestry.ancestor_class
             THEN 'direct' ELSE 'inverse' END AS orientation
    FROM required_relationships AS required
    JOIN class_ancestry AS source_ancestry
        ON source_ancestry.concrete_class = required.source_class
    JOIN class_ancestry AS destination_ancestry
        ON destination_ancestry.concrete_class = required.destination_class
    JOIN active_domains AS domains ON (
        domains.source_class = source_ancestry.ancestor_class
        AND domains.destination_class = destination_ancestry.ancestor_class
        AND NOT required.source_class = ANY(
            string_to_array(domains.disabled_source_classes, ',')
        )
        AND NOT required.destination_class = ANY(
            string_to_array(domains.disabled_destination_classes, ',')
        )
    ) OR (
        domains.source_class = destination_ancestry.ancestor_class
        AND domains.destination_class = source_ancestry.ancestor_class
        AND NOT required.destination_class = ANY(
            string_to_array(domains.disabled_source_classes, ',')
        )
        AND NOT required.source_class = ANY(
            string_to_array(domains.disabled_destination_classes, ',')
        )
    )
)
SELECT required.relationship_id, required.source_class, required.destination_class,
    COUNT(DISTINCT compatible.domain_id) AS compatible_native_domains,
    COALESCE(array_to_string(array_agg(
        DISTINCT compatible.domain_id || ' [' || compatible.orientation || ']'
    ) FILTER (WHERE compatible.domain_id IS NOT NULL), ', '),
    '[NO ACTIVE NATIVE DOMAIN]') AS native_domain_candidates
FROM required_relationships AS required
LEFT JOIN compatible_domains AS compatible
    ON compatible.relationship_id = required.relationship_id
GROUP BY required.relationship_id, required.source_class, required.destination_class
ORDER BY required.relationship_id;

ROLLBACK;
