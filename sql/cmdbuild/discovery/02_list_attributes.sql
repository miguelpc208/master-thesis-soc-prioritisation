BEGIN TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '60s';

WITH selected_attributes AS MATERIALIZED (
    SELECT relations.oid AS relation_id, relations.relname AS class_id,
        attributes.attnum AS ordinal_position, attributes.attname AS attribute_id,
        format_type(attributes.atttypid, attributes.atttypmod) AS postgres_type,
        attributes.attnotnull AS not_null, NOT attributes.attislocal AS is_inherited
    FROM pg_class AS relations
    JOIN pg_namespace AS namespaces ON namespaces.oid = relations.relnamespace
    JOIN pg_attribute AS attributes ON attributes.attrelid = relations.oid
    WHERE namespaces.nspname = 'public'
      AND relations.relname IN (
          'Supplier', 'SupplyContract', 'ServiceContract', 'Contract', 'SLA',
          'BusinessService', 'Application', 'Server', 'PhysicalServer',
          'VirtualServer', 'IncidentMgt', 'ChangeMgt'
      )
      AND attributes.attnum > 0 AND NOT attributes.attisdropped
      AND col_description(relations.oid, attributes.attnum) IS NOT NULL
      AND attributes.attname IN (
          'Code', 'Name', 'Description', 'ShortDescr', 'ExtDescr',
          'ExtendedDescription', 'StartDate', 'ExpirationDate', 'EndDate',
          'CreationTimestamp', 'ClosureTimestamp', 'TakeChargeTimestamp',
          'TakeChargeExpiry', 'ResolutionExpiry', 'ExpectedClosureDate',
          'Priority', 'PriorityIndex', 'Impact', 'Urgency', 'ProcessStatus',
          'FlowStatus', 'Number', 'MonitoringEventId', 'Supplier', 'Contract',
          'Service', 'ServiceContract', 'SLA', 'Hardware', 'HardwareKey',
          'Hostname', 'HostName', 'Environment', 'Criticality', 'Category',
          'Subcategory', 'Owner', 'ServiceOwner', 'State', 'ServiceState',
          'HDAnalysisTime', 'SPAnalysisTime', 'HDExecTime', 'SPExecTime',
          'STHDClassification', 'CTHDClassification', 'TTHDClassification',
          'STSPClassification', 'CTSPClassification', 'TTSPClassification',
          'ExecTime1', 'PrevExecTime1'
      )
), attribute_catalog AS MATERIALIZED (
    SELECT *, public._cm3_attribute_comment_get(
        relation_id::regclass, attribute_id::character varying
    ) AS metadata
    FROM selected_attributes
)
SELECT class_id, attribute_id, postgres_type, metadata ->> 'MODE' AS access_mode,
    metadata ->> 'DESCR' AS description, metadata ->> 'LOOKUP' AS lookup_name,
    metadata ->> 'REFERENCEDOM' AS reference_domain,
    metadata ->> 'REFERENCEDIR' AS reference_direction,
    metadata ->> 'ACTIVE' AS active, not_null, is_inherited
FROM attribute_catalog
ORDER BY class_id, ordinal_position;

ROLLBACK;
