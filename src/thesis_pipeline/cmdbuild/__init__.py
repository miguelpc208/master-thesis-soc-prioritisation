"""CMDBuild integration for synthetic business and SOC context."""

from thesis_pipeline.cmdbuild.business_payloads import (
    BusinessCardPayload,
    BusinessPayloadError,
    BusinessPayloadPlan,
    BusinessRelationPayload,
    CardReference,
    LookupReference,
    build_business_payload_plan,
)
from thesis_pipeline.cmdbuild.business_writer import (
    BusinessIngestionError,
    BusinessIngestionPreview,
    BusinessIngestionResult,
    execute_business_ingestion,
    prepare_business_ingestion,
)
from thesis_pipeline.cmdbuild.client import (
    CMDBuildAuthenticationError,
    CMDBuildClient,
    CMDBuildConfigurationError,
    CMDBuildError,
    CMDBuildResponseError,
    CMDBuildSettings,
)
from thesis_pipeline.cmdbuild.operational_payloads import (
    OperationalPayloadError,
    OperationalPayloadPlan,
    build_operational_payload_plan,
)
from thesis_pipeline.cmdbuild.operational_writer import (
    OperationalIngestionError,
    OperationalIngestionPreview,
    OperationalIngestionResult,
    OperationalPartialCommitError,
    execute_operational_ingestion,
    prepare_operational_ingestion,
)
from thesis_pipeline.cmdbuild.public_cve import (
    PublicCVEBindingError,
    PublicCVEBindingResult,
    PublicCVERecord,
    bind_public_cves,
)

__all__ = [
    "BusinessCardPayload",
    "BusinessIngestionError",
    "BusinessIngestionPreview",
    "BusinessIngestionResult",
    "BusinessPayloadError",
    "BusinessPayloadPlan",
    "BusinessRelationPayload",
    "CMDBuildAuthenticationError",
    "CMDBuildClient",
    "CMDBuildConfigurationError",
    "CMDBuildError",
    "CMDBuildResponseError",
    "CMDBuildSettings",
    "CardReference",
    "LookupReference",
    "OperationalIngestionError",
    "OperationalPartialCommitError",
    "OperationalIngestionPreview",
    "OperationalIngestionResult",
    "OperationalPayloadError",
    "OperationalPayloadPlan",
    "PublicCVEBindingError",
    "PublicCVEBindingResult",
    "PublicCVERecord",
    "bind_public_cves",
    "build_business_payload_plan",
    "build_operational_payload_plan",
    "execute_business_ingestion",
    "execute_operational_ingestion",
    "prepare_operational_ingestion",
    "prepare_business_ingestion",
]
