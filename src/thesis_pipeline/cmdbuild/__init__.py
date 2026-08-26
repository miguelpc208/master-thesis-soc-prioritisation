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
from thesis_pipeline.cmdbuild.client import (
    CMDBuildAuthenticationError,
    CMDBuildClient,
    CMDBuildConfigurationError,
    CMDBuildError,
    CMDBuildResponseError,
    CMDBuildSettings,
)
from thesis_pipeline.cmdbuild.public_cve import (
    PublicCVEBindingError,
    PublicCVEBindingResult,
    PublicCVERecord,
    bind_public_cves,
)

__all__ = [
    "BusinessCardPayload",
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
    "PublicCVEBindingError",
    "PublicCVEBindingResult",
    "PublicCVERecord",
    "bind_public_cves",
    "build_business_payload_plan",
]
