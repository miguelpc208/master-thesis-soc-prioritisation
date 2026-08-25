# CMDBuild READY2USE discovery decisions

Verified installation: READY2USE 2.4 on CMDBuild 4.1, PostgreSQL 17.11,
PostGIS 3.5.7, UTC, 779 public tables, and 411 pipe-delimited metadata comments.
All discovery queries execute in read-only transactions and use native metadata
helpers exposed by the observed installation.

| Experiment concept | Observed identifier | Interpretation |
| --- | --- | --- |
| Vendor | `Supplier` | Concrete class. |
| Supplier contract | `SupplyContract` | Concrete; `Contract` is a superclass. |
| SLA | `SLA` | Concrete class. |
| Business service | `BusinessService` | Concrete; `Impact` is lookup-backed. |
| Application | `Application` | Concrete; no native criticality field evidenced. |
| Physical/virtual asset | `PhysicalServer` / `VirtualServer` | `Server` is a superclass. |
| Incident/change | `IncidentMgt` / `ChangeMgt` | Verified `WFSAVE` workflows. |

`SupplierContract` connects `Supplier` to `SupplyContract`; `SLAContract` and
`SLAService` use superclass endpoints. `HardwareSoftwareInstance` may connect
concrete servers to applications through inheritance. Missing native domains
must be identified before choosing custom relations or analytical bridge tables.

`Contract.EndDate` is reserved; the observed business field is `ExpirationDate`.
`TakeChargeTimestamp` is read-only. Native CVE fields, incident-to-asset links,
and application criticality remain unconfirmed. Do not substitute unrelated
fields or claim REST compatibility before authenticated API verification.

The existing `config/cmdbuild_fields.json` remains intentionally unchanged.
