# CVE records

The tracker parses [CVE JSON 5.0](https://github.com/CVEProject/cve-schema) records from the [official CVE List](https://github.com/CVEProject/cvelistV5) and stores them in the database.
The schema follows the upstream format; see the [CVE record content rules](https://www.cve.org/ResourcesSupport/AllResources/CNARules#section_5_CVE_Record_Content) and the [schema reference](https://cveproject.github.io/cve-schema/schema/docs/) for field definitions.

Implementation: [`src/shared/models/cve.py`](../src/shared/models/cve.py).

## Top-level record (`CveRecord`)

| Field | Meaning |
| --- | --- |
| `cve_id` | Identifier, E.g. `CVE-2024-1234` |
| `state` | `PUBLISHED` or `REJECTED` |
| `assigner` / `requester` | CNA organizations that assigned or requested the ID |
| `date_published`, `date_updated`, `date_reserved` | Timestamps from the CVE Program |
| `serial` | Record revision number |
| `triaged` | Internal flag: a security team member has reviewed this CVE |

Each CVE has one or more **containers** (`Container`), holding the actual vulnerability data.

## Container (`Container`)

A container is published by a CVE Numbering Authority (CNA) or an Authorized Data Publisher (ADP).

| Field | Meaning |
| --- | --- |
| `title` | Short summary |
| `descriptions` | Long-form text (language-tagged) |
| `affected` | Products and version ranges that may be vulnerable (see below) |
| `problem_types` | CWE identifiers and descriptions |
| `references` | URLs with optional tags (advisory, patch, etc.) |
| `metrics` | CVSS vector strings (v3.0, v3.1, v4.0) |
| `configurations`, `workarounds`, `solutions`, `exploits` | Additional structured text |
| `timeline`, `credits`, `tags` | Events, attribution, labels |
| `source` | Raw JSON fragment from ingestion |

## Affected products (`AffectedProduct`)

This is what the matching algorithm uses to find Nixpkgs packages.

| Field | Meaning |
| --- | --- |
| `vendor`, `product` | Upstream vendor and product name |
| `package_name` | Package name when the CNA provides one |
| `cpes` | [CPE](https://nvd.nist.gov/products/cpe) strings identifying software |
| `versions` | Version constraints with status `affected`, `unaffected`, or `unknown` |
| `platforms` | OS or environment qualifiers |
| `repo`, `collection_url` | Source repository hints |
| `modules`, `program_files`, `program_routines` | Finer-grained location within a product |

Each `Version` entry expresses a constraint: exact version (`version`), upper bound (`less_than`, `less_equal`), and whether that range is affected.

## Why matching needs manual triage

CVE records describe upstream software by vendor names, product names, and CPE strings.
Nixpkgs identifies packages by attribute paths and derivation names.
Those naming schemes rarely align one-to-one, and version information in CVE data is often incomplete or imprecise.

The tracker proposes links automatically, but a human must verify each match, ignore irrelevant packages, and publish an issue when Nixpkgs is actually affected.
