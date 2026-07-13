# CVE records

The tracker parses [CVE JSON 5.0](https://github.com/CVEProject/cve-schema) records from the [official CVE List](https://github.com/CVEProject/cvelistV5) and stores them in the database.
The schema follows the upstream format; see the [CVE record content rules](https://www.cve.org/ResourcesSupport/AllResources/CNARules#section_5_CVE_Record_Content) and the [schema reference](https://cveproject.github.io/cve-schema/schema/docs/) for field definitions.

Implementation: [`src/shared/models/cve.py`](../src/shared/models/cve.py).

A `CveRecord` has one or more `Container`s (CNA or ADP). Matching mainly uses each container's `AffectedProduct` entries: vendor/product names, package names, CPE strings, and version constraints.

## Why matching needs manual triage

CVE records describe upstream software by vendor names, product names, and CPE strings.
Nixpkgs identifies packages by attribute paths and derivation names.
Those naming schemes rarely align one-to-one, and version information in CVE data is often incomplete or imprecise.

The tracker [proposes links automatically](../src/shared/listeners/automatic_linkage.py), but a human must verify each match, ignore irrelevant packages, and publish an issue when Nixpkgs is actually affected.
