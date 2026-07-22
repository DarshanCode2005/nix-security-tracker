# Design documents

Design notes for how the tracker matches CVEs to Nixpkgs packages and related decisions.

## Why matching needs manual triage

CVE records describe upstream software by vendor names, product names, and CPE strings.
Nixpkgs identifies packages by attribute paths and derivation names.
Those naming schemes rarely align one-to-one, and version information in CVE data is often incomplete or imprecise.

The tracker [proposes links automatically](../README.md#diagram-to-implementation-map), but a human must verify each match, ignore irrelevant packages, and publish an issue when Nixpkgs is actually affected.

## Documents

- [Record linkage](./01_linkage.md): High-level goal of matching CVE records to derivations.
- [CPE-based linkage](./02_cpe-based_linkage.md): Matching when CPE strings are available.
