# Report Schema Validation Evidence

**Execution Timestamp:** 2026-11-28T13:52:51.537Z
**Validator Engine:** `ajv@8.17.1` + `ajv-formats@3.0.1` + `ajv-draft-04@1.0.0`

## Pinned Specifications & Schema Digests

| Specification | Standard Version | Official Source | Pinned Schema SHA-256 |
|---|---|---|---|
| **SARIF** | 2.1.0 | [OASIS Spec](https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json) | `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e` |
| **CycloneDX** | 1.6 JSON | [CycloneDX Specification](https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json) | `18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d` |
| **SPDX** | 2.3 JSON | [SPDX 2.3 Specification](https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json) | `239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b` |

## Validation Test Results

| Report Type | Scenario | Exit Code | Generated File SHA-256 | Schema SHA-256 | Verdict |
|---|---|---|---|---|---|
| **SARIF 2.1.0** | Complete Scan | `0` | `1c4f8077871704e0402e607010de104dc779099a7da508d3ff85983be98d5768` | `c3b4bb2d60938974...` | **VALID** |
| **CycloneDX 1.6** | Complete Scan | `0` | `a7f64e59da942497f7f3cf558346276c9c1b0ccac8695b29e272c81e07964f31` | `18f57f7482593bad...` | **VALID** |
| **SPDX 2.3** | Complete Scan | `0` | `e896354f14f8a82c8d9b6b308a0749ba58796736584a7911004b7a2b42e25c67` | `239208b7ac287b3c...` | **VALID** |
| **SARIF 2.1.0** | Incomplete Scan (500/1 Source Cap) | `3` | `9df8dc8c08be92065fc2c99ec7715d996079e36120defffa649102afcb5dd225` | `c3b4bb2d60938974...` | **VALID** |
| **CycloneDX 1.6** | Incomplete Scan (500/1 Source Cap) | `3` | `30f9369d6c115064f06ecd0f28b863849404c2cf6859096cb4768c6faafda1e1` | `18f57f7482593bad...` | **VALID** |
| **SPDX 2.3** | Incomplete Scan (500/1 Source Cap) | `3` | `eed38dc00c5c7aafb2bcf4d54a464e399ae1a9f63d80ab817dbc0374298458ea` | `239208b7ac287b3c...` | **VALID** |

## Reproducibility Command
```bash
npm run validate:schemas
```