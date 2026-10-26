# Report Schema Validation Evidence

**Execution Timestamp:** 2026-10-26T16:02:07.250Z
**Validator Engine:** `ajv@8.17.1` + `ajv-formats@3.0.1` + `ajv-draft-04@1.0.0`

## Pinned Specifications & Schema Digests

| Specification | Standard Version | Official Source | Pinned Schema SHA-256 |
|---|---|---|---|
| **SARIF** | 2.1.0 | [OASIS Spec](https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json) | `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e` |
| **CycloneDX** | 1.5 JSON | [CycloneDX Specification](https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.5.schema.json) | `2d956c1d05c092695457a91f3b5c57c749793c013ec224a0935807cfc8ae4480` |
| **SPDX** | 2.3 JSON | [SPDX 2.3 Specification](https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json) | `239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b` |

## Validation Test Results

| Report Type | Scenario | Exit Code | Generated File SHA-256 | Schema SHA-256 | Verdict |
|---|---|---|---|---|---|
| **SARIF 2.1.0** | Complete Scan | `0` | `97d9ec2fc61655760c66ad2d092024db5f0c7e51ef25f51a41884ff90ddb0e10` | `c3b4bb2d60938974...` | **VALID** |
| **CycloneDX 1.5** | Complete Scan | `0` | `767d65cb06d755d631aa5be42ad82e3ed2c5d00f5663920558c0426b1c467e06` | `2d956c1d05c09269...` | **VALID** |
| **SPDX 2.3** | Complete Scan | `0` | `1930d3b8a007892d3ee21f6b67dd171b7261a6cdb55e2e41440b6884fa8dc91f` | `239208b7ac287b3c...` | **VALID** |
| **SARIF 2.1.0** | Incomplete Scan (500/1 Source Cap) | `3` | `cf88a73ff67899fbeed15425ee660be76664d72deefe193982b7a8552d1d9a04` | `c3b4bb2d60938974...` | **VALID** |
| **CycloneDX 1.5** | Incomplete Scan (500/1 Source Cap) | `3` | `d5c514a7a373be2e75a4fda184c216488dc0802d624663e5c4131ebb1e5db3b6` | `2d956c1d05c09269...` | **VALID** |
| **SPDX 2.3** | Incomplete Scan (500/1 Source Cap) | `3` | `31da4b4186cc9dc408aeefa6b5afa6ae4c84a9e1484c1ab0e518ca5e91125f1f` | `239208b7ac287b3c...` | **VALID** |

## Reproducibility Command
```bash
npm run validate:schemas
```