# Report Schema Validation Evidence

**Execution Timestamp:** 2026-11-07T07:59:35.149Z
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
| **SARIF 2.1.0** | Complete Scan | `0` | `3f31334183af614802d0abaf5835408f3bbc14e2970fb8a25fdffefdd4e9f447` | `c3b4bb2d60938974...` | **VALID** |
| **CycloneDX 1.5** | Complete Scan | `0` | `7c33c6e42b2311cc74487e15842bfbda697a5c0e266d8d9cc8369c13d0bee591` | `2d956c1d05c09269...` | **VALID** |
| **SPDX 2.3** | Complete Scan | `0` | `f28a119002ec806f6647b1047b11b91ca46797e382c9b95cf550ce82f9edd2f3` | `239208b7ac287b3c...` | **VALID** |
| **SARIF 2.1.0** | Incomplete Scan (500/1 Source Cap) | `3` | `fd9b1f757cc1d367f1e2df066863b03d506ccfdedaaf9c733ba8b2df0d481f86` | `c3b4bb2d60938974...` | **VALID** |
| **CycloneDX 1.5** | Incomplete Scan (500/1 Source Cap) | `3` | `ce1a39e382a62e2812fd1b207471678e8a6f169fcd290076bc0d211c1ec3d437` | `2d956c1d05c09269...` | **VALID** |
| **SPDX 2.3** | Incomplete Scan (500/1 Source Cap) | `3` | `6061b4d95d1f752e5db509b661519109a501336236db4020f6f0a677320dba6f` | `239208b7ac287b3c...` | **VALID** |

## Reproducibility Command
```bash
npm run validate:schemas
```