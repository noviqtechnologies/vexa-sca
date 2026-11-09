# Report Schema Validation Evidence

**Execution Timestamp:** 2026-11-09T14:28:21.004Z
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
| **SARIF 2.1.0** | Complete Scan | `0` | `83a555707a8b72e82bbeb21bdcaa4eac54f2c5dfd05ba4101546c8126ebbebb4` | `c3b4bb2d60938974...` | **VALID** |
| **CycloneDX 1.5** | Complete Scan | `0` | `999153bc7f606079b64f18cf5f3ef47a4a60f9b45486b63e435e5bf27d2b2e95` | `2d956c1d05c09269...` | **VALID** |
| **SPDX 2.3** | Complete Scan | `0` | `bfa78786fbff6068aa13b038b977c05feb7994596f2c7b8869a03b80cdef7298` | `239208b7ac287b3c...` | **VALID** |
| **SARIF 2.1.0** | Incomplete Scan (500/1 Source Cap) | `3` | `5ec6feaca53494483c2e197d3c35e9d7b1faa8fcd1bf90c44a0cf696b184388f` | `c3b4bb2d60938974...` | **VALID** |
| **CycloneDX 1.5** | Incomplete Scan (500/1 Source Cap) | `3` | `412b20a60d0a15cd489fd97641bd334546ec53cfb918ad3fca61c7040d450a11` | `2d956c1d05c09269...` | **VALID** |
| **SPDX 2.3** | Incomplete Scan (500/1 Source Cap) | `3` | `d79cc32955c35d39b12ad3901363a04ee1fcbd7c52d6cb54b8e9e6558bf8b1d4` | `239208b7ac287b3c...` | **VALID** |

## Reproducibility Command
```bash
npm run validate:schemas
```