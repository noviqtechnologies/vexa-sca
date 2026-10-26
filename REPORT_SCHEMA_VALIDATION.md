# Report Schema Validation Evidence

**Execution Timestamp:** 2026-10-26T14:52:02.433Z
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
| **SARIF 2.1.0** | Complete Scan | `0` | `026d982487730603d98f6415585d66f8c15d9649b15a3494eb0ab21390cfae70` | `c3b4bb2d60938974...` | **VALID** |
| **CycloneDX 1.5** | Complete Scan | `0` | `a32aafe3b3472f243db21cd1aa6498d57361dc44378c99aa947c10c4a47a3c43` | `2d956c1d05c09269...` | **VALID** |
| **SPDX 2.3** | Complete Scan | `0` | `a9cfca15d8aa0f1b6c1b4dc9b420d806cb67899eb54ac91c6d4dac7cee30ec58` | `239208b7ac287b3c...` | **VALID** |
| **SARIF 2.1.0** | Incomplete Scan (500/1 Source Cap) | `3` | `38a841d169b4e119d0ffe81720b37279008b76a6886caef649e7008b65108d62` | `c3b4bb2d60938974...` | **VALID** |
| **CycloneDX 1.5** | Incomplete Scan (500/1 Source Cap) | `3` | `cc5a4e25dc10ec290ec00acde52b1a4b8c0d6176a2481912b1b9b3e04713496f` | `2d956c1d05c09269...` | **VALID** |
| **SPDX 2.3** | Incomplete Scan (500/1 Source Cap) | `3` | `e03a7ea330d92db6ab685c23f92e1a49de172967ae5f15d62a577165a3cdf62c` | `239208b7ac287b3c...` | **VALID** |

## Reproducibility Command
```bash
npm run validate:schemas
```