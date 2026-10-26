# Report Schema Validation Evidence

**Execution Timestamp:** 2026-10-26T14:21:26.678Z
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
| **SARIF 2.1.0** | Complete Scan | `0` | `7e3c54f5bae3ac071265ba6864345691ccfea79adffd8dea0b11a2ca91b535fd` | `c3b4bb2d60938974...` | **VALID** |
| **CycloneDX 1.5** | Complete Scan | `0` | `cec910a4fcd3b5bbef39f442bc029074e1f1debe477e65d9079b28f245c7a808` | `2d956c1d05c09269...` | **VALID** |
| **SPDX 2.3** | Complete Scan | `0` | `1d2884239bf6fb852b8ba84e51f6dcfe9ad16e481c227d3dd351e77bb510e82f` | `239208b7ac287b3c...` | **VALID** |
| **SARIF 2.1.0** | Incomplete Scan (500/1 Source Cap) | `3` | `01a20321953f2844c986954a95801bd5a3bbda1de85ca61b96e28fcbb2be3418` | `c3b4bb2d60938974...` | **VALID** |
| **CycloneDX 1.5** | Incomplete Scan (500/1 Source Cap) | `3` | `273ec3fe0ed90a28d310a37462f67eccfa5b3f54890762c2b34385688652c1c3` | `2d956c1d05c09269...` | **VALID** |
| **SPDX 2.3** | Incomplete Scan (500/1 Source Cap) | `3` | `22f89c5307de1deeeea580369b1aeddf0f0eab128cd137d8783f282c3a94662c` | `239208b7ac287b3c...` | **VALID** |

## Reproducibility Command
```bash
npm run validate:schemas
```