# Contract boundary

`takosumi-dev-server` は Takosumi public contract の development adapter です。contract や production lifecycle authority は所有しません。

## Implemented

| Surface | Routes | Semantics |
| --- | --- | --- |
| Discovery | `/.well-known/takosumi`, `/v1/capabilities` | 実装済み capability だけを広告 |
| OIDC / OAuth | discovery, authorize, token, JWKS, UserInfo, revoke, introspect | 固定 Principal、自動承認、PKCE S256、pairwise subject |
| Workspace | `/api/v1/workspaces...` | bounded local fixture state |
| Source / Capsule | list/create/read, source sync, plan/apply | local ledger + no-infrastructure simulation |
| Interface | `/v1/interfaces...` | Ready fixture、Principal binding、60秒 invocation token |

## Intentionally absent

Stack、Resource Shape、OpenTofu runner、provider credential、real state、Output、audit、billing、backup/recovery は実装しません。未知の `/api/v1` / `/v1` route は `501 not_implemented` で失敗し、成功したふりをしません。

Production Takosumi と完全な同型が必要なテストは Takosumi 自身を起動してください。この server の seam は「公開 protocol に依存する product integration」と「実際の lifecycle authority」を分離するためのものです。
