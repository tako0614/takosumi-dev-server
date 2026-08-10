# takosumi-dev-server

Takosumi の公開 wire contract をローカル開発で再現する、product-neutral な開発サーバーです。Takos 専用ではありません。Takosumi に接続して動く Capsule、Web application、mobile client、service を、production control plane なしで開発・結合テストするために使います。

この server が提供するもの:

- OIDC discovery、OAuth 2.0 Authorization Code + PKCE、JWKS、token / refresh token、UserInfo、revoke、introspect
- 開発用 Principal と Workspace
- Workspace / Source / Capsule の fixture ledger
- Source sync、plan、apply の副作用を持たない simulation
- canonical Interface / InterfaceBinding の discovery と短命な invocation token
- JSON fixture の読み込みと、指定時だけ行うローカル persistence

提供しないもの:

- OpenTofu execution、provider credential、production Resource lifecycle
- audit / billing / recovery evidence
- Takosumi OSS や Takosumi Cloud の代替

そのため discovery は `stacks=false`、`opentofu_runner=false`、`interfaces=true` を返します。simulation route が成功しても infrastructure が作られたことは意味しません。

## Start

```bash
bun install
bun run dev
```

既定では `http://127.0.0.1:8792` の loopback だけで待ち受けます。

```text
OIDC issuer:    http://127.0.0.1:8792
API base:       http://127.0.0.1:8792/api/v1
bootstrap token: takosumi-dev-token
principal:      developer@local.test
Workspace:      ws_local
```

OAuth authorize endpoint は、loopback redirect URI に限って固定 Principal を自動承認します。PKCE S256 は必須です。秘密を持たない public client を各 product がそのまま使えます。

Takos の local process と組み合わせる例:

```bash
TAKOSUMI_ACCOUNTS_URL=http://127.0.0.1:8792 \
OIDC_ISSUER_URL=http://127.0.0.1:8792 \
OIDC_CLIENT_ID=takos-local \
OIDC_REDIRECT_URI=http://127.0.0.1:8787/auth/oidc/callback \
bun run dev
```

server-to-server fixture mutationでは bootstrap token を使えます。

```bash
curl -H 'Authorization: Bearer takosumi-dev-token' \
  http://127.0.0.1:8792/api/v1/workspaces
```

## Fixture persistence

通常は process 終了時に state を捨てます。明示した場合だけ JSON を読み書きします。

```bash
TAKOSUMI_DEV_STATE_FILE=.takosumi-dev-server/state.json bun run dev
```

fixture shape は [docs/fixtures.md](docs/fixtures.md) を参照してください。product 固有フィールドや分岐は server 本体へ追加せず、公開 contract の fixture として表現します。

## Network safety

既定は loopback bind、loopback OAuth redirect、loopback CORS のみです。LAN や
container networkに公開する場合は`TAKOSUMI_DEV_ALLOW_NON_LOOPBACK=1`、32文字以上の
explicit `TAKOSUMI_DEV_TOKEN`、exact allowlistを明示してください。このtoken issuerを
internetやproductionに公開しないでください。

## Contract ownership

Takosumi の contract は `takosumi` repo が正本です。この repo は development adapter であり contract owner ではありません。実装範囲と意図的な差分は [docs/contract-boundary.md](docs/contract-boundary.md) に記録します。
