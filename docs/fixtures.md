# Fixtures

`TAKOSUMI_DEV_STATE_FILE` の JSON document は次の top-level array / map を持ちます。

```json
{
  "principals": [],
  "workspaces": [],
  "memberships": {},
  "workspaceMembers": [],
  "sources": [],
  "capsules": [],
  "capsuleMembers": [],
  "runs": [],
  "interfaces": [],
  "bindings": []
}
```

省略した field は安全な空 fixture（Principal / Workspace だけは既定値）になります。Interface と Binding は Takosumi `takosumi.dev/v1alpha1` document shape のまま記述します。product 名を key にした server-side switch は作りません。

`memberships` の subject 一覧は legacy Workspace の参照範囲だけを表し、app 管理権限にはなりません。Workspace の `ownerUserId` は legacy app の owner になります。既存の active administrator を app member として再現するときだけ、同じ Workspace の `memberships` に加えて明示的な役割を記述します。

```json
{
  "workspaceMembers": [
    { "workspaceId": "ws_local", "accountId": "tsub_admin", "roles": ["admin"], "status": "active" }
  ]
}
```

`workspaceMembers` の `roles` は `owner` / `admin` / `member` / `viewer`、`status` は `active` / `invited` です。active の `owner` / `admin` だけが legacy app の member になり、member / viewer / invited / 役割未指定の membership は管理権限を持ちません。app owner の member 一覧にも投影しません。

Workspace に依存しない fixture は Capsule の `ownerAccountId` と、`capsuleMembers` の `{ "capsuleId": "cap_example", "accountId": "tsub_member", "status": "active" }` を使います。明示的な app 記録がある Capsule では Workspace の役割を権限の代わりにしません。

`GET /api/v1/apps` は Capsule の状態を公開 app contract に変換します。disabled は `stopped` / `none`、error は `needs_attention` / `retry`、未適用（`currentStateGeneration: 0`）は `installing` / `none`、適用済みは `installed` / `view_resources` です。destroyed は一覧から除外します。fixture にない screen や実行中 lifecycle を推測しません。`GET /api/v1/usage` は `{ "usageEvents": [] }` を返します。
