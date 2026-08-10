# Fixtures

`TAKOSUMI_DEV_STATE_FILE` の JSON document は次の top-level array / map を持ちます。

```json
{
  "principals": [],
  "workspaces": [],
  "memberships": {},
  "sources": [],
  "capsules": [],
  "runs": [],
  "interfaces": [],
  "bindings": []
}
```

省略した field は安全な空 fixture（Principal / Workspace だけは既定値）になります。Interface と Binding は Takosumi `takosumi.dev/v1alpha1` document shape のまま記述します。product 名を key にした server-side switch は作りません。
