# AgentCore Policy による userContext 注入の多層防御

ベース構成 (../fgac-interceptor) をベースに、AgentCore Policy (Cedar) を「Interceptor の注入結果を検証する」独立レイヤーとして追加した構成。評価順序が REQUEST Interceptor → Policy であることを利用し、tools/call の `userContext.userId` が JWT の email クレームと一致することを Policy Engine (ENFORCE) が検証する。

## ベース構成との差分

- Cognito の Pre Token Generation trigger (V2_0) がアクセストークンに email クレームを追加する。V2_0 のアクセストークンカスタマイズには feature plan ESSENTIALS 以上が必要 (スタックで明示)
- REQUEST Interceptor は検証済みトークンのデコードだけで email を取得する (userInfo / GetUser の外部呼び出しとキャッシュを削除)。email クレームがないトークンでの tools/call は 403 で拒否
- Policy Engine (Cedar、ENFORCE) をメイン Gateway に紐付け、`userContext.userId == principal.getTag("email")` を検証する permit ポリシーを Retrieve / AgenticRetrieveStream に定義。permit の条件を満たさない tools/call はすべて deny される
- deny を観測するための検証用 Gateway (Interceptor なし、同一 Policy Engine、Retrieve のみ) を常設。Policy 単体構成では呼び出し側が正しい userContext を送る必要があり、詐称・欠落は Policy が deny する
- データソースは docs (文書毎 ACL) の 1 本のみ、global ACL 方式は含まない (最小構成)

## 多層防御の構成

| レイヤー                          | 役割                                                                           | 失敗時の挙動             |
| --------------------------------- | ------------------------------------------------------------------------------ | ------------------------ |
| REQUEST Interceptor               | JWT の email クレームから userContext を強制注入 (correctness by construction) | email クレームなしは 403 |
| AgentCore Policy (Cedar, ENFORCE) | 注入後の userContext と JWT の email の一致を検証                              | 不一致・欠落は deny      |

テナント分離が Gateway の可変設定 1 項目 (interceptorConfigurations) に依存しなくなる。Interceptor が外れても、Policy が userContext の詐称・欠落を deny する。逆に Policy が外れても、Interceptor が正しい値を注入し続ける。

Cedar ポリシー (3 本共通の形):

```cedar
permit(
  principal is AgentCore::OAuthUser,
  action == AgentCore::Action::"kb___Retrieve",
  resource == AgentCore::Gateway::"<gateway ARN>"
) when {
  principal.hasTag("email") &&
  context has input && context.input has userContext &&
  context.input.userContext has userId &&
  context.input.userContext.userId == principal.getTag("email")
};
```

## Gateway 実行ロールに必要な Policy 関連権限 (実測)

`policyEngineConfiguration` を持つ Gateway の作成時、サービスは Gateway 実行ロールで以下の 2 つを事前チェックする (不足していると CreateGateway が access denied で失敗する。2026 年 8 月時点で公式ドキュメントに一覧はなく、エラーメッセージから特定した)。

- `bedrock-agentcore:GetPolicyEngine` (対象: Policy Engine の ARN)
- `bedrock-agentcore:AuthorizeAction` (対象: Policy Engine と Gateway の ARN。tools/call の評価)

加えて、実行時の tools/list のフィルタリングには `bedrock-agentcore:PartiallyAuthorizeActions` (対象: 同上) が必要になる。

Gateway の ARN は作成前に確定しないため、本スタックでは名前パターン `gateway/managed-kb-policy-*` でスコープしている。また CfnGateway は roleArn しか参照せず、CloudFormation はロールの DefaultPolicy の作成完了を待たないため、Gateway に Role コンストラクトへの明示的な依存 (`gateway.node.addDependency(gwRole)`) が必要。

## デプロイ

```bash
cd advanced-policy/cdk
npm install
npx cdk deploy ManagedKbPolicyStack --outputs-file outputs.json

# ingestion (デプロイ後に 1 回)
aws bedrock-agent start-ingestion-job \
  --knowledge-base-id <KbId> --data-source-id <DataSourceId>
```

Policy は Gateway Target の作成完了後に作成される (CreateGatewayTarget 時の暗黙同期でツールスキーマが Policy Engine に登録されるため。validationMode FAIL_ON_ANY_FINDINGS は未知のアクションを拒否する)。

## 検証

```bash
./advanced-policy/agent/run.sh verify-policy   # 8 ケースの一括検証
./advanced-policy/agent/run.sh tools           # メイン GW の tools/list
./advanced-policy/agent/run.sh agent "A部門の事業計画に記載されている計画管理コードは何ですか？"
./advanced-policy/agent/run.sh token b         # アクセストークンの表示
```

ユーザーは各サブコマンド末尾の引数 `a` / `b` で切り替える (既定は `a`)。

verify-policy の検証内容:

| #   | 経路      | 入力                       | 期待                                            |
| --- | --------- | -------------------------- | ----------------------------------------------- |
| 0   | -         | アクセストークンをデコード | email クレームが存在する                        |
| 1   | メイン GW | userContext なし           | Interceptor 注入 + Policy 通過でヒット          |
| 2   | メイン GW | 他人の userContext (詐称)  | deny されず上書きで通過し、他人の文書は返らない |
| 3   | メイン GW | tools/list                 | 条件付き permit がツールを隠さない              |
| 4   | 検証用 GW | 本人の userContext         | Policy 単体で通過しヒット                       |
| 5   | 検証用 GW | 他人の userContext (詐称)  | Policy が deny                                  |
| 6   | 検証用 GW | userContext なし           | Policy が deny                                  |
| 7   | 検証用 GW | tools/list                 | Retrieve が隠されず見える                       |

検証用 Gateway は deny の観測と Policy 単体構成の比較デモ用であり、本番構成はメイン Gateway (Interceptor + Policy) を推奨する。Policy 単体では tools/call の userContext を組み立てる主体が LLM に戻り、拒否ベースの防御になるため。

検証後は `npx cdk destroy ManagedKbPolicyStack` で削除できる。ベース構成と異なり S3 バケットは DESTROY + autoDeleteObjects のため、スタック削除で中身ごと削除される。
