"""Managed KB のリソースベースポリシーによる経路非依存のアクセス制限を実測する。

KB には「正規 Gateway 実行ロール以外の bedrock:Retrieve /
bedrock:GetDocumentContent を明示 Deny」するリソースベースポリシーが
アタッチされている。Gateway 側の制御 (Interceptor / AgentCore Policy) が
及ばないバイパス経路 (直接 API 呼び出し・Interceptor を持たない別 Gateway)
を rogue ロールで再現し、KB 側の Deny だけで遮断されることを確認する。

0. GetResourcePolicy: リソースベースポリシーがアタッチされている
1. 正規 GW / kb___Retrieve: 正規経路は Deny の影響を受けずヒット
2. 正規 GW / kb___AgenticRetrieveStream: 正規経路の agentic 検索も動く
3. デプロイヤ資格情報 / Retrieve 直接: 同一アカウントの管理者でも明示 Deny
4. rogue ロール / Retrieve 直接: identity ポリシーの Allow を明示 Deny が上書き
5. rogue ロール / AgenticRetrieveStream 直接: 内部の Retrieve が Deny され失敗
6. rogue ロール / GetKnowledgeBase: control-plane はリソースポリシーの対象外
7. rogue GW / kb___Retrieve: Interceptor なし Gateway の outbound を KB 側で遮断
8. AgenticRetrieveStream を Action に含むポリシーは PutResourcePolicy が拒否

Usage:
    uv run python resource-based-policy/agent/verify_resource_policy.py \\
        --kb-arn <KbArn> \\
        --gateway-url <GatewayUrl> \\
        --rogue-gateway-url <RogueGatewayUrl> \\
        --rogue-role-arn <RogueRoleArn> \\
        --access-token-a <user-a の ACCESS_TOKEN>
"""

import argparse
import json
import urllib.error
import urllib.request
from typing import Any

import boto3
from botocore.exceptions import ClientError

USER_A = "user-a@example.com"
# dept-a-plan (ACL=user-a) のカナリア語
TOKEN_A = "ヤマセミ-1101"

_COUNTERS: dict[str, int] = {}


def check(label: str, actual: bool, expected: bool = True) -> None:
    """1 ケースの結果を判定して出力する。"""
    verdict = "PASS" if actual == expected else "FAIL"
    _COUNTERS[verdict] = _COUNTERS.get(verdict, 0) + 1
    print(f"{label}: expected={expected} actual={actual} -> {verdict}")


def rpc(
    gateway_url: str,
    access_token: str,
    method: str,
    params: dict[str, Any] | None = None,
    timeout: int = 60,
) -> tuple[int, str]:
    """JSON-RPC リクエストを送信し、(ステータスコード, ボディ) を返す。"""
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    ).encode()
    req = urllib.request.Request(
        gateway_url,
        data=body,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return res.status, res.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def call_retrieve_mcp(
    gateway_url: str,
    access_token: str,
    query: str,
    user_context: dict[str, str] | None = None,
) -> tuple[int, str]:
    """kb___Retrieve を tools/call で呼び出す。"""
    arguments: dict[str, object] = {"retrievalQuery": {"text": query}}
    if user_context is not None:
        arguments["userContext"] = user_context
    return rpc(
        gateway_url,
        access_token,
        "tools/call",
        {"name": "kb___Retrieve", "arguments": arguments},
    )


def call_agentic_mcp(
    gateway_url: str, access_token: str, query: str
) -> tuple[int, str]:
    """kb___AgenticRetrieveStream を tools/call で呼び出す。"""
    return rpc(
        gateway_url,
        access_token,
        "tools/call",
        {
            "name": "kb___AgenticRetrieveStream",
            "arguments": {"messages": [{"role": "user", "content": {"text": query}}]},
        },
        timeout=300,
    )


def is_denied(status: int, body: str) -> bool:
    """エラー応答 (拒否) かを判定する。"""
    if status != 200:
        return True
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return False
    if "error" in payload:
        return True
    return bool(payload.get("result", {}).get("isError"))


def direct_retrieve(
    client: Any, kb_id: str, query: str, user_id: str
) -> tuple[bool, str]:
    """Retrieve API を直接呼び、(拒否されたか, 詳細) を返す。"""
    try:
        res = client.retrieve(
            knowledgeBaseId=kb_id,
            retrievalQuery={"text": query},
            retrievalConfiguration={
                "managedSearchConfiguration": {"numberOfResults": 10}
            },
            userContext={"userId": user_id},
        )
    except ClientError as e:
        return True, str(e)
    hits = [
        r
        for r in res.get("retrievalResults", [])
        if query in (r.get("content", {}).get("text") or "")
    ]
    return False, f"hits={len(hits)}"


def direct_agentic(
    client: Any, kb_id: str, query: str, user_id: str
) -> tuple[bool, str]:
    """AgenticRetrieveStream API を直接呼び、(拒否されたか, 詳細) を返す。

    リソースベースポリシーには bedrock:AgenticRetrieveStream を記載
    できないため、この呼び出し自体は identity ポリシーだけで認可される。
    内部の検索が KB のリソースポリシーの Deny を受けるかを、ストリームを
    最後まで読み切って観測する。
    """
    try:
        res = client.agentic_retrieve_stream(
            messages=[{"role": "user", "content": {"text": query}}],
            retrievers=[
                {
                    "description": "Department documents (business plans, notices)",
                    "configuration": {"knowledgeBase": {"knowledgeBaseId": kb_id}},
                }
            ],
            agenticRetrieveConfiguration={
                "foundationModelType": "MANAGED",
                "rerankingModelType": "MANAGED",
            },
            userContext={"userId": user_id},
        )
        events = [
            json.dumps(event, ensure_ascii=False, default=str)
            for event in res["stream"]
        ]
    except ClientError as e:
        return True, str(e)
    except Exception as e:  # ストリーム途中のエラーイベント
        return True, f"{type(e).__name__}: {e}"
    body = "\n".join(events)
    return False, f"events={len(events)} hit={TOKEN_A in body}"


def assume_role_session(role_arn: str, region: str) -> Any:
    """rogue ロールを AssumeRole し、そのロールの Session を返す。"""
    sts = boto3.client("sts", region_name=region)
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="kb-rbp-verify")[
        "Credentials"
    ]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def main() -> None:
    """9 ケースの検証を実行する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kb-arn", required=True)
    parser.add_argument("--gateway-url", required=True)
    parser.add_argument("--rogue-gateway-url", required=True)
    parser.add_argument("--rogue-role-arn", required=True)
    parser.add_argument("--access-token-a", required=True)
    args = parser.parse_args()

    kb_arn: str = args.kb_arn
    region = kb_arn.split(":")[3]
    kb_id = kb_arn.rsplit("/", 1)[-1]
    at: str = args.access_token_a

    agent_ctl = boto3.client("bedrock-agent", region_name=region)

    print("=== 0. GetResourcePolicy: リソースベースポリシーの存在 ===")
    policy_doc = ""
    try:
        res = agent_ctl.get_resource_policy(resourceArn=kb_arn)
        policy_doc = res["policy"]
        print(f"  policy: {policy_doc}")
    except ClientError as e:
        print(f"  GetResourcePolicy failed: {e}")
    check("ポリシーがアタッチされている", "DenyRetrieveExceptGatewayRole" in policy_doc)
    print()

    print("=== 1. 正規 GW / kb___Retrieve: 正規経路は Deny の影響を受けない ===")
    status, body = call_retrieve_mcp(args.gateway_url, at, TOKEN_A)
    check("A 部門文書がヒット", status == 200 and TOKEN_A in body)
    print()

    print("=== 2. 正規 GW / kb___AgenticRetrieveStream: agentic 検索も動く ===")
    status, body = call_agentic_mcp(
        args.gateway_url, at, "A部門の事業計画の計画管理コードは?"
    )
    check(
        "呼び出しが成功し A 部門文書に到達",
        status == 200 and TOKEN_A in body and not is_denied(status, body),
    )
    print()

    print("=== 3. デプロイヤ資格情報 / Retrieve 直接: 管理者でも明示 Deny ===")
    deployer_rt = boto3.client("bedrock-agent-runtime", region_name=region)
    denied, detail = direct_retrieve(deployer_rt, kb_id, TOKEN_A, USER_A)
    print(f"  detail: {detail[:300]}")
    check("拒否される", denied)
    check("明示 Deny (resource-based policy) が理由", "resource-based policy" in detail)
    print()

    rogue_session = assume_role_session(args.rogue_role_arn, region)

    print("=== 4. rogue ロール / Retrieve 直接: identity の Allow を Deny が上書き ===")
    rogue_rt = rogue_session.client("bedrock-agent-runtime")
    denied, detail = direct_retrieve(rogue_rt, kb_id, TOKEN_A, USER_A)
    print(f"  detail: {detail[:300]}")
    check("拒否される", denied)
    check("明示 Deny (resource-based policy) が理由", "resource-based policy" in detail)
    print()

    print("=== 5. rogue ロール / AgenticRetrieveStream 直接: 内部検索への効き方 ===")
    # AgenticRetrieveStream はリソースポリシーに記載できないが、内部検索が
    # 呼び出し元プリンシパルの bedrock:Retrieve を KB 単位で認可するため、
    # リソースポリシーの明示 Deny が dependencyFailedException として届く
    # (2026 年 8 月の実測)。
    denied, detail = direct_agentic(rogue_rt, kb_id, TOKEN_A, USER_A)
    print(f"  detail: {detail[:300]}")
    check("拒否される (内部の Retrieve が Deny される)", denied)
    check("明示 Deny (resource-based policy) が理由", "resource-based policy" in detail)
    print()

    print("=== 6. rogue ロール / GetKnowledgeBase: control-plane は対象外 ===")
    rogue_ctl = rogue_session.client("bedrock-agent")
    try:
        res = rogue_ctl.get_knowledge_base(knowledgeBaseId=kb_id)
        ok = res["knowledgeBase"]["knowledgeBaseId"] == kb_id
    except ClientError as e:
        ok = False
        print(f"  GetKnowledgeBase failed: {e}")
    check("成功する (リソースポリシーでは制御できない)", ok)
    print()

    print("=== 7. rogue GW / kb___Retrieve: KB 側の Deny で遮断 ===")
    status, body = call_retrieve_mcp(
        args.rogue_gateway_url, at, TOKEN_A, {"userId": USER_A}
    )
    print(f"  status={status} body={body[:300]}")
    check("拒否される", is_denied(status, body))
    check("A 部門文書は返らない", TOKEN_A not in body)
    print()

    print("=== 8. AgenticRetrieveStream を Action に含むポリシーは付与不可 ===")
    invalid_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AgenticNotSupported",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": ["bedrock:AgenticRetrieveStream"],
                    "Resource": kb_arn,
                }
            ],
        }
    )
    rejected = False
    detail = ""
    try:
        agent_ctl.put_resource_policy(resourceArn=kb_arn, policy=invalid_policy)
    except ClientError as e:
        rejected = True
        detail = str(e)
    print(f"  detail: {detail[:300]}")
    if not rejected and policy_doc:
        # 予期に反して置き換わってしまった場合は元のポリシーを復元する
        agent_ctl.put_resource_policy(resourceArn=kb_arn, policy=policy_doc)
        print("  WARNING: put が成功したため元のポリシーを復元した")
    check("バリデーションで拒否される", rejected)
    print()

    print(f"=== pass={_COUNTERS.get('PASS', 0)} fail={_COUNTERS.get('FAIL', 0)} ===")


if __name__ == "__main__":
    main()
