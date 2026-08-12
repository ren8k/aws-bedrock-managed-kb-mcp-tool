"""Interceptor (注入) と AgentCore Policy (検証) の多層防御を実測する。

2 つの Gateway に JSON-RPC を直接送り、以下の 8 ケースを確認する。
メイン Gateway は Interceptor + Policy (ENFORCE)、検証用 Gateway は
Policy (ENFORCE) のみで、両者は同一の Policy Engine を共有する。

0. アクセストークンに email クレームが存在する (Pre Token Generation)
1. メイン GW / userContext なし: Interceptor 注入 + Policy 通過でヒット
2. メイン GW / userContext 詐称: Interceptor が上書きし他人の文書は返らない
3. メイン GW / tools/list: 条件付き permit がツールを隠さない
4. 検証用 GW / 本人の userContext: Policy 単体で通過しヒット
5. 検証用 GW / userContext 詐称: Policy が deny
6. 検証用 GW / userContext なし: Policy が deny
7. 検証用 GW / tools/list: 可視性の実測 (記録用)

Usage:
    uv run python advanced-policy/agent/verify_policy_enforcement.py \\
        --gateway-url <GatewayUrl> \\
        --noint-gateway-url <NoInterceptorGatewayUrl> \\
        --access-token-a <user-a の ACCESS_TOKEN>
"""

import argparse
import base64
import json
import urllib.error
import urllib.request
from typing import Any

USER_A = "user-a@example.com"
USER_B = "user-b@example.com"
# dept-a-plan (ACL=user-a) / dept-b-plan (ACL=user-b) のカナリア語
TOKEN_A = "ヤマセミ-1101"
TOKEN_B = "クマタカ-2202"

_COUNTERS: dict[str, int] = {}


def check(label: str, actual: bool, expected: bool = True) -> None:
    """1 ケースの結果を判定して出力する。"""
    verdict = "PASS" if actual == expected else "FAIL"
    _COUNTERS[verdict] = _COUNTERS.get(verdict, 0) + 1
    print(f"{label}: expected={expected} actual={actual} -> {verdict}")


def decode_claims(token: str) -> dict[str, Any]:
    """アクセストークンのペイロードをデコードする (署名検証なし)。"""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    return claims if isinstance(claims, dict) else {}


def rpc(
    gateway_url: str,
    access_token: str,
    method: str,
    params: dict[str, Any] | None = None,
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
        with urllib.request.urlopen(req, timeout=60) as res:
            return res.status, res.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def call_retrieve(
    gateway_url: str,
    access_token: str,
    query: str,
    user_context: dict[str, str] | None = None,
) -> tuple[int, str]:
    """kb___Retrieve を呼び出す。"""
    arguments: dict[str, object] = {"retrievalQuery": {"text": query}}
    if user_context is not None:
        arguments["userContext"] = user_context
    return rpc(
        gateway_url,
        access_token,
        "tools/call",
        {"name": "kb___Retrieve", "arguments": arguments},
    )


def list_tool_names(gateway_url: str, access_token: str) -> list[str]:
    """tools/list を呼び、ツール名の一覧を返す。"""
    status, body = rpc(gateway_url, access_token, "tools/list")
    if status != 200:
        print(f"  tools/list status={status} body={body[:200]}")
        return []
    tools = json.loads(body).get("result", {}).get("tools", [])
    return [t["name"] for t in tools]


def is_denied(status: int, body: str) -> bool:
    """Policy による拒否 (エラー応答) かを判定する。"""
    if status != 200:
        return True
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return False
    if "error" in payload:
        return True
    return bool(payload.get("result", {}).get("isError"))


def main() -> None:
    """8 ケースの検証を実行する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-url", required=True)
    parser.add_argument("--noint-gateway-url", required=True)
    parser.add_argument("--access-token-a", required=True)
    args = parser.parse_args()
    gw, noint, at = args.gateway_url, args.noint_gateway_url, args.access_token_a

    print("=== 0. アクセストークンの email クレーム (Pre Token Generation) ===")
    claims = decode_claims(at)
    check("email クレームが user-a の email", claims.get("email") == USER_A)
    print()

    print("=== 1. メイン GW / userContext なし: 注入 + Policy 通過 ===")
    status, body = call_retrieve(gw, at, TOKEN_A)
    check("A 部門文書がヒット", status == 200 and TOKEN_A in body)
    print()

    print("=== 2. メイン GW / userContext 詐称 (user-b): 上書きされ漏洩しない ===")
    status, body = call_retrieve(gw, at, TOKEN_B, {"userId": USER_B})
    check(
        "呼び出し自体は成功 (Policy 通過)",
        status == 200 and not is_denied(status, body),
    )
    check("B 部門文書は返らない", TOKEN_B not in body)
    print()

    print("=== 3. メイン GW / tools/list: 条件付き permit がツールを隠さない ===")
    names = list_tool_names(gw, at)
    print(f"  tools: {names}")
    check("kb___Retrieve が見える", "kb___Retrieve" in names)
    check("kb___AgenticRetrieveStream が見える", "kb___AgenticRetrieveStream" in names)
    print()

    print("=== 4. 検証用 GW / 本人の userContext: Policy 単体で通過 ===")
    status, body = call_retrieve(noint, at, TOKEN_A, {"userId": USER_A})
    check("A 部門文書がヒット", status == 200 and TOKEN_A in body)
    print()

    print("=== 5. 検証用 GW / userContext 詐称 (user-b): Policy が deny ===")
    status, body = call_retrieve(noint, at, TOKEN_B, {"userId": USER_B})
    check("拒否される", is_denied(status, body))
    check("B 部門文書は返らない", TOKEN_B not in body)
    print(f"  deny 応答: status={status} body={body[:300]}")
    print()

    print("=== 6. 検証用 GW / userContext なし: Policy が deny ===")
    status, body = call_retrieve(noint, at, TOKEN_A)
    check("拒否される", is_denied(status, body))
    print(f"  deny 応答: status={status} body={body[:300]}")
    print()

    print("=== 7. 検証用 GW / tools/list: 可視性の実測 ===")
    names = list_tool_names(noint, at)
    print(f"  tools: {names}")
    check("kb___Retrieve が見える", "kb___Retrieve" in names)
    print()

    print(f"=== pass={_COUNTERS.get('PASS', 0)} fail={_COUNTERS.get('FAIL', 0)} ===")


if __name__ == "__main__":
    main()
