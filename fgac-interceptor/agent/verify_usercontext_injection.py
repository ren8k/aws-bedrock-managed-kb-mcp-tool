"""Interceptor の userContext 注入と詐称防止を直接呼び出しで確認する。

Gateway の MCP エンドポイントに JSON-RPC の tools/call を直接送り、
以下の 3 ケースの挙動を実測する。

1. userContext なし: Interceptor が userInfo で解決した email を注入し、
   本人の ACL 許可文書がヒットする
2. userContext 詐称: 他人の userId を明示指定しても Interceptor が
   上書きし、他人の文書は返らない
3. 無効なアクセストークン: Gateway の authorizer が 401 で拒否する

Usage:
    uv run python fgac-interceptor/agent/verify_usercontext_injection.py \
        --gateway-url <GatewayUrl> \
        --access-token-a <user-a の ACCESS_TOKEN>
"""

import argparse
import json
import urllib.error
import urllib.request


def call_tool(
    gateway_url: str,
    access_token: str,
    query: str,
    user_context: dict[str, str] | None = None,
) -> tuple[int, str]:
    """tools/call を直接送信し、(ステータスコード, ボディ先頭) を返す。"""
    arguments: dict[str, object] = {"retrievalQuery": {"text": query}}
    if user_context is not None:
        arguments["userContext"] = user_context
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "kb___Retrieve", "arguments": arguments},
        }
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
            return res.status, res.read().decode()[:600]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:600]


def main() -> None:
    """3 ケースの検証を実行する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-url", required=True)
    parser.add_argument("--access-token-a", required=True)
    args = parser.parse_args()

    print("=== 1. userContext なし (user-a AT): A 部門文書ヒットを期待 ===")
    status, body = call_tool(args.gateway_url, args.access_token_a, "ヤマセミ-1101")
    print(f"status={status} hit={'ヤマセミ-1101' in body}\n{body[:200]}\n")

    print(
        "=== 2. userContext 詐称 (user-a AT + userId=user-b): B 部門文書 0 件を期待 ==="
    )
    status, body = call_tool(
        args.gateway_url,
        args.access_token_a,
        "クマタカ-2202",
        user_context={"userId": "user-b@example.com"},
    )
    print(f"status={status} b_doc_leaked={'クマタカ-2202' in body}\n{body[:200]}\n")

    print("=== 3. 無効なアクセストークン: 401 を期待 ===")
    status, body = call_tool(args.gateway_url, "invalid.token.value", "ヤマセミ-1101")
    print(f"status={status}\n{body[:200]}")


if __name__ == "__main__":
    main()
