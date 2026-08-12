"""Gateway の tools/list を直接呼び、公開ツールのスキーマを採取する。

Agent (LLM) を介さず JSON-RPC の tools/list を送り、各ツールの
inputSchema を表示する。parameterOverrides で visible にした
userContext がスキーマに現れていることの確認に使う。

Usage:
    uv run python advanced-policy/agent/list_gateway_tools.py \
        --gateway-url <GatewayUrl> \
        --access-token <ACCESS_TOKEN> \
        [--raw]
"""

import argparse
import json
import urllib.request
from typing import Any


def list_tools(gateway_url: str, access_token: str) -> list[dict[str, Any]]:
    """tools/list を送信し、ツール定義の配列を返す。

    Args:
        gateway_url: Gateway の MCP エンドポイント。
        access_token: inbound 認証用のアクセストークン。

    Returns:
        tools 配列 (name / description / inputSchema を含む)。
    """
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
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
    with urllib.request.urlopen(req, timeout=30) as res:
        payload = json.loads(res.read())
    tools: list[dict[str, Any]] = payload["result"]["tools"]
    return tools


def summarize(tool: dict[str, Any]) -> str:
    """ツール 1 件のスキーマ要約 (引数名と userContext の有無) を返す。"""
    schema = tool.get("inputSchema", {})
    props = schema.get("properties", {})
    required = schema.get("required", [])
    lines = [f"tool: {tool['name']}"]
    for name, prop in props.items():
        req_mark = " (required)" if name in required else ""
        lines.append(f"  - {name}: {prop.get('type', '?')}{req_mark}")
    has_uc = "userContext" in props
    lines.append(f"  userContext in schema: {has_uc}")
    return "\n".join(lines)


def main() -> None:
    """tools/list を実行し、要約または生 JSON を表示する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-url", required=True)
    parser.add_argument("--access-token", required=True)
    parser.add_argument(
        "--raw", action="store_true", help="生の tools/list レスポンスを表示する"
    )
    args = parser.parse_args()

    tools = list_tools(args.gateway_url, args.access_token)
    if args.raw:
        print(json.dumps({"tools": tools}, ensure_ascii=False, indent=2))
        return
    for tool in tools:
        print(summarize(tool))
        print()


if __name__ == "__main__":
    main()
