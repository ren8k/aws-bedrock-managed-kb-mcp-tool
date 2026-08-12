"""方式 1: Gateway REQUEST Interceptor で userContext を注入する構成の Agent。

クライアント側に userContext のロジックは一切ない。送るのは Authorization
ヘッダーのアクセストークン 1 つだけで、OAuth 2.0 の標準的な bearer 認証と
同じ形になる。Gateway の JWT authorizer がアクセストークンを検証し、
REQUEST interceptor が userInfo エンドポイントで email を解決して
userContext に強制設定する。

Usage:
    uv run python agent/agent_interceptor.py \
        --gateway-url https://<gateway>.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp \
        --access-token <ACCESS_TOKEN> \
        --prompt "B部門の事業計画の計画管理コードを調べてください。"
"""

import argparse

from mcp.client.streamable_http import streamablehttp_client
from strands import Agent
from strands.tools.mcp import MCPClient

MODEL_ID = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"

SYSTEM_PROMPT = (
    "あなたは社内文書検索アシスタントです。"
    "ツールで知識ベースを検索して質問に答えてください。"
    "検索結果に情報がない場合は「見つかりませんでした」と答えてください。"
)


def run_agent(gateway_url: str, access_token: str, prompt: str) -> str:
    """認証済みユーザーとして Agent を実行する。

    userContext の設定はクライアントの責務ではない。Gateway の REQUEST
    interceptor がアクセストークンから email を解決して設定するため、
    ここではアクセストークンをヘッダーに渡すだけでよい。

    Args:
        gateway_url: Gateway の MCP エンドポイント。
        access_token: inbound 認証用の Cognito アクセストークン。
        prompt: エージェントへの指示。

    Returns:
        回答テキスト。
    """
    mcp_client = MCPClient(
        lambda: streamablehttp_client(
            gateway_url, headers={"Authorization": f"Bearer {access_token}"}
        )
    )
    with mcp_client:
        tools = mcp_client.list_tools_sync()
        print(f"tools: {[t.tool_name for t in tools]}")
        agent = Agent(
            model=MODEL_ID,
            tools=tools,
            system_prompt=SYSTEM_PROMPT,
            callback_handler=None,
        )
        return str(agent(prompt))


def main() -> None:
    """コマンドライン引数で Agent を実行する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-url", required=True)
    parser.add_argument("--access-token", required=True)
    parser.add_argument("--prompt", required=True)
    args = parser.parse_args()
    print(run_agent(args.gateway_url, args.access_token, args.prompt))


if __name__ == "__main__":
    main()
