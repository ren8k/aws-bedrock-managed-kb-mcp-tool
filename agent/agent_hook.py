"""方式 2: Agent アプリ側のフックで userContext を注入する構成の Agent。

Strands の BeforeToolCallEvent フックで、LLM が生成したツール引数の
userContext を認証済みユーザーの email に強制上書きする。Gateway 側に
Interceptor がない構成では、このフックが唯一の注入層になる。

email は Interceptor 方式と同じ原理で、アクセストークン自身の権限で
解決する (Cognito GetUser API)。email の出所がアクセストークンの権限で
取得した情報になるため、Gateway 認証と userContext の主体が乖離しない。
Cognito のアクセストークンには email クレームが含まれないため、トークン
のデコードでは email は得られない点に注意。

GetUser は aws.cognito.signin.user.admin スコープを要求する
(USER_PASSWORD_AUTH のトークンには常に付く)。Hosted UI の 3LO で
スコープを絞ったトークンを使う構成では、GetUser の代わりに Cognito
ドメインの userInfo エンドポイント (openid スコープで動作) を使う。

Usage:
    uv run python agent/agent_hook.py \
        --gateway-url https://<gateway>.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp \
        --access-token <ACCESS_TOKEN> \
        --prompt "A部門の事業計画に記載されている計画管理コードは何ですか？"
"""

import argparse
from typing import Any

import boto3
from mcp.client.streamable_http import streamablehttp_client
from strands import Agent
from strands.hooks import BeforeToolCallEvent, HookProvider, HookRegistry
from strands.tools.mcp import MCPClient

MODEL_ID = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"

SYSTEM_PROMPT = (
    "あなたは社内文書検索アシスタントです。"
    "ツールで知識ベースを検索して質問に答えてください。"
    "検索結果に情報がない場合は「見つかりませんでした」と答えてください。"
)


def email_from_access_token(access_token: str, region: str = "us-east-1") -> str:
    """アクセストークン自身の権限で本人の email を解決する (GetUser)。

    Args:
        access_token: Gateway 認証にも使うアクセストークン。
        region: Cognito user pool のリージョン。

    Returns:
        email 属性の値。

    Raises:
        KeyError: email 属性が存在しない場合。
    """
    client = boto3.client("cognito-idp", region_name=region)
    res = client.get_user(AccessToken=access_token)
    attrs = {a["Name"]: a["Value"] for a in res["UserAttributes"]}
    return str(attrs["email"])


class InjectUserContext(HookProvider):
    """KB 系ツールの userContext を認証済みユーザーの email に強制上書きするフック。

    LLM が userContext を指定しなくても注入し、LLM が他人の値を
    指定しても上書きする。信頼境界はアプリ側 (このフック) にある。
    """

    def __init__(
        self,
        user_id: str,
        tool_suffixes: tuple[str, ...] = ("___Retrieve", "___AgenticRetrieveStream"),
    ) -> None:
        """Args:
        user_id: userContext.userId に設定する検証済みの email。
        tool_suffixes: 上書き対象とするツール名のサフィックス。
        """
        self._user_id = user_id
        self._suffixes = tool_suffixes

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(BeforeToolCallEvent, self._inject)

    def _inject(self, event: BeforeToolCallEvent) -> None:
        if event.tool_use["name"].endswith(self._suffixes):
            # LLM が何を指定していても認証済みユーザーで上書きする
            event.tool_use["input"]["userContext"] = {"userId": self._user_id}


def run_agent(gateway_url: str, access_token: str, prompt: str) -> str:
    """認証済みユーザーとして Agent を実行する。

    Args:
        gateway_url: Gateway の MCP エンドポイント。
        access_token: inbound 認証用の Cognito アクセストークン。
        prompt: エージェントへの指示。

    Returns:
        回答テキスト。
    """
    user_id = email_from_access_token(access_token)
    mcp_client = MCPClient(
        lambda: streamablehttp_client(
            gateway_url, headers={"Authorization": f"Bearer {access_token}"}
        )
    )
    with mcp_client:
        # フックが注入する userContext は visible なツールにしか渡せない。
        # 対象ターゲットのツールのみに限定する。
        tools = [
            t
            for t in mcp_client.list_tools_sync()
            if t.tool_name.endswith(("___Retrieve", "___AgenticRetrieveStream"))
        ]
        print(f"tools: {[t.tool_name for t in tools]}")
        agent = Agent(
            model=MODEL_ID,
            tools=tools,
            hooks=[InjectUserContext(user_id)],
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
