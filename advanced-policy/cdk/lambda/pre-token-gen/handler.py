"""Cognito Pre Token Generation (V2_0) trigger.

アクセストークンに email クレームを追加する。これにより、

- Gateway の REQUEST Interceptor は検証済みトークンのデコードだけで
  email を取得でき、userInfo / GetUser の外部呼び出しが不要になる
- AgentCore Policy (Cedar) が principal tag "email" として JWT の email を
  参照でき、tools/call 引数の userContext.userId と照合できる

email 属性を持たないユーザーにはクレームを追加しない。その場合、
Interceptor は 403 で拒否し、Policy も hasTag("email") を満たさないため
deny となる (fail-closed)。

V2_0 イベントの accessTokenGeneration.claimsToAddOrOverride は
Cognito の ESSENTIALS 以上の feature plan が必要。
"""

import json
from typing import Any


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Pre Token Generation V2_0 エントリポイント。

    Args:
        event: Pre Token Generation V2_0 のイベント。
        context: Lambda コンテキスト。

    Returns:
        claimsAndScopeOverrideDetails を設定したイベント。
    """
    email = event.get("request", {}).get("userAttributes", {}).get("email")
    if isinstance(email, str) and email:
        event["response"]["claimsAndScopeOverrideDetails"] = {
            "accessTokenGeneration": {"claimsToAddOrOverride": {"email": email}}
        }
    print(
        json.dumps(
            {
                "trigger_source": event.get("triggerSource"),
                "email_claim_added": bool(email),
            }
        )
    )
    return event
