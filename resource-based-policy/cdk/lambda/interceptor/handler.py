"""AgentCore Gateway REQUEST interceptor (email クレーム版)。

ベース構成 (cdk/lambda/interceptor/handler.py) では、アクセストークンに
email クレームが含まれないため、userInfo / GetUser の外部呼び出しで email
を解決していた。本構成では Cognito の Pre Token Generation トリガーが
email をアクセストークンのクレームに追加するため、authorizer 検証済み
トークンのデコードだけで email を取得できる (外部呼び出し・キャッシュ不要)。

クレームの正しさは Gateway の JWT authorizer による署名検証が保証する。
email クレームを持たないトークンは 403 で拒否する (fail-closed)。

注入後の tools/call は AgentCore Policy (Cedar) が評価し、
arguments.userContext.userId と JWT の email クレームの一致を検証する。
Interceptor (注入) と Policy (検証) の 2 レイヤーで多層防御を構成する。
"""

import base64
import json
from typing import Any


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """REQUEST interceptor エントリポイント。

    Args:
        event: interceptorInputVersion 1.0 のペイロード。
        context: Lambda コンテキスト。

    Returns:
        transformedGatewayRequest を含む interceptor 出力。email クレームが
        ない場合は transformedGatewayResponse (403) を返す。
    """
    mcp = event.get("mcp", {})
    gateway_request = mcp.get("gatewayRequest", {})
    body = gateway_request.get("body") or {}

    if not (isinstance(body, dict) and body.get("method") == "tools/call"):
        return _pass_through(body)

    headers = gateway_request.get("headers") or {}
    token = _bearer_token(headers)
    if not token:
        return _error_response("Missing Authorization bearer token", body)
    email = _email_from_token(token)
    if not email:
        print(json.dumps({"reject_reason": "access token has no email claim"}))
        return _error_response("Access token has no email claim", body)

    params = body.setdefault("params", {})
    args = params.setdefault("arguments", {})
    original = args.get("userContext")
    args["userContext"] = {"userId": email}
    print(
        json.dumps(
            {
                "injected_userId": email,
                "client_supplied_userContext": original,
                "tool": params.get("name"),
            }
        )
    )
    return _pass_through(body)


def _email_from_token(token: str) -> str | None:
    """検証済みアクセストークンから email クレームを取り出す。

    署名・有効期限は Gateway の JWT authorizer が検証済みのため、
    ここではデコードのみを行う。

    Args:
        token: authorizer 検証済みのアクセストークン。

    Returns:
        email クレームの値。欠落時は None。
    """
    claims = _decode_payload(token)
    email = claims.get("email") if claims else None
    return email if isinstance(email, str) and email else None


def _decode_payload(token: str) -> dict[str, Any] | None:
    """JWT のペイロードをデコードする (署名検証なし)。"""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, json.JSONDecodeError):
        return None
    return claims if isinstance(claims, dict) else None


def _bearer_token(headers: dict[str, str]) -> str | None:
    """Authorization ヘッダーから bearer トークンを取り出す。"""
    auth = next((v for k, v in headers.items() if k.lower() == "authorization"), None)
    if not auth:
        return None
    return auth.split()[-1]


def _pass_through(body: dict[str, Any]) -> dict[str, Any]:
    """リクエストボディをそのまま (または書き換え済みで) 通す。"""
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {"transformedGatewayRequest": {"body": body}},
    }


def _error_response(message: str, body: dict[str, Any]) -> dict[str, Any]:
    """拒否理由を 403 の JSON-RPC エラーとして返す。"""
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayResponse": {
                "statusCode": 403,
                "headers": {"Content-Type": "application/json"},
                "body": {
                    "jsonrpc": "2.0",
                    "id": body.get("id"),
                    "error": {"code": -32000, "message": message},
                },
            }
        },
    }
