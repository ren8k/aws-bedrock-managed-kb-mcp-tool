"""AgentCore Gateway REQUEST interceptor.

OAuth 2.0 の意味論に沿い、クライアントが送るのは Authorization ヘッダーの
アクセストークン 1 つだけとする。email はアクセストークンから解決し、
tools/call の arguments.userContext に強制設定する。

email の解決はトークンのスコープに応じて 2 段構えとする。まず OIDC 標準の
userInfo エンドポイントを試し (openid スコープのトークン、例: Hosted UI の
3LO)、openid スコープがない場合は Cognito の GetUser API にフォールバック
する (aws.cognito.signin.user.admin スコープのトークン、例:
USER_PASSWORD_AUTH)。Cognito の userInfo は openid スコープを要求し、
USER_PASSWORD_AUTH のトークンには openid が含まれないため、単一の解決先
ではどちらかのトークンを受けられない。

いずれの解決先でも、email の出所がアクセストークン自身の権限で取得した
情報になるため、認証された主体と userContext の主体は乖離しない (ID
トークンを別ヘッダーで受け取る方式で必要だった sub 一致検証は不要)。

アクセストークンの署名・有効期限・client_id は Gateway の JWT authorizer
が検証済みのため、この Lambda では検証しない。解決結果は実行環境の
プロセス内キャッシュ (sub -> email、TTL 付き) で再利用する。実行環境の
再利用に相乗りする確率的キャッシュであり、ミス時は解決し直すだけなので
正確性には影響しない。

Environment variables:
    USERINFO_URL: Cognito ドメインの userInfo エンドポイント URL。
"""

import base64
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

import boto3

USERINFO_URL = os.environ["USERINFO_URL"]

_cognito_idp = boto3.client("cognito-idp")

_EMAIL_CACHE: dict[str, tuple[str, float]] = {}
_CACHE_TTL_SECONDS = 300.0


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """REQUEST interceptor エントリポイント。

    Args:
        event: interceptorInputVersion 1.0 のペイロード。
        context: Lambda コンテキスト。

    Returns:
        transformedGatewayRequest を含む interceptor 出力。email を解決
        できない場合は transformedGatewayResponse (403) を返す。
    """
    mcp = event.get("mcp", {})
    gateway_request = mcp.get("gatewayRequest", {})
    body = gateway_request.get("body") or {}

    if not (isinstance(body, dict) and body.get("method") == "tools/call"):
        return _pass_through(body)

    headers = gateway_request.get("headers") or {}
    try:
        email = _resolve_email(headers)
    except EmailResolutionError as e:
        print(json.dumps({"reject_reason": str(e)}))
        return _error_response(str(e), body)

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


class EmailResolutionError(Exception):
    """email の解決失敗。メッセージはクライアントに返る。"""


def _resolve_email(headers: dict[str, str]) -> str:
    """アクセストークンからユーザーの email を解決する。

    キャッシュキーはアクセストークンの sub クレーム。トークン文字列
    そのものではなく sub をキーにすることで、同一ユーザーのトークン
    更新をまたいでキャッシュがヒットする。

    Args:
        headers: Gateway が渡すリクエストヘッダー (passRequestHeaders 有効時)。

    Returns:
        アクセストークンの権限で取得した email。

    Raises:
        EmailResolutionError: トークン欠落、解決先の呼び出し失敗、
            email クレーム欠落のいずれか。
    """
    token = _bearer_token(headers)
    if not token:
        raise EmailResolutionError("Missing Authorization bearer token")

    sub = _sub_from_token(token)
    if sub:
        cached = _EMAIL_CACHE.get(sub)
        if cached and cached[1] > time.time():
            return cached[0]

    if "openid" in _scopes_from_token(token):
        email = _fetch_email_from_userinfo(token)
    else:
        email = _fetch_email_from_get_user(token)
    if sub:
        _EMAIL_CACHE[sub] = (email, time.time() + _CACHE_TTL_SECONDS)
    return email


def _fetch_email_from_userinfo(token: str) -> str:
    """userInfo エンドポイントを呼び、email クレームを返す。

    openid スコープを持つトークン (Hosted UI の 3LO 等) 用。

    Args:
        token: authorizer 検証済みのアクセストークン。

    Returns:
        email クレームの値。

    Raises:
        EmailResolutionError: HTTP エラーまたは email クレーム欠落。
    """
    req = urllib.request.Request(
        USERINFO_URL, headers={"Authorization": f"Bearer {token}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            info = json.loads(res.read())
    except urllib.error.HTTPError as e:
        raise EmailResolutionError(
            f"userInfo request failed with status {e.code}"
        ) from e
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        raise EmailResolutionError("userInfo request failed") from e

    email = info.get("email")
    if not isinstance(email, str) or not email:
        raise EmailResolutionError("userInfo response has no email claim")
    return email


def _fetch_email_from_get_user(token: str) -> str:
    """Cognito GetUser API を呼び、email 属性を返す。

    aws.cognito.signin.user.admin スコープを持つトークン
    (USER_PASSWORD_AUTH 等) 用のフォールバック。

    Args:
        token: authorizer 検証済みのアクセストークン。

    Returns:
        email 属性の値。

    Raises:
        EmailResolutionError: API エラーまたは email 属性欠落。
    """
    try:
        res = _cognito_idp.get_user(AccessToken=token)
    except Exception as e:  # noqa: BLE001 - botocore の例外階層をまとめて拒否に落とす
        raise EmailResolutionError("GetUser request failed") from e
    email = next(
        (a["Value"] for a in res.get("UserAttributes", []) if a.get("Name") == "email"),
        None,
    )
    if not isinstance(email, str) or not email:
        raise EmailResolutionError("GetUser response has no email attribute")
    return email


def _decode_payload(token: str) -> dict[str, Any] | None:
    """JWT のペイロードをデコードする (署名検証なし)。

    署名・有効期限は Gateway の JWT authorizer が検証済み。ここで読む
    クレームは scope (解決先の選択) と sub (キャッシュキー) のみで、
    email の出所は常にアクセストークンの権限による取得
    (userInfo / GetUser) とする。
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, json.JSONDecodeError):
        return None
    return claims if isinstance(claims, dict) else None


def _scopes_from_token(token: str) -> set[str]:
    """アクセストークンから scope 一覧を取り出す。"""
    claims = _decode_payload(token)
    scope = claims.get("scope") if claims else None
    return set(scope.split()) if isinstance(scope, str) else set()


def _sub_from_token(token: str) -> str | None:
    """アクセストークンから sub を取り出す (キャッシュキー用)。"""
    claims = _decode_payload(token)
    sub = claims.get("sub") if claims else None
    return sub if isinstance(sub, str) else None


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
    """email 解決失敗を 403 の JSON-RPC エラーとして返す。"""
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
