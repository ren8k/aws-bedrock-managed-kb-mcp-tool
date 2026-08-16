"""メタデータフィルタリングと ACL の併用を直接 API で確認する。

本スタックの docs データソース (ACL 有効 + metadataAttributes) に対し、
userContext と filter の組み合わせでヒット状況を実測する。

前半は filter の基本動作 (equals / andAll / greaterThan、および
customer-managed KB の vectorSearchConfiguration 構文が拒否されること)。
後半は ACL と filter が独立した 2 つのゲートとして AND で効くこと
(どちらか一方が他方を上書きする優先関係ではないこと) の切り分け。

Usage:
    uv run python fgac-interceptor/agent/verify_metadata_filter.py --kb-id <KbId>
"""

import argparse
from typing import Any

import boto3
from botocore.exceptions import ClientError

USER_A = "user-a@example.com"
USER_B = "user-b@example.com"

# dept-a-plan: ACL=user-a, department=d001, year=2026
TOKEN_A = "ヤマセミ-1101"
# shared-notice: ACL=user-a/user-b, department=shared, year=2025
TOKEN_SHARED = "ハヤブサ-3303"

EQ_D001: dict[str, Any] = {"equals": {"key": "department", "value": "d001"}}
EQ_D002: dict[str, Any] = {"equals": {"key": "department", "value": "d002"}}


def hit(
    client: Any,
    kb_id: str,
    token: str,
    user_id: str | None = None,
    filter_: dict[str, Any] | None = None,
) -> bool:
    """カナリア語で検索し、結果に含まれるかを返す。"""
    search: dict[str, Any] = {"numberOfResults": 10}
    if filter_ is not None:
        search["filter"] = filter_
    kwargs: dict[str, Any] = {
        "knowledgeBaseId": kb_id,
        "retrievalQuery": {"text": token},
        "retrievalConfiguration": {"managedSearchConfiguration": search},
    }
    if user_id is not None:
        kwargs["userContext"] = {"userId": user_id}
    res = client.retrieve(**kwargs)
    return any(
        token in (r.get("content", {}).get("text") or "")
        for r in res.get("retrievalResults", [])
    )


def check(label: str, actual: bool, expected: bool, counters: dict[str, int]) -> None:
    """1 ケースの結果を判定して出力する。"""
    verdict = "PASS" if actual == expected else "FAIL"
    counters[verdict] = counters.get(verdict, 0) + 1
    print(f"{label}: expected={expected} actual={actual} -> {verdict}")


def main() -> None:
    """filter の基本動作と ACL との AND 関係を検証する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kb-id", required=True)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    client = boto3.client("bedrock-agent-runtime", region_name=args.region)
    kb = args.kb_id
    counters: dict[str, int] = {}

    print("=== filter の基本動作 (userContext は本人) ===")
    check(
        "equals department=d001 で dept-a-plan",
        hit(client, kb, TOKEN_A, USER_A, EQ_D001),
        True,
        counters,
    )
    check(
        "equals department=d002 で dept-a-plan (不一致)",
        hit(client, kb, TOKEN_A, USER_A, EQ_D002),
        False,
        counters,
    )
    check(
        "andAll (department=d001 AND year>2020) で dept-a-plan",
        hit(
            client,
            kb,
            TOKEN_A,
            USER_A,
            {"andAll": [EQ_D001, {"greaterThan": {"key": "year", "value": 2020}}]},
        ),
        True,
        counters,
    )
    check(
        "greaterThan year>2025 で shared-notice (year=2025、境界)",
        hit(
            client,
            kb,
            TOKEN_SHARED,
            USER_A,
            {"greaterThan": {"key": "year", "value": 2025}},
        ),
        False,
        counters,
    )

    print("\n=== ACL と filter の関係 (dept-a-plan: ACL=user-a, department=d001) ===")
    check(
        "ACL 許可 + filter 一致 (user-a + d001)",
        hit(client, kb, TOKEN_A, USER_A, EQ_D001),
        True,
        counters,
    )
    check(
        "ACL 許可 + filter 不一致 (user-a + d002) → ACL 優先仮説の棄却",
        hit(client, kb, TOKEN_A, USER_A, EQ_D002),
        False,
        counters,
    )
    check(
        "ACL 拒否 + filter 一致 (user-b + d001) → filter 優先仮説の棄却",
        hit(client, kb, TOKEN_A, USER_B, EQ_D001),
        False,
        counters,
    )
    check(
        "userContext なし + filter 一致 → ACL 有効 DS は fail-closed",
        hit(client, kb, TOKEN_A, None, EQ_D001),
        False,
        counters,
    )

    print("\n=== 旧構文 (customer-managed KB の vectorSearchConfiguration) ===")
    try:
        client.retrieve(
            knowledgeBaseId=kb,
            retrievalQuery={"text": TOKEN_A},
            retrievalConfiguration={"vectorSearchConfiguration": {"filter": EQ_D001}},
            userContext={"userId": USER_A},
        )
        print("vectorSearchConfiguration.filter: 受理された -> FAIL")
        counters["FAIL"] = counters.get("FAIL", 0) + 1
    except ClientError as e:
        msg = e.response["Error"]["Message"]
        rejected = "managedSearchConfiguration" in msg
        print(
            f"vectorSearchConfiguration.filter: 拒否 -> {'PASS' if rejected else 'FAIL'}"
        )
        print(f"  {msg[:160]}")
        counters["PASS" if rejected else "FAIL"] = (
            counters.get("PASS" if rejected else "FAIL", 0) + 1
        )

    print(f"\n=== pass={counters.get('PASS', 0)} fail={counters.get('FAIL', 0)} ===")


if __name__ == "__main__":
    main()
