"""global ACL ファイル方式の ACL フィルタリングを直接 API で確認する。

本スタックの KB に対し、global ACL ファイルで制御した 2 文書と、
ACL エントリを持たない 1 文書について、userContext 別のヒット状況を実測する。

- finance/budget.txt (global ACL: user-a に ALLOW) -> user-a のみヒット
- hr/rules.txt (global ACL: user-b に ALLOW) -> user-b のみヒット
- no-acl/unclassified-memo.txt (ACL なし) -> 誰にもヒットしない (未取り込み)

Usage:
    uv run python fgac-interceptor/agent/verify_global_acl.py --kb-id <KbId>
"""

import argparse
from typing import Any

import boto3

CASES: list[dict[str, Any]] = [
    {
        "doc": "finance/budget.txt (global ACL: user-a)",
        "token": "トビ-8808",
        "expect": {
            "user-a@example.com": True,
            "user-b@example.com": False,
            None: False,
        },
    },
    {
        "doc": "hr/rules.txt (global ACL: user-b)",
        "token": "ノスリ-9909",
        "expect": {
            "user-a@example.com": False,
            "user-b@example.com": True,
            None: False,
        },
    },
    {
        "doc": "no-acl/unclassified-memo.txt (ACL エントリなし)",
        "token": "フクロウ-5505",
        "expect": {
            "user-a@example.com": False,
            "user-b@example.com": False,
            None: False,
        },
    },
]


def retrieve_hit(client: Any, kb_id: str, token: str, user_id: str | None) -> bool:
    """カナリア語で検索し、結果に含まれるかを返す。"""
    kwargs: dict[str, Any] = {
        "knowledgeBaseId": kb_id,
        "retrievalQuery": {"text": token},
        "retrievalConfiguration": {
            "managedSearchConfiguration": {"numberOfResults": 10}
        },
    }
    if user_id is not None:
        kwargs["userContext"] = {"userId": user_id}
    res = client.retrieve(**kwargs)
    return any(
        token in (r.get("content", {}).get("text") or "")
        for r in res.get("retrievalResults", [])
    )


def main() -> None:
    """global ACL のフィルタリングマトリクスを検証する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kb-id", required=True)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    client = boto3.client("bedrock-agent-runtime", region_name=args.region)
    n_pass = 0
    n_fail = 0
    for case in CASES:
        for user_id, expected in case["expect"].items():
            actual = retrieve_hit(client, args.kb_id, case["token"], user_id)
            verdict = "PASS" if actual == expected else "FAIL"
            n_pass += verdict == "PASS"
            n_fail += verdict == "FAIL"
            label = user_id or "userContext なし"
            print(
                f"{case['doc']} / {label}: "
                f"expected={expected} actual={actual} -> {verdict}"
            )
    print(f"=== pass={n_pass} fail={n_fail} ===")


if __name__ == "__main__":
    main()
