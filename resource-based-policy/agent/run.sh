#!/usr/bin/env bash
#
# resource-based-policy デモの実行ヘルパー。
#
# resource-based-policy/cdk/outputs.json から Gateway URL / Cognito 設定を
# 読み、Secrets Manager のパスワードでアクセストークンを発行してから、
# resource-based-policy/agent/ 配下のスクリプトを実行する。
#
# Usage:
#   ./resource-based-policy/agent/run.sh token [user]          アクセストークンを表示
#   ./resource-based-policy/agent/run.sh tools [user]          正規 GW の tools/list
#   ./resource-based-policy/agent/run.sh agent <prompt> [user] Agent の実行 (正規 GW)
#   ./resource-based-policy/agent/run.sh verify-rbp [user]     リソースベースポリシーの検証
#
# user は a / b (既定: a)。例:
#   ./resource-based-policy/agent/run.sh agent "A部門の事業計画の計画管理コードは？" a
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUTS="${REPO_ROOT}/resource-based-policy/cdk/outputs.json"

if [[ ! -f "${OUTPUTS}" ]]; then
	echo "outputs.json が見つかりません: ${OUTPUTS}" >&2
	echo "先に 'cd resource-based-policy/cdk && npx cdk deploy ManagedKbRbpStack --outputs-file outputs.json' を実行してください" >&2
	exit 1
fi

output() {
	python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['ManagedKbRbpStack'][sys.argv[2]])" "${OUTPUTS}" "$1"
}

GATEWAY_URL="$(output GatewayUrl)"
ROGUE_GATEWAY_URL="$(output RogueGatewayUrl)"
ROGUE_ROLE_ARN="$(output RogueRoleArn)"
KB_ARN="$(output KbArn)"
CLIENT_ID="$(output UserPoolClientId)"
SECRET_NAME="$(output TestUserPasswordSecretName)"

# アクセストークンを発行する。パスワードは記号を含むため JSON で渡す。
issue_token() {
	local user="${1:-a}"
	local email="user-${user}@example.com"
	local password
	password="$(aws secretsmanager get-secret-value \
		--secret-id "${SECRET_NAME}" --query 'SecretString' --output text)"
	local params
	params="$(python3 -c "import json,sys; print(json.dumps({'USERNAME': sys.argv[1], 'PASSWORD': sys.argv[2]}))" \
		"${email}" "${password}")"
	aws cognito-idp initiate-auth \
		--auth-flow USER_PASSWORD_AUTH \
		--client-id "${CLIENT_ID}" \
		--auth-parameters "${params}" \
		--query 'AuthenticationResult.AccessToken' --output text
}

run_py() {
	(cd "${REPO_ROOT}" && uv run python "$@")
}

cmd="${1:-}"
shift || true

case "${cmd}" in
token)
	issue_token "${1:-a}"
	;;
tools)
	run_py resource-based-policy/agent/list_gateway_tools.py \
		--gateway-url "${GATEWAY_URL}" \
		--access-token "$(issue_token "${1:-a}")" \
		--raw
	;;
agent)
	prompt="${1:?prompt を指定してください}"
	run_py resource-based-policy/agent/agent_interceptor.py \
		--gateway-url "${GATEWAY_URL}" \
		--access-token "$(issue_token "${2:-a}")" \
		--prompt "${prompt}"
	;;
verify-rbp)
	run_py resource-based-policy/agent/verify_resource_policy.py \
		--kb-arn "${KB_ARN}" \
		--gateway-url "${GATEWAY_URL}" \
		--rogue-gateway-url "${ROGUE_GATEWAY_URL}" \
		--rogue-role-arn "${ROGUE_ROLE_ARN}" \
		--access-token-a "$(issue_token "${1:-a}")"
	;;
*)
	# ファイル先頭のコメントブロック (shebang の次から最初の非コメント行まで) を表示
	awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "${BASH_SOURCE[0]}"
	exit 1
	;;
esac
