#!/usr/bin/env bash
#
# advanced-policy デモの実行ヘルパー。
#
# advanced-policy/cdk/outputs.json から Gateway URL / Cognito 設定を読み、
# Secrets Manager のパスワードでアクセストークンを発行してから、
# advanced-policy/agent/ 配下のスクリプトを実行する。
#
# Usage:
#   ./advanced-policy/agent/run.sh token [user]          アクセストークンを表示
#   ./advanced-policy/agent/run.sh tools [user]          メイン GW の tools/list
#   ./advanced-policy/agent/run.sh agent <prompt> [user] Agent の実行 (メイン GW)
#   ./advanced-policy/agent/run.sh verify-policy [user]  多層防御の 8 ケース検証
#
# user は a / b (既定: a)。例:
#   ./advanced-policy/agent/run.sh agent "A部門の事業計画の計画管理コードは？" a
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUTS="${REPO_ROOT}/advanced-policy/cdk/outputs.json"

if [[ ! -f "${OUTPUTS}" ]]; then
	echo "outputs.json が見つかりません: ${OUTPUTS}" >&2
	echo "先に 'cd advanced-policy/cdk && npx cdk deploy ManagedKbPolicyStack --outputs-file outputs.json' を実行してください" >&2
	exit 1
fi

output() {
	python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['ManagedKbPolicyStack'][sys.argv[2]])" "${OUTPUTS}" "$1"
}

GATEWAY_URL="$(output GatewayUrl)"
NOINT_GATEWAY_URL="$(output NoInterceptorGatewayUrl)"
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
	run_py advanced-policy/agent/list_gateway_tools.py \
		--gateway-url "${GATEWAY_URL}" \
		--access-token "$(issue_token "${1:-a}")" \
		--raw
	;;
agent)
	prompt="${1:?prompt を指定してください}"
	run_py advanced-policy/agent/agent_interceptor.py \
		--gateway-url "${GATEWAY_URL}" \
		--access-token "$(issue_token "${2:-a}")" \
		--prompt "${prompt}"
	;;
verify-policy)
	run_py advanced-policy/agent/verify_policy_enforcement.py \
		--gateway-url "${GATEWAY_URL}" \
		--noint-gateway-url "${NOINT_GATEWAY_URL}" \
		--access-token-a "$(issue_token "${1:-a}")"
	;;
*)
	# ファイル先頭のコメントブロック (shebang の次から最初の非コメント行まで) を表示
	awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "${BASH_SOURCE[0]}"
	exit 1
	;;
esac
