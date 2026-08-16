#!/usr/bin/env bash
#
# デモの実行ヘルパー。
#
# fgac-interceptor/cdk/outputs.json から Gateway URL / KB ID / Cognito
# 設定を読み、Secrets Manager のパスワードでアクセストークンを発行して
# から、fgac-interceptor/agent/ 配下のスクリプトを実行する。
#
# Usage:
#   ./fgac-interceptor/agent/run.sh token [user]                 アクセストークンを表示
#   ./fgac-interceptor/agent/run.sh tools [user]                 tools/list を取得
#   ./fgac-interceptor/agent/run.sh agent <prompt> [user]        方式 1 (Interceptor 構成)
#   ./fgac-interceptor/agent/run.sh hook <prompt> [user]         方式 2 (アプリ側フック構成)
#   ./fgac-interceptor/agent/run.sh verify-injection [user]      userContext 注入・詐称防止
#   ./fgac-interceptor/agent/run.sh verify-global-acl            global ACL のフィルタリング
#   ./fgac-interceptor/agent/run.sh verify-metadata-filter       ACL と filter の併用
#   ./fgac-interceptor/agent/run.sh verify-all                   検証スクリプトを一括実行
#
# user は a / b (既定: a)。例:
#   ./fgac-interceptor/agent/run.sh agent "A部門の事業計画の計画管理コードは？" a
#   ./fgac-interceptor/agent/run.sh agent "B部門の事業計画の計画管理コードは？" b
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUTS="${REPO_ROOT}/fgac-interceptor/cdk/outputs.json"

if [[ ! -f "${OUTPUTS}" ]]; then
	echo "outputs.json が見つかりません: ${OUTPUTS}" >&2
	echo "先に 'cd fgac-interceptor/cdk && npx cdk deploy ManagedKbGatewayStack --outputs-file outputs.json' を実行してください" >&2
	exit 1
fi

output() {
	python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['ManagedKbGatewayStack'][sys.argv[2]])" "${OUTPUTS}" "$1"
}

GATEWAY_URL="$(output GatewayUrl)"
KB_ID="$(output KbId)"
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
	run_py fgac-interceptor/agent/list_gateway_tools.py \
		--gateway-url "${GATEWAY_URL}" \
		--access-token "$(issue_token "${1:-a}")" \
		--raw
	;;
agent)
	prompt="${1:?prompt を指定してください}"
	run_py fgac-interceptor/agent/agent_interceptor.py \
		--gateway-url "${GATEWAY_URL}" \
		--access-token "$(issue_token "${2:-a}")" \
		--prompt "${prompt}"
	;;
hook)
	prompt="${1:?prompt を指定してください}"
	run_py fgac-interceptor/agent/agent_hook.py \
		--gateway-url "${GATEWAY_URL}" \
		--access-token "$(issue_token "${2:-a}")" \
		--prompt "${prompt}"
	;;
verify-injection)
	run_py fgac-interceptor/agent/verify_usercontext_injection.py \
		--gateway-url "${GATEWAY_URL}" \
		--access-token-a "$(issue_token "${1:-a}")"
	;;
verify-global-acl)
	run_py fgac-interceptor/agent/verify_global_acl.py --kb-id "${KB_ID}"
	;;
verify-metadata-filter)
	run_py fgac-interceptor/agent/verify_metadata_filter.py --kb-id "${KB_ID}"
	;;
verify-all)
	echo "### userContext の注入・詐称防止"
	run_py fgac-interceptor/agent/verify_usercontext_injection.py \
		--gateway-url "${GATEWAY_URL}" \
		--access-token-a "$(issue_token a)"
	echo
	echo "### global ACL のフィルタリング"
	run_py fgac-interceptor/agent/verify_global_acl.py --kb-id "${KB_ID}"
	echo
	echo "### ACL とメタデータフィルタリングの併用"
	run_py fgac-interceptor/agent/verify_metadata_filter.py --kb-id "${KB_ID}"
	;;
*)
	# ファイル先頭のコメントブロック (shebang の次から最初の非コメント行まで) を表示
	awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "${BASH_SOURCE[0]}"
	exit 1
	;;
esac
