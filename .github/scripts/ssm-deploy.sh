#!/usr/bin/env bash
# ssm-deploy — the RUNNER side of the opt-in EC2 continuous delivery (.github/workflows/deploy-ec2.yml).
#
# Mints SHORT-LIVED AWS credentials from the GitHub OIDC token (sts:AssumeRoleWithWebIdentity — no
# long-lived AWS keys ever live in the repo or the runner), then runs the box-side tools/remote-deploy.sh
# on the target EC2 instance via AWS SSM RunShellScript, streams its output, and exits with the box's
# exit code so a failed / rolled-back deploy fails the job.
#
# Uses ONLY curl + jq + the aws CLI preinstalled on ubuntu-latest — it adds no third-party Action to pin
# or trust, which matches this repo's supply-chain posture (every `uses:` is a maintained, SHA-pinned
# first-party Action).
set -euo pipefail

: "${VIGIL_DEPLOY_AWS_ROLE_ARN:?set the deploy role ARN (repo variable)}"
: "${VIGIL_DEPLOY_AWS_REGION:?set the AWS region (repo variable)}"
: "${VIGIL_DEPLOY_SSM_TARGET:?set the target EC2 instance id i-... (repo variable)}"
: "${ACTIONS_ID_TOKEN_REQUEST_URL:?OIDC not available — the job needs permissions: id-token: write}"
OSUSER="${VIGIL_DEPLOY_OS_USER:-vigil}"
IID="$VIGIL_DEPLOY_SSM_TARGET"
export AWS_DEFAULT_REGION="$VIGIL_DEPLOY_AWS_REGION"

[[ "$IID" == i-* ]] || { echo "ssm-deploy: VIGIL_DEPLOY_SSM_TARGET must be an EC2 instance id (i-...)"; exit 1; }

# 1) GitHub OIDC JWT for the AWS STS audience.
JWT="$(curl -sS -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sts.amazonaws.com" | jq -r '.value')"
[ -n "$JWT" ] && [ "$JWT" != "null" ] || { echo "ssm-deploy: could not mint an OIDC token"; exit 1; }

# 2) Assume the scoped deploy role (15 min).
read -r AK SK TK < <(aws sts assume-role-with-web-identity \
  --role-arn "$VIGIL_DEPLOY_AWS_ROLE_ARN" \
  --role-session-name "vigil-deploy-${GITHUB_RUN_ID:-manual}" \
  --web-identity-token "$JWT" --duration-seconds 900 \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)
[ -n "${AK:-}" ] || { echo "ssm-deploy: AssumeRoleWithWebIdentity returned no credentials"; exit 1; }
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="$TK"

# 3) Run the box-side rollout via SSM, as the VIGIL OS user (systemd --user owns the unit).
CMD="runuser -l ${OSUSER} -c 'cd ~/vigil && bash tools/remote-deploy.sh'"
CID="$(aws ssm send-command --instance-ids "$IID" --document-name AWS-RunShellScript \
  --comment "vigil CD ${GITHUB_SHA:0:12}" \
  --parameters commands="$(jq -Rn --arg c "$CMD" '[$c]')" \
  --query 'Command.CommandId' --output text)"
echo "ssm-deploy: command $CID dispatched to $IID"

# 4) Poll to a terminal state (max ~10 min), then print the box output and honour its exit code.
ST="Pending"
for _ in $(seq 1 100); do
  sleep 6
  ST="$(aws ssm get-command-invocation --command-id "$CID" --instance-id "$IID" \
        --query 'Status' --output text 2>/dev/null || echo Pending)"
  case "$ST" in Pending|InProgress|Delayed) ;; *) break ;; esac
done

echo "----- box output -----"
aws ssm get-command-invocation --command-id "$CID" --instance-id "$IID" \
  --query 'StandardOutputContent' --output text || true
aws ssm get-command-invocation --command-id "$CID" --instance-id "$IID" \
  --query 'StandardErrorContent' --output text || true
echo "----------------------"
RC="$(aws ssm get-command-invocation --command-id "$CID" --instance-id "$IID" \
      --query 'ResponseCode' --output text 2>/dev/null || echo 1)"
echo "ssm-deploy: box exit code = $RC (SSM status $ST)"
[ "$ST" = "Success" ] && [ "$RC" = "0" ]
