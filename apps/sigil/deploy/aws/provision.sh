#!/usr/bin/env bash
# VIGIL — one-time AWS provisioning for the single-host sovereign deployment (docs/runbooks/AWS-DEPLOY.md).
# ============================================================================================================
# Creates, each LEAST-PRIVILEGE and idempotently (checks before it creates):
#   1. a KMS CMK (alias/<project>-owner-kek) that envelope-encrypts VIGIL's KEK   -> VIGIL_KMS_KEY_ID
#   2. an S3 backup bucket (versioned, default SSE-KMS, public access blocked)    -> VIGIL_PUSH_DEST
#   3. an IAM role + instance profile the EC2 host assumes (NO static keys): KMS Encrypt/Decrypt/GenerateDataKey
#      on that CMK + S3 Get/Put on that bucket, and nothing else
#   4. a security group: 443 + 80 ONLY from Cloudflare's current ranges, 22 ONLY from your admin IP
#   5. an Elastic IP (the stable public IPv4 you point the DNS A record at)
#
# REVIEW THIS SCRIPT before running it — it creates billable AWS resources under YOUR account. It does NOT
# launch the EC2 instance or touch DNS (those are the owner steps in AWS-DEPLOY.md §1 + §3). No secret is
# created or printed; the owner key is sealed on the host later (`sigil vault provision`).
#
# Requirements: awscli v2 (an identity allowed to create KMS/S3/IAM/EC2 for THIS setup step), jq, curl.
# Usage:
#   REGION=eu-west-1 PROJECT=vigil ADMIN_SSH_CIDR=203.0.113.4/32 ./provision.sh
set -euo pipefail

REGION="${REGION:?set REGION, e.g. eu-west-1}"
PROJECT="${PROJECT:-vigil}"
ADMIN_SSH_CIDR="${ADMIN_SSH_CIDR:?set ADMIN_SSH_CIDR to your admin IP /32 for SSH, e.g. 203.0.113.4/32}"

aws() { command aws --region "$REGION" "$@"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 1; }; }
need jq; need curl; command -v aws >/dev/null 2>&1 || { echo "missing awscli v2" >&2; exit 1; }

ACCT="$(aws sts get-caller-identity --query Account --output text)"
BUCKET="${BUCKET:-${PROJECT}-backups-${ACCT}}"
echo "== account ${ACCT} · region ${REGION} · project ${PROJECT} =="

# 1) KMS CMK — the owner-key KEK envelope -------------------------------------------------------------------
ALIAS="alias/${PROJECT}-owner-kek"
KEY_ID="$(aws kms describe-key --key-id "$ALIAS" --query KeyMetadata.KeyId --output text 2>/dev/null || true)"
if [ -z "$KEY_ID" ] || [ "$KEY_ID" = "None" ]; then
  KEY_ID="$(aws kms create-key --description "${PROJECT} owner-key KEK (VIGIL VIGIL_KEK_BACKEND=kms)" \
            --key-usage ENCRYPT_DECRYPT --key-spec SYMMETRIC_DEFAULT --query KeyMetadata.KeyId --output text)"
  aws kms create-alias --alias-name "$ALIAS" --target-key-id "$KEY_ID"
  echo "  + created KMS CMK ${KEY_ID} (${ALIAS})"
else
  echo "  = KMS CMK exists: ${KEY_ID} (${ALIAS})"
fi
KEY_ARN="$(aws kms describe-key --key-id "$KEY_ID" --query KeyMetadata.Arn --output text)"

# 2) S3 backup bucket — versioned, default SSE-KMS, public access blocked -----------------------------------
if ! aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
  if [ "$REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$BUCKET" >/dev/null
  else
    aws s3api create-bucket --bucket "$BUCKET" \
      --create-bucket-configuration "LocationConstraint=${REGION}" >/dev/null
  fi
  echo "  + created S3 bucket ${BUCKET}"
else
  echo "  = S3 bucket exists: ${BUCKET}"
fi
aws s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-versioning --bucket "$BUCKET" --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket "$BUCKET" --server-side-encryption-configuration "$(jq -cn \
  --arg arn "$KEY_ARN" '{Rules:[{ApplyServerSideEncryptionByDefault:{SSEAlgorithm:"aws:kms",KMSMasterKeyID:$arn},BucketKeyEnabled:true}]}')"
echo "  = bucket hardened (versioning + default SSE-KMS + public access blocked)"

# 3) IAM instance role — least privilege -------------------------------------------------------------------
ROLE="${PROJECT}-host"
aws iam get-role --role-name "$ROLE" >/dev/null 2>&1 || aws iam create-role --role-name "$ROLE" \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
aws iam put-role-policy --role-name "$ROLE" --policy-name "${PROJECT}-host-policy" --policy-document "$(jq -cn \
  --arg key "$KEY_ARN" --arg bkt "arn:aws:s3:::${BUCKET}" '{Version:"2012-10-17",Statement:[
    {Sid:"OwnerKekEnvelope",Effect:"Allow",Action:["kms:Encrypt","kms:Decrypt","kms:GenerateDataKey","kms:DescribeKey"],Resource:$key},
    {Sid:"BackupObjects",Effect:"Allow",Action:["s3:PutObject","s3:GetObject"],Resource:($bkt+"/*")},
    {Sid:"BackupList",Effect:"Allow",Action:["s3:ListBucket"],Resource:$bkt}]}')"
aws iam get-instance-profile --instance-profile-name "$ROLE" >/dev/null 2>&1 \
  || aws iam create-instance-profile --instance-profile-name "$ROLE" >/dev/null
aws iam add-role-to-instance-profile --instance-profile-name "$ROLE" --role-name "$ROLE" 2>/dev/null || true
echo "  = IAM role/instance-profile ${ROLE} ready (KMS Encrypt/Decrypt/GenerateDataKey on the CMK + S3 Get/Put on the bucket only)"

# 4) Security group — 443/80 from Cloudflare only, 22 from the admin IP -------------------------------------
VPC="$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
SG="${PROJECT}-edge"
SGID="$(aws ec2 describe-security-groups --filters "Name=group-name,Values=${SG}" \
        --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)"
if [ -z "$SGID" ] || [ "$SGID" = "None" ]; then
  SGID="$(aws ec2 create-security-group --group-name "$SG" --vpc-id "$VPC" \
          --description "${PROJECT} edge: 443/80 from Cloudflare only, 22 from admin" --query GroupId --output text)"
  echo "  + created security group ${SGID} (${SG})"
else
  echo "  = security group exists: ${SGID} (${SG})"
fi
aws ec2 authorize-security-group-ingress --group-id "$SGID" --protocol tcp --port 22 --cidr "$ADMIN_SSH_CIDR" 2>/dev/null \
  && echo "  + SSH 22 from ${ADMIN_SSH_CIDR}" || echo "  = SSH rule already present"
V4="$(curl -fsS https://www.cloudflare.com/ips-v4)"
V6="$(curl -fsS https://www.cloudflare.com/ips-v6)"
# Add ONE Cloudflare CIDR to a port, idempotently. We authorize PER-CIDR, not as one all-in-one blob: a
# single multi-CIDR authorize fails ATOMICALLY the moment any one CIDR already exists
# (InvalidPermission.Duplicate), which would silently drop every genuinely-new range in the same call —
# making the documented "re-run provision.sh to pick up changed Cloudflare ranges" a no-op. Here only a real
# Duplicate is treated as already-present; any OTHER error is surfaced and aborts the run (fail-loud).
cf_add() {   # $1=port  $2=cidr  $3=v4|v6
  local key="IpRanges" ckey="CidrIp" out perm
  [ "$3" = "v6" ] && { key="Ipv6Ranges"; ckey="CidrIpv6"; }
  perm="$(jq -cn --argjson p "$1" --arg c "$2" --arg key "$key" --arg ckey "$ckey" \
    '{IpProtocol:"tcp",FromPort:$p,ToPort:$p} + {($key):[{($ckey):$c,Description:"Cloudflare"}]}')"
  if out="$(aws ec2 authorize-security-group-ingress --group-id "$SGID" --ip-permissions "$perm" 2>&1)"; then
    return 0
  fi
  printf '%s' "$out" | grep -q "InvalidPermission.Duplicate" && return 0   # already present — fine
  echo "  ! failed to authorize Cloudflare ${3} ${2} on port ${1}: ${out}" >&2
  exit 1
}
for port in 443 80; do
  n=0
  while IFS= read -r c; do [ -n "$c" ] || continue; if cf_add "$port" "$c" v4; then n=$((n + 1)); fi; done <<<"$V4"
  while IFS= read -r c; do [ -n "$c" ] || continue; if cf_add "$port" "$c" v6; then n=$((n + 1)); fi; done <<<"$V6"
  echo "  = ${port}: ensured ${n} Cloudflare CIDR(s) present (new ranges land on re-run; duplicates skipped)"
done

# 5) Elastic IP ---------------------------------------------------------------------------------------------
EIP_ALLOC="$(aws ec2 describe-addresses --filters "Name=tag:Name,Values=${PROJECT}-eip" \
             --query 'Addresses[0].AllocationId' --output text 2>/dev/null || true)"
if [ -z "$EIP_ALLOC" ] || [ "$EIP_ALLOC" = "None" ]; then
  EIP_ALLOC="$(aws ec2 allocate-address --domain vpc \
    --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Name,Value=${PROJECT}-eip}]" \
    --query AllocationId --output text)"
  echo "  + allocated Elastic IP (${EIP_ALLOC})"
else
  echo "  = Elastic IP exists (${EIP_ALLOC})"
fi
EIP="$(aws ec2 describe-addresses --allocation-ids "$EIP_ALLOC" --query 'Addresses[0].PublicIp' --output text)"

cat <<SUMMARY

== provisioned. Put these on the EC2 host (AWS-DEPLOY.md §2); the rest is launch + DNS ==
  VIGIL_KEK_BACKEND=kms
  VIGIL_KMS_KEY_ID=${ALIAS}
  VIGIL_AWS_REGION=${REGION}
  VIGIL_PUSH_DEST=s3://${BUCKET}/vigil
  VIGIL_BACKUP_S3_SSE_KMS_KEY_ID=${ALIAS}          # optional 2nd at-rest layer

  SECURITY_GROUP_ID=${SGID}                        # launch the instance in this SG
  INSTANCE_PROFILE=${ROLE}                         # attach this instance profile (no static keys)
  ELASTIC_IP=${EIP}  (allocation ${EIP_ALLOC})     # associate with the instance, point the DNS A record here
SUMMARY
