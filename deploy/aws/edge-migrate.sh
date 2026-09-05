#!/usr/bin/env bash
# Plan a traffic attachment/cutover without rebuilding or changing application configuration.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVICE_STACK="silicon-iam-production"
EDGE_STACK="silicon-iam-edge"
MODE="${1:-}"
case "$MODE" in
  attach) SHARED=true ;;
  retire-shared) SHARED=false ;;
  *) printf 'Usage: bash deploy/aws/edge-migrate.sh attach|retire-shared\n' >&2; exit 2 ;;
esac
# The caller supplies AWS_PROFILE and AWS_REGION. No secrets are read.
: "${AWS_REGION:?set AWS_REGION}"
EDGE_STATUS=$(aws cloudformation describe-stacks --stack-name "$EDGE_STACK" --query 'Stacks[0].StackStatus' --output text)
case "$EDGE_STATUS" in CREATE_COMPLETE|UPDATE_COMPLETE) ;; *) printf 'Edge stack is not ready: %s\n' "$EDGE_STATUS" >&2; exit 1 ;; esac
TARGET=$(aws cloudformation describe-stacks --stack-name "$EDGE_STACK" --query "Stacks[0].Outputs[?OutputKey=='ApiTargetGroupArn'].OutputValue" --output text)
[[ "$TARGET" == arn:*:elasticloadbalancing:*:targetgroup/* ]] || { printf 'Missing edge target group\n' >&2; exit 1; }
HEALTH=$(aws elbv2 describe-target-health --target-group-arn "$TARGET" --output json)
printf '%s' "$HEALTH" | jq -e '.TargetHealthDescriptions | length > 0 and all(.[]; .TargetHealth.State == "healthy")' >/dev/null || {
  printf 'Dedicated targets must already be registered and healthy before planning cutover\n' >&2
  exit 1
}
# Preserve all existing values, including immutable image and Secrets Manager references.
PARAMETERS=$(aws cloudformation describe-stacks --stack-name "$SERVICE_STACK" --query 'Stacks[0].Parameters' --output json |
  jq --arg target "$TARGET" --arg shared "$SHARED" '
    map(select(.ParameterKey != "DedicatedTargetGroupArn" and .ParameterKey != "UseSharedLoadBalancer") |
      {ParameterKey, UsePreviousValue: true}) +
    [{ParameterKey:"DedicatedTargetGroupArn",ParameterValue:$target},
     {ParameterKey:"UseSharedLoadBalancer",ParameterValue:$shared}]')
CHANGE_SET="dedicated-edge-$MODE-$(date -u +%Y%m%d%H%M%S)"
aws cloudformation create-change-set --stack-name "$SERVICE_STACK" --change-set-name "$CHANGE_SET" \
  --change-set-type UPDATE --template-body "file://$ROOT/deploy/aws/production.yaml" \
  --parameters "$PARAMETERS" --capabilities CAPABILITY_NAMED_IAM
printf '\nCreated change set %s. Inspect it before executing.\n' "$CHANGE_SET"
printf 'Expected attach: AutoScalingGroup modification only. No instance, image, database, bucket or role changes.\n'
printf 'Retire shared routing only after authoritative DNS and fresh connections use the dedicated edge.\n'
