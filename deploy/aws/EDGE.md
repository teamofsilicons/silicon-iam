# Dedicated IAM edge

The service owns `deploy/aws/edge.json`: a dedicated HTTPS load balancer,
host-restricted listener, target group, ALB-only instance ingress, WAF and
redacted block logs. It reuses the existing VPC, public subnets, ACM certificate
and application instances. It does not replace databases, images or storage.

## Safe migration

1. Create a CloudFormation change set for `silicon-iam-edge` using
   `edge.json`. Supply `VpcId`, `PublicSubnetA`, `PublicSubnetB`,
   `InstanceSecurityGroupId` and `CertificateArn` from the deployment.
   Review additions, then execute. Wait for CREATE_COMPLETE.
2. Register the current service ASG instance(s) in the new `ApiTargetGroupArn`
   output and wait for healthy targets. Test the new edge using the real Host/SNI
   with curl's `--connect-to`; never bypass certificate verification.
3. Run `AWS_REGION=us-east-1 bash deploy/aws/edge-migrate.sh attach`.
   Inspect the service change set: only AutoScalingGroup target attachments
   should change. Preserve every existing image, AMI, secret and database parameter.
   Execute it and verify both target groups are healthy.
4. Change only the `backend.iam.teamofsilicons.com` CNAME to
   the edge's `LoadBalancerDnsName`. Preserve the rest of the DNS zone.
   Wait through the previous TTL, then verify authoritative/public resolution
   and new TLS connections, readiness and real API requests.
5. Run `bash deploy/aws/edge-migrate.sh retire-shared` with the same AWS
   environment. Inspect before execution. It removes this service's old listener
   rule, listener certificate attachment, target group and shared-ALB security-group
   rules. The dedicated ingress stays in the edge stack.
6. Confirm only the dedicated group remains on the ASG. Do not delete the shared
   load balancer: other services still use it.

Both commands **create a plan only**; they do not execute a change set.
The migration retains application-session and signing keys. No token rotation or
database migration is needed. Normal service deployments preserve the migration
parameters; do not reset `UseSharedLoadBalancer` to true after cutover.

## Rollback

Before retiring shared resources, point the CNAME back to its previous value;
both edges remain attached and healthy. Preserve a private copy of the previous
DNS record and stack parameters. After retirement, re-enable shared routing
through a reviewed service change set before restoring the old DNS destination.
Keep deletion protection enabled on the dedicated ALB. WAF block logs retain
30 days and are retained if the edge stack is deleted.

## Firewall

The managed common and known-bad protections stay enabled. Registration keeps
its existing cookie exceptions. EC2 metadata SSRF query matches are counted,
then blocked again unless **all** conditions match: GET /api/v1/login on
backend.iam.teamofsilicons.com, app_id=tos>briefcase, and an exact
http://localhost:4317/auth/callback?state=<64 lowercase hex characters> callback.
This exception does not bypass other query, header, cookie, body, rate or
known-bad checks and does not create a broad Allow rule.

WAF uses one common-rules evaluation and one known-bad evaluation. Query strings,
URI paths and credential-bearing headers are redacted, request sampling is off,
and only blocked requests are logged.
