# Retained direct-nginx IAM ingress

`production.yaml` now describes the existing singleton topology explicitly.
Direct mode creates a new launch-template version that provisions the main API,
scoped API, worker, nginx and Certbot from the selected immutable backend image.
It keeps the existing RDS databases, application credentials, dedicated scoped
webhook keyring, public ENI, Elastic IP and DNS names.

This is replacement-host provisioning. Use the canonical release operator for
the coordinated schema cutover on the serving host. Updating the template does
not run its user data on that host. Do not run `bootstrap-production.sh` manually
there; it refuses an existing `/etc/silicon-iam/api.env`.

## Current recovery inputs

The 2026-09-21 read-only audit found the ASG selecting launch-template version46,
an outdated image and an already deleted load-balancer target group. The live
instance instead serves both domains through nginx and a retained secondary ENI.
The release operator holds `AZRebalance`, `InstanceRefresh`, and
`ReplaceUnhealthy`; the prior suspended-process set was empty. Keep this recorded
hold until the operator explicitly reviews replacement readiness.

| CloudFormation parameter | Existing production value |
| --- | --- |
| `DirectNginx` | `true` |
| `UseSharedLoadBalancer` | `false` |
| `DedicatedTargetGroupArn` | empty string |
| `PrivateSubnetA` | `subnet-00cb233b2b136e259` (us-east-1a) |
| `PublicNetworkInterfaceId` | `eni-06b8a2b93a8d9e270` |
| `ScopedWebhookSecretArn` | `arn:aws:secretsmanager:us-east-1:234951665042:secret:silicon-iam/production/scoped-webhook-7K3Tmi` |
| `TlsArchiveBucket` | `silicon-iam-recovery-234951665042-us-east-1` |
| `TlsArchiveKey` | `canonical-20260921/tls-before-cutover.tar.gz` |
| `TlsArchiveVersionId` | `ndyiUlQvRzzQO3cZv.j9.OowEZj3pdxc` |
| `TlsArchiveSha256` | `d9c7d3d7ff04695d09328f032711255403e36425c92f07e50ca8798cd5f6dae5` |
| `BackendImageUri` | **The final rebuilt, rehearsed and deployed canonical image digest.** Read it from the current release manifest; do not reuse an earlier staged image. |

The existing ENI is in public subnet `subnet-07945746462c26b2d`, also us-east-1a.
It retains `44.209.29.33` and is attached as device1 with
`DeleteOnTermination=false`. Both the ENI and serving instance carry
`Service=silicon-iam`; the launch template supplies that tag to new instances.
The helper checks the instance identity through IMDSv2 and rejects another AZ.
AWS requires an attached ENI and instance to be in the
[same Availability Zone](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/network-interface-attachments.html).

The recovery bucket is private, versioned, encrypted with SSE-S3/AES256, and
requires HTTPS. The selected archive is 10,080 bytes. It contains existing
certificate, private-key, ACME-account, renewal and nginx bytes; none are stored
in Git or in user data. Its permitted paths are exactly:

- `/etc/letsencrypt/**`
- `/etc/nginx/conf.d/base-tier.conf`
- `/etc/nginx/conf.d/scoped-iam.conf`
- `/etc/sysconfig/certbot`

## Review and apply without replacing the serving instance

1. Finish the canonical database cutover and verify all three running services
   use the final digest. Capture the current stack parameters, ASG suspended
   processes, launch-template version, instance ID and ENI attachment again.
   Keep the private release evidence and database backups.
2. Run the checks below. Create a CloudFormation change set with the table's
   explicit direct-ingress inputs, final image digest, and previous values for
   other stack parameters. Use `CAPABILITY_NAMED_IAM`. Review any resolved AMI
   change: the existing `AmiId` is an SSM parameter, so preserving its parameter
   name can resolve a newer AL2023 image at update time.
3. The expected changes are the launch template, exact instance-role grants and
   ASG placement/health/target-group settings. Require no RDS replacement, public
   ENI/EIP or DNS change, instance refresh, capacity change, or serving-instance
   replacement. Stop and investigate any additional resource change. Direct mode
   sets one private subnet in the ENI's AZ, EC2 health and no target groups.
4. After the release operator approves that concrete change set, execute it with
   the replacement hold still present. This template has no rolling-update or
   replacement policy. Do not start an instance refresh to validate it. If AWS
   rejects removal of the stale deleted target-group reference, stop for a narrow
   ASG reconciliation; do not recreate the old edge stack as a workaround.
5. Re-read the stack, ASG and new launch-template version. Confirm the ASG points
   at that explicit version, its resolved image digest is final, no target group
   remains, health is EC2, placement is AZa and the serving instance is unchanged.
   Check the resolved user data is below EC2's raw 16KiB limit. Align the launch
   template's default version for manual operator launches only after this review;
   the ASG already uses an explicit version.
6. Preserve the hold during the rest of the release. Resuming the three processes
   is a separate operator decision after the new source and recovery dependencies
   are verified. Restore only the processes this release suspended; never reset
   another operator's suspension state. EC2 health checks do not validate nginx
   or application readiness, so retain external checks for both public endpoints.

```sh
python3 scripts/render-production-userdata.py --check
python3 scripts/test-production-provisioning.py
bash -n deploy/aws/bootstrap-production.sh
cfn-lint --non-zero-exit-code error deploy/aws/production.yaml
aws cloudformation validate-template --profile silicon-production --region us-east-1 \
  --template-body file://deploy/aws/production.yaml
```

The source passes the nine offline recovery checks and AWS template validation.
`cfn-lint` has no errors; it reports W1030 for the empty default of the optional
scoped-secret ARN. The direct-mode rule requires that ARN, and its policy only
exists when direct mode is selected. The generated payload is approximately
11KiB before parameter resolution. The readable scripts are embedded as a
deterministic compressed archive to remain below the
[EC2 user-data limit](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html).
Regenerate the payload after editing either source script.

## Replacement and failure behavior

Fresh provisioning first checks the retained ENI. If it is attached to another
instance, provisioning fails before database-role configuration or migration.
It never force-detaches a serving host, reassigns an EIP, changes a route or
security group, or provisions a new edge stack. A replacement in parallel with
the serving singleton is deliberately not an automatic traffic handover.

Once the predecessor has been deliberately retired and the ENI is available,
the new instance can recover it as device1. Provisioning uses existing secrets
for database roles and application keyrings, applies the image's migrations and
runtime grants, installs the scoped-auth helper in both planes, and installs all
three service units. Both Honeycomb worker flags come from the existing app
secret. A failed bootstrap stops all three application services and leaves a
cloud-init error for operator inspection.

The helper downloads the exact S3 object version, requires AES256 encryption and
the pinned SHA256, validates every archive path and link before extraction, and
restores the existing Certbot account and nginx configs. It verifies nginx,
attaches the available ENI, waits for AL2023's extra-interface address and source
routing, renews certificates when needed, enables nginx/renewal at boot, and
checks both `/readyz` routes with normal TLS validation. Renewal reuses the
existing account. A failed recovery never steals or deletes the retained ENI.

The new IAM policy grants only scoped-secret read, `s3:GetObjectVersion` on this
key and version, ENI describe, attach of the exact ENI to a tagged IAM instance,
and modification of that ENI's attachment retention attribute. AWS additionally
authorizes the attached instance for that retention update, so a separate
statement permits the instance resource only when it has the IAM service and
production ASG tags. The attribute restriction remains on the exact ENI; the
instance evaluation does not expose `ec2:Attribute`. This split follows the
decoded live-role dry-run denial observed during the 2026-09-21 validation.
The ENI context uses the case-sensitive value `Attachment`, even though the CLI
option is `--attachment`; the policy and regression fixture use that exact value.
The policy has no detach,
EIP, DNS, S3 write or bucket-list permission. Resource types and attribute
conditions follow the [EC2 authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html).

Before resuming replacement, use the instance role to download and validate the
pinned archive, compare its files and the scoped keyring with the current host,
and run both EC2 attachment/retention requests with `--dry-run`. Require
`DryRunOperation` for both; `UnauthorizedOperation` is a recovery blocker.
Dry-run permission checks do not attach an interface or change its retention.

If fresh provisioning fails after writing an environment file, do not remove
the existing-host guard or blindly rerun database preparation. Inspect the
failed stage and image/schema compatibility, fix that stage, then deliberately
resume the services and `direct-ingress.py recover` with the same reviewed
nonsecret parameters. No live replacement or reboot has been performed to test
this patch; the checks cover source generation, archive recovery and attachment
guards without moving production traffic.

## Refreshing the recovery archive later

On the existing host, run the checked-in helper as root with a new private file:

```sh
python3 direct-ingress.py capture --output /var/backups/silicon-iam/ingress-new.tar.gz
```

It preserves symlinks and file modes, refuses to overwrite the output, and emits
only its path, size and SHA256. Upload through an authorized operator to a new
version of the private encrypted recovery object; do not grant the permanent
instance role upload access. Verify encryption, object version, size and SHA256,
then change the three archive pin parameters in a reviewed template update.
Keep the previous version for recovery. Never print or commit archive contents.
