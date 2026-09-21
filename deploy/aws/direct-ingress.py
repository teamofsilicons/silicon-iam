#!/usr/bin/env python3
"""Recover this singleton's retained ENI and pinned private ingress archive.

Called only by fresh-instance provisioning. Never detaches an interface, changes
DNS/EIPs/security groups, or prints certificate/key material.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import subprocess
import tarfile
import time
from urllib.request import Request, urlopen

ROOTS = ("etc/letsencrypt", "etc/nginx/conf.d/base-tier.conf",
         "etc/nginx/conf.d/scoped-iam.conf", "etc/sysconfig/certbot")
HOSTS = ("backend.iam.teamofsilicons.com", "scoped.backend.iam.teamofsilicons.com")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(command):
    result = subprocess.run(command, text=True, capture_output=True)
    require(result.returncode == 0, command[0] + " failed during ingress recovery")
    return result.stdout


def aws(*arguments):
    output = run(["aws", "--region", os.environ["REGION"], *arguments, "--output", "json"])
    return json.loads(output) if output.strip() else {}


def identity():
    base = "http://169.254.169.254/latest/"
    request = Request(base + "api/token", method="PUT",
                      headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
    with urlopen(request, timeout=3) as response:
        token = response.read().decode()
    request = Request(base + "dynamic/instance-identity/document",
                      headers={"X-aws-ec2-metadata-token": token})
    with urlopen(request, timeout=3) as response:
        return json.load(response)


def validate_interface(interface, instance):
    require(interface["AvailabilityZone"] == instance["availabilityZone"],
            "Retained ingress ENI is in another Availability Zone")
    require(dict((tag["Key"], tag["Value"]) for tag in interface.get("TagSet", [])).get("Service") == "silicon-iam",
            "Retained ingress ENI is not tagged for silicon-iam")
    require(interface.get("Association", {}).get("PublicIp"), "Retained ENI has no existing public address")
    attachment = interface.get("Attachment")
    if attachment:
        require(attachment["InstanceId"] == instance["instanceId"],
                "Retained ingress ENI belongs to another instance; never detach the serving host")
        require(attachment["DeviceIndex"] == 1, "Unexpected retained ENI device index")
    else:
        require(interface["Status"] == "available", "Retained ingress ENI is not available")


def read_interface():
    rows = aws("ec2", "describe-network-interfaces", "--network-interface-ids",
               os.environ["PUBLIC_ENI"])["NetworkInterfaces"]
    require(len(rows) == 1, "Expected exactly one retained ingress ENI")
    return rows[0]


def preflight():
    instance = identity()
    interface = read_interface()
    validate_interface(interface, instance)
    return instance, interface


def attach():
    # Recheck immediately before attaching. AWS also rejects concurrent claims;
    # recovery never retries by force-detaching or reassigning the Elastic IP.
    instance, interface = preflight()
    attachment = interface.get("Attachment")
    if attachment:
        attachment_id = attachment["AttachmentId"]
    else:
        attachment_id = aws("ec2", "attach-network-interface", "--network-interface-id",
                            os.environ["PUBLIC_ENI"], "--instance-id", instance["instanceId"],
                            "--device-index", "1")["AttachmentId"]
    aws("ec2", "modify-network-interface-attribute", "--network-interface-id",
        os.environ["PUBLIC_ENI"], "--attachment",
        json.dumps({"AttachmentId": attachment_id, "DeleteOnTermination": False}))
    for _ in range(60):
        addresses = json.loads(run(["ip", "-json", "address", "show"]))
        rules = json.loads(run(["ip", "-json", "rule", "show"]))
        ip = interface["PrivateIpAddress"]
        if (any(address.get("local") == ip for device in addresses for address in device.get("addr_info", []))
                and any(rule.get("src") in (ip, ip + "/32") for rule in rules)):
            return
        time.sleep(2)
    raise RuntimeError("AL2023 did not configure retained ENI addressing and source routing")


def allowed(name):
    return any(name == root or (root == "etc/letsencrypt" and name.startswith(root + "/")) for root in ROOTS)


def checked_members(archive):
    members = archive.getmembers()
    require(len(members) <= 10000 and sum(m.size for m in members) <= 128 * 1024 * 1024,
            "Ingress archive exceeds its recovery bound")
    names = set()
    links = set()
    for member in members:
        name = member.name.rstrip("/")
        path = PurePosixPath(name)
        require(not path.is_absolute() and ".." not in path.parts and allowed(name),
                "Unexpected path in ingress archive")
        require(name not in names, "Duplicate path in ingress archive")
        names.add(name)
        require(member.isdir() or member.isfile() or member.issym(), "Special file in ingress archive")
        if member.issym():
            target = posixpath.normpath(posixpath.join(posixpath.dirname(name), member.linkname))
            require(not member.linkname.startswith("/") and allowed(target), "Escaping ingress archive symlink")
            links.add(name)
    for name in names:
        require(not any(str(parent) in links for parent in PurePosixPath(name).parents),
                "Archive path traverses an archive symlink")
    return members


def restore(path, root=Path("/")):
    # Validate every member before creating anything. Restore only the existing
    # certificate/account/config bytes; archive content cannot write elsewhere.
    with tarfile.open(path, "r:gz") as archive:
        members = checked_members(archive)
        for member in sorted(members, key=lambda item: (item.issym(), len(PurePosixPath(item.name).parts))):
            target = root / member.name
            require(not target.is_symlink(), "Refusing to overwrite an existing symlink during recovery")
            for parent in target.parents:
                require(not parent.is_symlink(), "Recovery parent is a symlink")
                if parent == root:
                    break
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(exist_ok=True)
            elif member.issym():
                target.symlink_to(member.linkname)
            else:
                source = archive.extractfile(member)
                require(source is not None, "Unreadable ingress archive member")
                with target.open("wb") as output:
                    while chunk := source.read(1024 * 1024):
                        output.write(chunk)
            if not member.issym():
                target.chmod(member.mode & 0o777)
    for host in HOSTS:
        for filename in ("fullchain.pem", "privkey.pem"):
            require((root / "etc/letsencrypt/live" / host / filename).is_file(), "Missing restored certificate/key")
    require((root / "etc/nginx/conf.d/base-tier.conf").is_file()
            and (root / "etc/nginx/conf.d/scoped-iam.conf").is_file(), "Missing restored nginx route")


def download_archive(path):
    metadata = aws("s3api", "get-object", "--bucket", os.environ["TLS_ARCHIVE_BUCKET"],
                   "--key", os.environ["TLS_ARCHIVE_KEY"], "--version-id",
                   os.environ["TLS_ARCHIVE_VERSION_ID"], str(path))
    require(metadata.get("ServerSideEncryption") == "AES256", "Ingress archive must use SSE-S3 encryption")
    require(hashlib.sha256(path.read_bytes()).hexdigest() == os.environ["TLS_ARCHIVE_SHA256"],
            "Pinned ingress archive checksum mismatch")


def recover():
    preflight()
    path = Path("/opt/silicon-iam/provisioning/ingress.tar.gz")
    try:
        download_archive(path)
        restore(path)
    finally:
        path.unlink(missing_ok=True)
    Path("/var/www/certbot").mkdir(parents=True, exist_ok=True)
    run(["nginx", "-t"])
    run(["systemctl", "enable", "--now", "nginx"])
    attach()
    # The recovered account can renew an older pinned certificate without
    # registering a new account or changing application credentials.
    run(["certbot", "renew", "--noninteractive", "--no-random-sleep-on-renew",
         "--deploy-hook", "systemctl reload nginx"])
    run(["systemctl", "enable", "--now", "certbot-renew.timer"])
    for host in HOSTS:
        run(["curl", "--fail", "--silent", "--show-error", "--max-time", "10",
             "--resolve", host + ":443:127.0.0.1", "https://" + host + "/readyz"])
    print("Retained direct IAM ingress recovered; public DNS and interface identity preserved.")


def capture(output, root=Path("/")):
    require(os.geteuid() == 0, "Capture ingress state on the existing host as root")
    require(not output.exists(), "Refusing to overwrite an ingress archive")
    output.parent.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    with tarfile.open(output, "x:gz", dereference=False) as archive:
        for name in ROOTS:
            path = root / name
            require(path.exists(), "A required ingress archive source is missing")
            archive.add(path, arcname=name)
    output.chmod(0o600)
    with tarfile.open(output, "r:gz") as archive:
        checked_members(archive)
    print(json.dumps({"archive": str(output), "bytes": output.stat().st_size,
                      "sha256": hashlib.sha256(output.read_bytes()).hexdigest()}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["preflight", "recover", "capture"])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if args.operation == "capture":
        require(args.output is not None, "Capture requires a private output path")
        capture(args.output)
    elif args.operation == "preflight":
        preflight()
        print("Retained direct-ingress ENI preflight passed.")
    else:
        recover()
