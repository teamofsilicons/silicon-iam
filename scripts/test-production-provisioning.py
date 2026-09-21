#!/usr/bin/env python3
"""Offline regression checks for the bounded singleton recovery bootstrap."""
import base64
import copy
import fnmatch
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ingress = load("ingress", "deploy/aws/direct-ingress.py")
renderer = load("renderer", "scripts/render-production-userdata.py")
INSTANCE = {"instanceId": "i-new", "availabilityZone": "us-east-1a"}
INTERFACE = {
    "AvailabilityZone": "us-east-1a", "Status": "available",
    "TagSet": [{"Key": "Service", "Value": "silicon-iam"}],
    "Association": {"PublicIp": "192.0.2.1"}, "PrivateIpAddress": "10.0.0.2",
}


class IngressTests(unittest.TestCase):
    def test_other_instance_and_wrong_az_never_attach_or_modify(self):
        for changes in (
            {"Attachment": {"InstanceId": "i-serving", "DeviceIndex": 1}},
            {"AvailabilityZone": "us-east-1b"},
            {"Association": {}},
            {"TagSet": []},
        ):
            with self.subTest(changes=changes), patch.object(ingress, "identity", return_value=INSTANCE), \
                    patch.object(ingress, "read_interface", return_value=INTERFACE | changes), \
                    patch.object(ingress, "aws") as aws:
                with self.assertRaises(RuntimeError):
                    ingress.attach()
                aws.assert_not_called()

    def test_available_eni_attaches_once_and_is_retained(self):
        calls = []

        def aws(*args):
            calls.append(args)
            return {"AttachmentId": "eni-attach-new"}

        addresses = json.dumps([{"addr_info": [{"local": "10.0.0.2"}]}])
        routes = json.dumps([{"src": "10.0.0.2/32"}])
        with patch.object(ingress, "preflight", return_value=(INSTANCE, copy.deepcopy(INTERFACE))), \
                patch.object(ingress, "aws", side_effect=aws), \
                patch.object(ingress, "run", side_effect=[addresses, routes]), \
                patch.dict(os.environ, {"PUBLIC_ENI": "eni-retained"}):
            ingress.attach()
        self.assertEqual([call[1] for call in calls],
                         ["attach-network-interface", "modify-network-interface-attribute"])
        self.assertIn("i-new", calls[0])
        self.assertIn("eni-retained", calls[0])
        self.assertEqual(json.loads(calls[1][-1]),
                         {"AttachmentId": "eni-attach-new", "DeleteOnTermination": False})

    def test_already_attached_to_this_instance_is_not_attached_again(self):
        interface = INTERFACE | {"Attachment": {
            "InstanceId": "i-new", "DeviceIndex": 1, "AttachmentId": "eni-attach-existing"}}
        with patch.object(ingress, "preflight", return_value=(INSTANCE, interface)), \
                patch.object(ingress, "aws") as aws, \
                patch.object(ingress, "run", side_effect=[
                    '[{"addr_info":[{"local":"10.0.0.2"}]}]', '[{"src":"10.0.0.2"}]']), \
                patch.dict(os.environ, {"PUBLIC_ENI": "eni-retained"}):
            ingress.attach()
        self.assertEqual(aws.call_count, 1)
        self.assertEqual(aws.call_args.args[1], "modify-network-interface-attribute")

    def test_only_pinned_encrypted_archive_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive.tar.gz"
            content = b"private recovery archive"
            path.write_bytes(content)
            env = {"TLS_ARCHIVE_BUCKET": "private-bucket", "TLS_ARCHIVE_KEY": "one/key.tar.gz",
                   "TLS_ARCHIVE_VERSION_ID": "version-1", "TLS_ARCHIVE_SHA256": hashlib.sha256(content).hexdigest()}
            with patch.dict(os.environ, env), patch.object(ingress, "aws", return_value={"ServerSideEncryption": "AES256"}) as aws:
                ingress.download_archive(path)
                self.assertEqual(aws.call_args.args, ("s3api", "get-object", "--bucket", "private-bucket",
                                                     "--key", "one/key.tar.gz", "--version-id", "version-1", str(path)))
                path.write_bytes(b"changed")
                with self.assertRaisesRegex(RuntimeError, "checksum"):
                    ingress.download_archive(path)
                aws.return_value = {}
                with self.assertRaisesRegex(RuntimeError, "encryption"):
                    ingress.download_archive(path)

    def test_archive_rejects_escape_link_and_special_entries_before_write(self):
        for name, kind, link in (
            ("../etc/shadow", tarfile.REGTYPE, ""),
            ("/etc/letsencrypt/x", tarfile.REGTYPE, ""),
            ("etc/letsencrypt/link", tarfile.SYMTYPE, "../../shadow"),
            ("etc/letsencrypt/device", tarfile.CHRTYPE, ""),
            ("etc/letsencrypt/hard", tarfile.LNKTYPE, "etc/letsencrypt/key"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                archive_path = Path(directory) / "archive.tar.gz"
                destination = Path(directory) / "restore"
                with tarfile.open(archive_path, "w:gz") as archive:
                    member = tarfile.TarInfo(name)
                    member.type, member.linkname = kind, link
                    archive.addfile(member)
                with self.assertRaises(RuntimeError):
                    ingress.restore(archive_path, destination)
                self.assertFalse(destination.exists())

    def test_certificate_account_config_bytes_and_symlinks_survive_capture_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            destination = Path(directory) / "restored"
            archive_path = Path(directory) / "private.tar.gz"
            files = {}
            for host in ingress.HOSTS:
                for name in ("fullchain", "privkey"):
                    key = f"etc/letsencrypt/archive/{host}/{name}1.pem"
                    files[key] = f"synthetic {host} {name}\n".encode()
                    link = source / f"etc/letsencrypt/live/{host}/{name}.pem"
                    link.parent.mkdir(parents=True, exist_ok=True)
                    link.symlink_to(f"../../archive/{host}/{name}1.pem")
                files[f"etc/letsencrypt/renewal/{host}.conf"] = b"existing renewal configuration\n"
            files["etc/letsencrypt/accounts/acme/account/private_key.json"] = b'{"synthetic":"same-account"}'
            for name in ingress.ROOTS[1:]:
                files[name] = ("existing " + name).encode()
            for name, content in files.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                path.chmod(0o600)
            with patch.object(ingress.os, "geteuid", return_value=0), patch("builtins.print"):
                ingress.capture(archive_path, source)
            self.assertEqual(archive_path.stat().st_mode & 0o777, 0o600)
            ingress.restore(archive_path, destination)
            for name, content in files.items():
                self.assertEqual((destination / name).read_bytes(), content)
                self.assertEqual((destination / name).stat().st_mode & 0o777, 0o600)
            for host in ingress.HOSTS:
                self.assertTrue((destination / f"etc/letsencrypt/live/{host}/privkey.pem").is_symlink())


class BootstrapTests(unittest.TestCase):
    def test_retention_authorizes_both_required_resources_without_broadening_eni_scope(self):
        # Ruby/YAML is already required by the repository's CI checks. Its YAML
        # reader retains the scalar values of these CloudFormation intrinsics.
        template = json.loads(subprocess.check_output([
            "ruby", "-rjson", "-ryaml", "-e", "puts JSON.generate(YAML.load_file(ARGV[0]))",
            str(ROOT / "deploy/aws/production.yaml")], text=True))
        policy = template["Resources"]["InstanceRole"]["Properties"]["Policies"][1][1]["PolicyDocument"]
        substitutions = {"AWS::Partition": "aws", "AWS::Region": "us-east-1",
                         "AWS::AccountId": "234951665042", "PublicNetworkInterfaceId": "eni-retained"}

        def allowed(resource, context, action="ec2:ModifyNetworkInterfaceAttribute"):
            for statement in policy["Statement"]:
                if statement["Action"] != action or statement["Effect"] != "Allow":
                    continue
                pattern = statement["Resource"]
                for key, value in substitutions.items():
                    pattern = pattern.replace("${" + key + "}", value)
                conditions = statement.get("Condition", {}).get("StringEquals", {})
                if fnmatch.fnmatchcase(resource, pattern) and all(context.get(key) == value for key, value in conditions.items()):
                    return True
            return False

        prefix = "arn:aws:ec2:us-east-1:234951665042:"
        eni = prefix + "network-interface/eni-retained"
        instance = prefix + "instance/i-replacement"
        eni_context = {"ec2:ResourceTag/Service": "silicon-iam", "ec2:Attribute": "attachment"}
        # Real decoded AWS denial: the attached-instance evaluation carries
        # these resource tags but no ec2:Attribute key.
        instance_context = {"ec2:ResourceTag/Service": "silicon-iam",
                            "ec2:ResourceTag/aws:autoscaling:groupName": "silicon-iam-production"}
        self.assertTrue(allowed(eni, eni_context))
        self.assertTrue(allowed(instance, instance_context))
        self.assertFalse(allowed(prefix + "network-interface/eni-other", eni_context))
        self.assertFalse(allowed(eni, eni_context | {"ec2:Attribute": "groupSet"}))
        self.assertFalse(allowed(instance, {"ec2:ResourceTag/Service": "silicon-iam"}))
        self.assertFalse(allowed(instance, instance_context | {"ec2:ResourceTag/Service": "another-app"}))
        self.assertFalse(allowed(eni, eni_context, "ec2:DetachNetworkInterface"))

    def test_embedded_sources_are_exact_and_bash_valid(self):
        content = renderer.script()
        self.assertLess(len(content.encode()), 14000)
        start = content.index("\n", content.index("base64 --decode")) + 1
        encoded = content[start:content.index("\nBOOTSTRAP_ARCHIVE", start)]
        with tarfile.open(fileobj=io.BytesIO(base64.b64decode(encoded)), mode="r:gz") as archive:
            self.assertEqual(archive.getnames(), list(renderer.SOURCES))
            for member in archive:
                self.assertEqual(archive.extractfile(member).read(),
                                 (ROOT / "deploy/aws" / member.name).read_bytes())
        subprocess.run(["bash", "-n"], input=content, text=True, check=True)
        subprocess.run(["bash", "-n", str(ROOT / "deploy/aws/bootstrap-production.sh")], check=True)

    def test_generated_template_current_and_preflight_before_database_writes(self):
        template = (ROOT / "deploy/aws/production.yaml").read_text()
        self.assertEqual(template, renderer.render(template))
        bootstrap = (ROOT / "deploy/aws/bootstrap-production.sh").read_text()
        self.assertLess(bootstrap.index("direct-ingress.py preflight"), bootstrap.index("configure_database()"))
        self.assertIn("iam-scoped-auth-init", bootstrap)
        self.assertIn("IAM_HONEYCOMB_SCHEDULED_TESTING", bootstrap)
        self.assertIn("IAM_HONEYCOMB_RETIRE_LEGACY_WRITERS", bootstrap)


if __name__ == "__main__":
    unittest.main()
