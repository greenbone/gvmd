"""Contract tests for the multi-target-only review service."""

import tempfile
import unittest
import uuid
from pathlib import Path
from xml.etree import ElementTree as ET

import controller

TARGET_A = "11111111-1111-4111-8111-111111111111"
TARGET_B = "11111111-1111-4111-8111-111111111112"
PORTS = "22222222-2222-4222-8222-222222222222"
CREDENTIAL = "33333333-3333-4333-8333-333333333333"
CONFIG = "55555555-5555-4555-8555-555555555555"
SCANNER = "66666666-6666-4666-8666-666666666666"


class FakeGmp:
    def get_targets(self, **_):
        return '<get_targets_response status="200"/>'

    def get_credentials(self, **_):
        return '<get_credentials_response status="200"/>'

    def get_scan_configs(self, **_):
        return f'<get_configs_response status="200"><config id="{CONFIG}"/></get_configs_response>'

    def get_scanners(self, **_):
        return f'<get_scanners_response status="200"><scanner id="{SCANNER}"/></get_scanners_response>'

    def get_target(self, target_id):
        hosts = "192.0.2.1,192.0.2.2,192.0.2.3" if target_id == TARGET_A else "192.0.2.4,192.0.2.5,192.0.2.6"
        return (f'<get_targets_response status="200"><target id="{target_id}">'
                f'<name>{"A" if target_id == TARGET_A else "B"}</name>'
                f'<hosts>{hosts}</hosts><port_list id="{PORTS}"/>'
                f'<ssh_credential id="{CREDENTIAL}"><port>22</port></ssh_credential>'
                '</target></get_targets_response>')


class Tests(unittest.TestCase):
    def request(self):
        return {"name": "Six hosts", "target_ids": [TARGET_A, TARGET_B],
                "config_id": CONFIG, "scanner_id": SCANNER}

    def test_six_hosts_are_two_scan_units(self):
        plan = controller.build_plan(FakeGmp(), self.request())
        self.assertEqual(len(plan["units"]), 6)
        self.assertEqual([unit["hosts"] for unit in plan["scan_units"]],
                         [["192.0.2.1", "192.0.2.2", "192.0.2.3"], ["192.0.2.4", "192.0.2.5", "192.0.2.6"]])
        targets = [ET.fromstring(controller.target_xml("group", unit))
                   for unit in plan["scan_units"]]
        self.assertEqual([target.findtext("hosts") for target in targets],
                         ["192.0.2.1,192.0.2.2,192.0.2.3", "192.0.2.4,192.0.2.5,192.0.2.6"])
        self.assertTrue(all(target.find("ssh_credential").get("id") == CREDENTIAL
                            for target in targets))

    def test_override_request_is_rejected_in_this_tier(self):
        request = self.request()
        request["overrides"] = [{"host": "192.0.2.3", "service": "ssh", "credential_id": CREDENTIAL}]
        with self.assertRaisesRegex(controller.ReviewError, "combined feature tier"):
            controller.build_plan(FakeGmp(), request)

    def test_create_group_creates_two_children(self):
        class CreatingGmp:
            targets = []
            tasks = []

            def send_command(self, command):
                self.targets.append(ET.fromstring(command).findtext("hosts"))
                return (f'<create_target_response status="201" '
                        f'id="{uuid.UUID(int=len(self.targets))}"/>')

            def create_task(self, **kwargs):
                self.tasks.append(kwargs)
                return (f'<create_task_response status="201" '
                        f'id="{uuid.UUID(int=100 + len(self.tasks))}"/>')

        plan = controller.build_plan(FakeGmp(), self.request())
        gmp = CreatingGmp()
        original_db = controller.DB
        original_create_native_task = controller.create_native_task
        with tempfile.TemporaryDirectory() as directory:
            controller.DB = Path(directory) / "groups.sqlite"
            controller.create_native_task = lambda *_: SCANNER
            try:
                controller.init_db()
                group = controller.create_group(gmp, plan)
                self.assertEqual(len(group["children"]), 2)
                self.assertEqual(gmp.targets, ["192.0.2.1,192.0.2.2,192.0.2.3", "192.0.2.4,192.0.2.5,192.0.2.6"])
                self.assertEqual(len(gmp.tasks), 2)
            finally:
                controller.DB = original_db
                controller.create_native_task = original_create_native_task


if __name__ == "__main__":
    unittest.main()
