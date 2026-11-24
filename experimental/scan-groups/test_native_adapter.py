"""Native manager adapter contract tests for the isolated proposal."""

import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree as ET

import controller
from test_controller import (ASSET, CONFIG, OVERRIDE, SCANNER, SixHostGmp,
                             TARGET, TARGET_B)


PARENT = str(uuid.UUID(int=500))


class NativeGmp:
    def __init__(self):
        self.targets = []
        self.members = []
        self.mode = None
        self.run_state = "new"
        self.starts = []

    def send_command(self, xml):
        root = ET.fromstring(xml)
        if root.tag == "create_target":
            self.targets.append(root.findtext("hosts"))
            return (f'<create_target_response status="201" '
                    f'id="{uuid.UUID(int=len(self.targets))}"/>')
        if root.tag == "create_multi_target_task":
            self.mode = root.get("mode")
            self.members = [(target.get("source_target_id"), target.get("id"),
                             str(uuid.UUID(int=100 + i)))
                            for i, target in enumerate(root.findall("target"))]
            return f'<create_multi_target_task_response status="201" id="{PARENT}"/>'
        if root.tag == "get_multi_target_tasks":
            assert root.get("task_id") == PARENT
            children = "".join(
                f'<child ordinal="{i}" source_target_id="{source}" '
                f'target_id="{target}" task_id="{task}" '
                f'state="{"done" if self.run_state == "done" else "canceled" if self.run_state == "stopped" else "new"}" '
                f'report_id="{uuid.UUID(int=200 + i) if self.run_state == "done" else ""}"/>'
                for i, (source, target, task) in enumerate(self.members))
            return (f'<get_multi_target_tasks_response status="200">'
                    f'<multi_target_task id="{PARENT}" run_state="{self.run_state}">'
                    f'{children}</multi_target_task></get_multi_target_tasks_response>')
        raise AssertionError(root.tag)

    def start_task(self, task_id):
        self.starts.append(task_id)
        self.run_state = "queued"
        return '<start_task_response status="202"/>'

    def stop_task(self, task_id):
        self.run_state = "stopped"
        return '<stop_task_response status="202"/>'


class NativeAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = patch.object(controller, "DB", Path(self.tmp.name) / "groups.sqlite")
        self.backend = patch.object(controller, "NATIVE_BACKEND", True)
        self.db.start()
        self.backend.start()
        controller.init_db()

    def tearDown(self):
        self.backend.stop()
        self.db.stop()
        self.tmp.cleanup()

    def plan(self, *, override):
        request = {"name": "Native test", "target_ids": [TARGET, TARGET_B],
                   "config_id": CONFIG, "scanner_id": SCANNER, "overrides": []}
        saved = ({"asset_id": ASSET, "service": "ssh",
                  "credential_id": OVERRIDE},) if override else ()
        return controller.build_plan(SixHostGmp(), request, saved_overrides=saved)

    def test_two_targets_create_two_native_children(self):
        gmp = NativeGmp()
        group = controller.create_group(gmp, self.plan(override=False))
        self.assertEqual(gmp.mode, "targets")
        self.assertEqual(gmp.targets, ["192.0.2.1,192.0.2.2,192.0.2.3",
                                       "192.0.2.4,192.0.2.5,192.0.2.6"])
        self.assertEqual(len(group["children"]), 2)
        self.assertEqual(controller.group_summary(
            gmp, controller.group_by_id(group["id"]))["status"], "New")
        controller.start_group(gmp, controller.group_by_id(group["id"]))
        self.assertEqual(gmp.starts, [PARENT])
        controller.stop_group(gmp, controller.group_by_id(group["id"]))
        stopped = controller.group_summary(gmp, controller.group_by_id(group["id"]))
        self.assertEqual([child["status"] for child in stopped["children"]],
                         ["Stopped", "Stopped"])

    def test_one_override_creates_three_native_children(self):
        gmp = NativeGmp()
        group = controller.create_group(gmp, self.plan(override=True))
        self.assertEqual(gmp.mode, "overrides")
        self.assertEqual(gmp.targets, ["192.0.2.1,192.0.2.2", "192.0.2.3",
                                       "192.0.2.4,192.0.2.5,192.0.2.6"])
        self.assertEqual(len(group["children"]), 3)
        gmp.run_state = "done"
        summary = controller.group_summary(gmp, controller.group_by_id(group["id"]))
        self.assertEqual(summary["status"], "Done")
        self.assertEqual(summary["report_count"], 3)
        with controller.database() as db:
            row = db.execute("SELECT report_state FROM groups WHERE id=?",
                             (group["id"],)).fetchone()
        self.assertEqual(row[0], "ready")


if __name__ == "__main__":
    unittest.main()
