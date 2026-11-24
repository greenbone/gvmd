"""Operator-only membership lookup for generated scan tasks."""

import tempfile
import unittest
import uuid
from pathlib import Path

import controller

GROUP = "11111111-1111-4111-8111-111111111111"
CHILD = "22222222-2222-4222-8222-222222222222"
LOGICAL = "33333333-3333-4333-8333-333333333333"
ORDINARY = "44444444-4444-4444-8444-444444444444"


class MembershipTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.original_db = controller.DB
        controller.DB = Path(self.directory.name) / "groups.sqlite"
        controller.init_db()
        controller.save_group(
            GROUP, {"name": "Review"},
            [{"host": "192.0.2.1", "task_id": CHILD,
              "target_id": str(uuid.uuid4())}], LOGICAL)

    def tearDown(self):
        controller.DB = self.original_db
        self.directory.cleanup()

    def test_mixed_batch_returns_only_managed_tasks(self):
        self.assertEqual(controller.task_membership(
            [ORDINARY, LOGICAL, CHILD, ORDINARY]),
            {"managed_task_ids": [CHILD, LOGICAL]})

    def test_empty_batch(self):
        self.assertEqual(controller.task_membership([]),
                         {"managed_task_ids": []})

    def test_invalid_ids_and_excessive_batch_rejected(self):
        with self.assertRaises(controller.ReviewError):
            controller.task_membership(["../../bad"])
        with self.assertRaises(controller.ReviewError):
            controller.task_membership([CHILD] * 101)


if __name__ == "__main__":
    unittest.main()
