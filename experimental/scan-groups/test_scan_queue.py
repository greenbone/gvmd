"""Durable admission and recovery tests for experimental child scans."""

import tempfile
import unittest
import uuid
import json
import sqlite3
from pathlib import Path

import controller

SCANNER = str(uuid.UUID(int=900))


class ScanGmp:
    def __init__(self):
        self.status = {}
        self.report = {}
        self.starts = []
        self.fail_after_accept = False
        self.fail_before_accept = False
        self.missing = set()
        self.unavailable = set()
        self.incomplete = set()

    def get_task(self, task_id):
        if task_id in self.missing:
            return '<get_tasks_response status="404" status_text="not found"/>'
        if task_id in self.unavailable:
            return '<get_tasks_response status="503" status_text="unavailable"/>'
        if task_id in self.incomplete:
            return '<get_tasks_response status="200"/>'
        status = self.status.get(task_id, "New")
        report = self.report.get(task_id)
        last = f'<last_report><report id="{report}"/></last_report>' if report else ""
        return (f'<get_tasks_response status="200"><task id="{task_id}">'
                f'<status>{status}</status>{last}</task></get_tasks_response>')

    def start_task(self, task_id):
        self.starts.append(task_id)
        if self.fail_before_accept:
            raise RuntimeError("reply lost before GMP accepted the start")
        report = str(uuid.UUID(int=1000 + len(self.starts)))
        self.report[task_id] = report
        self.status[task_id] = "Requested"
        if self.fail_after_accept:
            raise RuntimeError("reply lost after GMP accepted the start")
        return (f'<start_task_response status="202"><report_id>{report}'
                '</report_id></start_task_response>')

    def stop_task(self, task_id):
        self.status[task_id] = "Stopped"
        return '<stop_task_response status="200"/>'

    def complete(self, task_id):
        self.status[task_id] = "Done"


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.original_db = controller.DB
        controller.DB = Path(self.directory.name) / "queue.sqlite"
        controller.init_db()
        self.gmp = ScanGmp()

    def tearDown(self):
        controller.DB = self.original_db
        self.directory.cleanup()

    def test_database_context_closes_connection(self):
        with controller.database() as db:
            self.assertEqual(db.execute("SELECT 1").fetchone()[0], 1)
        with self.assertRaises(sqlite3.ProgrammingError):
            db.execute("SELECT 1")

    def test_second_controller_cannot_claim_same_database(self):
        first = controller.claim_single_controller()
        try:
            with self.assertRaisesRegex(RuntimeError, "Another scan group controller"):
                controller.claim_single_controller()
        finally:
            first.close()
        second = controller.claim_single_controller()
        second.close()

    def group(self, number, count=2, scanner_id=SCANNER):
        group_id = str(uuid.UUID(int=number))
        children = [{"host": f"192.0.2.{number * 10 + i}",
                     "task_id": str(uuid.UUID(int=number * 100 + i)),
                     "target_id": str(uuid.UUID(int=number * 1000 + i))}
                    for i in range(1, count + 1)]
        controller.save_group(group_id, {"name": f"Group {number}",
                                         "scanner_id": scanner_id}, children,
                              str(uuid.UUID(int=number * 10000)))
        return group_id, [child["task_id"] for child in children]

    def test_queue_limits_and_round_robin(self):
        groups = [self.group(i) for i in (1, 2, 3)]
        for group_id, tasks in groups:
            result = controller.start_group(self.gmp, controller.group_by_id(group_id))
            self.assertEqual(result["queued"], tasks)
            summary = controller.group_summary(self.gmp, controller.group_by_id(group_id))
            self.assertEqual(summary["status"], "Queued")
            self.assertEqual(summary["children"][0]["status"], "Queued")
        self.assertEqual(self.gmp.starts, [])  # /start only persists the queue.
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp),
                         [groups[0][1][0], groups[1][1][0]])
        self.gmp.complete(groups[0][1][0])
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp),
                         [groups[2][1][0]])  # Fair to the untouched group.
        self.assertEqual(len(self.gmp.starts), 3)
        self.gmp.complete(groups[1][1][0])
        self.gmp.complete(groups[2][1][0])
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp),
                         [groups[0][1][1], groups[1][1][1]])

    def test_single_group_uses_idle_second_slot(self):
        group_id, tasks = self.group(33, count=4)
        controller.start_group(self.gmp, controller.group_by_id(group_id))
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp), [tasks[0]])
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp), [tasks[1]])
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp), [])
        self.assertEqual(len(controller.group_by_id(group_id)["run_state"]["inflight"]), 2)

    def test_later_group_takes_next_freed_slot(self):
        first_id, first_tasks = self.group(34, count=4)
        second_id, second_tasks = self.group(35, count=2)
        controller.start_group(self.gmp, controller.group_by_id(first_id))
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp), [first_tasks[0]])
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp), [first_tasks[1]])
        controller.start_group(self.gmp, controller.group_by_id(second_id))
        self.gmp.complete(first_tasks[0])
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp), [second_tasks[0]])
        self.assertEqual(len(controller.group_by_id(first_id)["run_state"]["inflight"]), 1)

    def test_stop_cancels_pending_before_dispatch(self):
        group_id, tasks = self.group(4)
        controller.start_group(self.gmp, controller.group_by_id(group_id))
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp), [tasks[0]])
        stopped = controller.stop_group(self.gmp, controller.group_by_id(group_id))
        self.assertEqual(stopped["stopped"], [tasks[0]])
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp), [])
        self.assertEqual(self.gmp.starts, [tasks[0]])
        self.assertEqual(controller.group_by_id(group_id)["run_state"]["state"], "stopped")

    def test_queued_summary_does_not_poll_native_tasks(self):
        group_id, tasks = self.group(5, count=2)
        controller.start_group(self.gmp, controller.group_by_id(group_id))

        class NoNativeReads:
            def get_task(self, _task_id):
                raise AssertionError("Queued scans must not be polled")

        summary = controller.group_summary(
            NoNativeReads(), controller.group_by_id(group_id))
        self.assertEqual(summary["status"], "Queued")
        self.assertEqual([child["status"] for child in summary["children"]],
                         ["Queued", "Queued"])
        self.assertEqual([child["task_id"] for child in summary["children"]], tasks)

    def test_terminal_run_reports_done_and_allows_restart(self):
        group_id, tasks = self.group(6, count=1)
        controller.start_group(self.gmp, controller.group_by_id(group_id))
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp), tasks)
        self.gmp.complete(tasks[0])
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp), [])
        self.assertEqual(controller.group_by_id(group_id)["run_state"]["state"], "done")
        self.assertEqual(controller.group_summary(
            self.gmp, controller.group_by_id(group_id))["status"], "Done")
        self.assertEqual(controller.start_group(
            self.gmp, controller.group_by_id(group_id))["queued"], tasks)

    def test_scanner_limit_is_independent_of_global_limit(self):
        groups = [self.group(i, count=1, scanner_id=SCANNER if i < 10 else
                             str(uuid.UUID(int=901))) for i in (7, 8, 9, 10)]
        original = controller.MAX_GLOBAL_ACTIVE_CHILDREN
        try:
            controller.MAX_GLOBAL_ACTIVE_CHILDREN = 3
            self.assertEqual([controller.start_group(
                self.gmp, controller.group_by_id(group_id))["queued"]
                for group_id, _ in groups], [tasks for _, tasks in groups])
            self.assertEqual(controller.dispatch_scan_queue_once(self.gmp),
                             [groups[0][1][0], groups[1][1][0], groups[3][1][0]])
        finally:
            controller.MAX_GLOBAL_ACTIVE_CHILDREN = original

    def test_legacy_active_run_consumes_capacity(self):
        legacy_id, legacy_tasks = self.group(11, count=1)
        self.gmp.status[legacy_tasks[0]] = "Running"
        self.gmp.report[legacy_tasks[0]] = str(uuid.UUID(int=2000))
        controller.save_run_state(legacy_id, {
            "id": str(uuid.uuid4()), "state": "active",
            "reports": {legacy_tasks[0]: self.gmp.report[legacy_tasks[0]]},
            "failed": []})
        groups = [self.group(i, count=1) for i in (12, 13)]
        for group_id, _ in groups:
            controller.start_group(self.gmp, controller.group_by_id(group_id))
        self.assertEqual(len(controller.dispatch_scan_queue_once(self.gmp)), 1)
        self.assertEqual(len(self.gmp.starts), 1)

    def test_duplicate_start_does_not_replace_queued_run(self):
        group_id, tasks = self.group(14)
        controller.start_group(self.gmp, controller.group_by_id(group_id))
        with self.assertRaisesRegex(controller.ReviewError, "queued or active"):
            controller.start_group(self.gmp, controller.group_by_id(group_id))
        self.assertEqual(controller.group_by_id(group_id)["run_state"]["pending"], tasks)

    def test_outstanding_backlog_cap_blocks_start(self):
        first_id, _ = self.group(1, count=64)
        group_id, _ = self.group(2, count=1)
        controller.start_group(self.gmp, controller.group_by_id(first_id))
        with self.assertRaisesRegex(controller.ReviewError, "Outstanding scan safety limit"):
            controller.start_group(self.gmp, controller.group_by_id(group_id))
        self.assertEqual(controller.outstanding_child_count(), 64)

    def test_confirmed_missing_inflight_releases_capacity(self):
        groups = [self.group(i, count=1) for i in (21, 22, 23)]
        for group_id, _ in groups:
            controller.start_group(self.gmp, controller.group_by_id(group_id))
        self.assertEqual(len(controller.dispatch_scan_queue_once(self.gmp)), 2)
        self.gmp.missing.update(tasks[0] for _, tasks in groups[:2])
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp),
                         [groups[2][1][0]])
        for group_id, _ in groups[:2]:
            run = controller.group_by_id(group_id)["run_state"]
            self.assertEqual(run["state"], "failed")
            self.assertEqual(run["inflight"], [])

    def test_transient_gmp_failure_retains_capacity(self):
        groups = [self.group(i, count=1) for i in (24, 25, 26)]
        for group_id, _ in groups:
            controller.start_group(self.gmp, controller.group_by_id(group_id))
        self.assertEqual(len(controller.dispatch_scan_queue_once(self.gmp)), 2)
        self.gmp.unavailable.add(groups[0][1][0])
        self.gmp.incomplete.add(groups[1][1][0])
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp), [])
        self.assertEqual(len(self.gmp.starts), 2)

    def test_ambiguous_new_status_holds_capacity_until_verified_missing(self):
        groups = [self.group(i, count=1) for i in (27, 28, 29)]
        for group_id, _ in groups:
            controller.start_group(self.gmp, controller.group_by_id(group_id))
        self.gmp.fail_before_accept = True
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp), [])
        self.gmp.fail_before_accept = False
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp), [])
        self.assertEqual(len(self.gmp.starts), 2)
        self.gmp.missing.add(groups[0][1][0])
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp),
                         [groups[2][1][0]])

    def test_legacy_failed_partial_run_still_occupies_capacity(self):
        legacy_id, legacy_tasks = self.group(30, count=2)
        self.gmp.status[legacy_tasks[0]] = "Running"
        self.gmp.report[legacy_tasks[0]] = str(uuid.UUID(int=3000))
        controller.save_run_state(legacy_id, {
            "id": str(uuid.uuid4()), "state": "starting",
            "reports": {legacy_tasks[0]: self.gmp.report[legacy_tasks[0]]},
            "failed": []})
        groups = [self.group(i, count=1) for i in (31, 32)]
        for group_id, _ in groups:
            controller.start_group(self.gmp, controller.group_by_id(group_id))
        self.assertEqual(len(controller.dispatch_scan_queue_once(self.gmp)), 1)
        self.assertEqual(controller.group_by_id(legacy_id)["run_state"]["state"], "failed")

    def test_create_requires_matching_preview_scan_count(self):
        plan = controller.with_plan_fingerprint({
            "name": "Two scans", "scan_units": [
                {"credentials": {"ssh": str(uuid.UUID(int=4000))}}, {}]})
        with self.assertRaisesRegex(controller.ReviewError, "expected_scan_count"):
            controller.require_expected_scan_count({}, plan)
        with self.assertRaisesRegex(controller.ReviewError, "expected_scan_count"):
            controller.require_expected_scan_count({"expected_scan_count": True}, plan)
        with self.assertRaises(controller.PlanChangedError):
            controller.require_expected_scan_count({"expected_scan_count": 3}, plan)
        body = {"expected_scan_count": 2,
                "expected_plan_fingerprint": plan["plan_fingerprint"]}
        controller.require_expected_scan_count(body, plan)
        changed = controller.with_plan_fingerprint({
            "name": "Two scans", "scan_units": [
                {"credentials": {"ssh": str(uuid.UUID(int=4001))}}, {}]})
        self.assertEqual(len(plan["scan_units"]), len(changed["scan_units"]))
        with self.assertRaises(controller.PlanChangedError):
            controller.require_expected_scan_count(body, changed)
        with self.assertRaisesRegex(controller.ReviewError, "expected_plan_fingerprint"):
            controller.require_expected_scan_count({"expected_scan_count": 2}, plan)

    def test_dispatch_index_migrates_old_groups_and_skips_history(self):
        with sqlite3.connect(controller.DB) as db:
            db.execute("DROP TABLE groups")
            db.execute("CREATE TABLE groups (id TEXT PRIMARY KEY, name TEXT NOT NULL, "
                       "plan TEXT NOT NULL, children TEXT NOT NULL, native_task_id TEXT, "
                       "native_error TEXT, run_state TEXT)")
            states = (None,
                      {"state": "done", "reports": {}, "failed": []},
                      {"state": "failed", "reports": {}, "failed": []},
                      {"state": "queued", "pending": [str(uuid.UUID(int=999))],
                       "inflight": [], "launching": None, "reports": {},
                       "failed": [], "last_dispatch": 0})
            for number, state in enumerate(states, start=1):
                db.execute("INSERT INTO groups VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (str(uuid.UUID(int=number)), f"Old {number}",
                            json.dumps({"name": f"Old {number}",
                                        "scanner_id": SCANNER}),
                            json.dumps([]), SCANNER, None,
                            json.dumps(state) if state else None))
        controller.init_db()
        self.assertEqual({group["id"] for group in controller.get_dispatch_groups()},
                         {str(uuid.UUID(int=3)), str(uuid.UUID(int=4))})
        with sqlite3.connect(controller.DB) as db:
            self.assertIn("groups_dispatch_state_idx",
                          [row[1] for row in db.execute("PRAGMA index_list(groups)")])
        controller.save_run_state(str(uuid.UUID(int=4)),
                                  {"state": "done", "pending": [], "inflight": [],
                                   "launching": None, "reports": {}, "failed": []})
        self.assertEqual([group["id"] for group in controller.get_dispatch_groups()],
                         [str(uuid.UUID(int=3))])

    def test_ambiguous_start_survives_restart_without_duplicate(self):
        group_id, tasks = self.group(5)
        controller.start_group(self.gmp, controller.group_by_id(group_id))
        self.gmp.fail_after_accept = True
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp), [])
        self.assertEqual(controller.group_by_id(group_id)["run_state"]["state"], "failed")
        self.gmp.fail_after_accept = False
        self.assertEqual(controller.dispatch_scan_queue_once(self.gmp), [])
        self.assertEqual(self.gmp.starts, [tasks[0]])
        run = controller.group_by_id(group_id)["run_state"]
        self.assertEqual(run["reports"][tasks[0]], self.gmp.report[tasks[0]])
        self.assertIsNone(run["launching"])
        self.assertEqual(run["pending"], [])

    def test_partition_cap_precedes_native_resource_creation(self):
        class NoCreation:
            def send_command(self, _):
                raise AssertionError("must reject before GMP resource creation")
        with self.assertRaisesRegex(controller.ReviewError, "17 background scans"):
            controller.create_group(NoCreation(), {"name": "Too many",
                                                    "units": [], "scan_units": [{}] * 17})


if __name__ == "__main__":
    unittest.main()
