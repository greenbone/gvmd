"""Focused failure, race, and lifecycle tests for native group reports."""
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

import controller

GROUP = '11111111-1111-4111-8111-111111111111'
CHILD = '22222222-2222-4222-8222-222222222222'
TARGET = '33333333-3333-4333-8333-333333333333'
LOGICAL = '44444444-4444-4444-8444-444444444444'
SOURCE = '55555555-5555-4555-8555-555555555555'
IMPORTED = '66666666-6666-4666-8666-666666666666'
SIGNATURE = 'a' * 64


class Gmp:
    report_status = 'Done'
    task_status = 'Done'
    response = f'<create_report_response status="201" id="{IMPORTED}"/>'

    def __init__(self):
        self.get_report_calls = 0
        self.sent = 0
        self.deleted = []

    def get_task(self, task_id):
        if task_id == LOGICAL:
            return (f'<get_tasks_response status="200"><task id="{task_id}">'
                    f'<status>{self.task_status}</status><last_report><report id="{IMPORTED}"/>'
                    '</last_report></task></get_tasks_response>')
        return (f'<get_tasks_response status="200"><task id="{task_id}">'
                f'<status>Done</status><last_report><report id="{SOURCE}"/>'
                '</last_report></task></get_tasks_response>')

    def get_report(self, report_id, **kwargs):
        self.get_report_calls += 1
        if report_id == IMPORTED:
            return (f'<get_reports_response status="200"><report id="{IMPORTED}">'
                    f'<scan_run_status>{self.report_status}</scan_run_status>'
                    '</report></get_reports_response>')
        return (f'<get_reports_response status="200"><report><report>'
                '<scan_start>2026-01-01T00:00:00Z</scan_start>'
                '<scan_end>2026-01-01T00:01:00Z</scan_end>'
                '<results></results></report></report></get_reports_response>')

    def get_results(self, *, filter_string, **kwargs):
        return ('<get_results_response status="200"><result_count>'
                '<filtered>0</filtered></result_count></get_results_response>')

    def send_command(self, command):
        self.sent += 1
        return self.response

    def delete_report(self, resource_id):
        self.deleted.append(('report', resource_id))
        return '<delete_report_response status="200"/>'

    def delete_task(self, resource_id, **kwargs):
        self.deleted.append(('task', resource_id))
        return '<delete_task_response status="200"/>'

    def delete_target(self, resource_id, **kwargs):
        self.deleted.append(('target', resource_id))
        return '<delete_target_response status="200"/>'


class Tests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.old_db = controller.DB
        controller.DB = Path(self.directory.name) / 'groups.sqlite'
        controller.init_db()
        children = [{'host': '192.0.2.1', 'hosts': ['192.0.2.1'],
                     'task_id': CHILD, 'target_id': TARGET}]
        controller.save_group(GROUP, {'name': 'Review', 'target_ids': [SOURCE],
                                      'scanner_id': SOURCE}, children, LOGICAL)

    def tearDown(self):
        controller.DB = self.old_db
        self.directory.cleanup()

    def group(self):
        return controller.group_by_id(GROUP)

    def add_import(self, state='pending', report_id=IMPORTED, next_attempt=None,
                   signature=SIGNATURE):
        with sqlite3.connect(controller.DB) as db:
            db.execute('INSERT INTO native_imports '
                       '(group_id,signature,report_id,expected_results,state,next_attempt) '
                       'VALUES (?,?,?,?,?,?)',
                       (GROUP, signature, report_id, 0, state,
                        next_attempt or int(time.time()) + 600))

    def test_index_and_managed_ids_ignore_idle_history(self):
        self.assertEqual(controller.get_report_candidates(), [])
        self.assertEqual(set(controller.managed_task_ids()['task_ids']), {CHILD, LOGICAL})
        self.assertEqual(controller.task_membership([CHILD, SOURCE, LOGICAL]),
                         {'managed_task_ids': [CHILD, LOGICAL]})
        self.assertEqual([group['id'] for group in
                          controller.get_groups_for_task_ids([CHILD, LOGICAL])],
                         [GROUP])
        self.assertEqual(controller.get_groups_for_task_ids([SOURCE]), [])
        with self.assertRaisesRegex(controller.ReviewError, 'at most 100'):
            controller.task_membership([CHILD] * 101)
        with self.assertRaisesRegex(controller.ReviewError, 'at most 100'):
            controller.get_groups_for_task_ids([CHILD] * 101)
        controller.save_run_state(GROUP, {'state': 'done', 'reports': {CHILD: SOURCE}})
        self.assertEqual([x['id'] for x in controller.get_report_candidates()], [GROUP])
        with sqlite3.connect(controller.DB) as db:
            for suffix in ('2', '3'):
                db.execute("INSERT INTO groups (id,name,plan,children,report_state,report_due) "
                           "VALUES (?,?,?,?, 'ready', 0)",
                           (suffix * 8 + '-1111-4111-8111-111111111111',
                            'Old', '{}', '[]'))
        self.assertEqual([x['id'] for x in controller.get_report_candidates(limit=2)],
                         [GROUP])
        with sqlite3.connect(controller.DB) as db:
            db.execute("UPDATE groups SET report_state='idle' WHERE id=?", (GROUP,))
        self.assertEqual(controller.get_report_candidates(), [])

    def test_existing_groups_backfill_managed_task_index(self):
        with sqlite3.connect(controller.DB) as db:
            db.execute('DROP TABLE managed_tasks')
        controller.init_db()
        self.assertEqual(set(controller.managed_task_ids()['task_ids']),
                         {CHILD, LOGICAL})

    def test_processing_reservation_survives_run_update_and_blocks_actions(self):
        with sqlite3.connect(controller.DB) as db:
            db.execute("UPDATE groups SET report_state='processing' WHERE id=?", (GROUP,))
        controller.save_run_state(GROUP, {'state': 'done', 'reports': {CHILD: SOURCE}})
        with sqlite3.connect(controller.DB) as db:
            self.assertEqual(db.execute('SELECT report_state FROM groups').fetchone()[0], 'processing')
        with self.assertRaises(controller.GroupConflictError):
            controller.start_group(Gmp(), self.group())
        with self.assertRaises(controller.GroupConflictError):
            controller.delete_group(Gmp(), self.group())

    def test_slow_import_remains_pending_after_deadline(self):
        self.add_import(next_attempt=int(time.time()) - 100)
        gmp = Gmp()
        gmp.task_status = 'Running'
        outcome = controller.reconcile_import(gmp, self.group(), SIGNATURE,
                                               controller.import_attempt(GROUP, SIGNATURE))
        self.assertEqual(outcome['state'], 'pending')
        self.assertEqual(controller.import_attempt(GROUP, SIGNATURE)['state'], 'pending')
        self.assertEqual(gmp.deleted, [])

    def test_import_requires_own_report_done_and_result_count(self):
        self.add_import()
        gmp = Gmp()
        gmp.report_status = 'Running'
        self.assertEqual(controller.reconcile_import(gmp, self.group(), SIGNATURE,
                         controller.import_attempt(GROUP, SIGNATURE))['state'], 'pending')
        with sqlite3.connect(controller.DB) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM native_reports').fetchone()[0], 0)
        gmp.report_status = 'Done'
        self.assertEqual(controller.reconcile_import(gmp, self.group(), SIGNATURE,
                         controller.import_attempt(GROUP, SIGNATURE))['state'], 'complete')
        with sqlite3.connect(controller.DB) as db:
            self.assertEqual(db.execute('SELECT report_id FROM native_reports').fetchone()[0], IMPORTED)
            self.assertEqual(db.execute('SELECT count(*) FROM native_imports').fetchone()[0], 0)

    def test_interrupted_import_retries_once_then_publishes(self):
        gmp = Gmp()
        signature = controller.report_signature(controller.group_summary(gmp, self.group()))
        self.add_import(signature=signature)
        gmp.task_status = 'Interrupted'
        self.assertEqual(controller.reconcile_import(gmp, self.group(), signature,
                         controller.import_attempt(GROUP, signature))['state'], 'failed')
        gmp.task_status = 'Done'
        outcome = controller.publish_native_report(gmp, self.group(), manual=True)
        self.assertEqual(outcome['state'], 'pending')
        self.assertEqual(gmp.deleted, [('report', IMPORTED)])
        self.assertEqual(gmp.sent, 1)
        self.assertEqual(controller.reconcile_import(gmp, self.group(), signature,
                         controller.import_attempt(GROUP, signature))['state'], 'complete')
        self.assertEqual(gmp.sent, 1)

    def test_missing_scan_times_backoff_and_no_refetch(self):
        class MissingTimes(Gmp):
            def get_report(self, report_id, **kwargs):
                self.get_report_calls += 1
                return ('<get_reports_response status="200"><report><report>'
                        '<results></results></report></report></get_reports_response>')
        gmp = MissingTimes()
        with self.assertRaisesRegex(controller.ReviewError, 'scan times'):
            controller.publish_native_report(gmp, self.group())
        count = gmp.get_report_calls
        self.assertEqual(controller.publish_native_report(gmp, self.group())['state'], 'blocked')
        self.assertEqual(gmp.get_report_calls, count)

    def test_report_import_rejects_result_without_host_metadata(self):
        class MissingHost(Gmp):
            def get_results(self, **kwargs):
                return ('<get_results_response status="200"><result_count>'
                        '<filtered>1</filtered></result_count></get_results_response>')

            def get_report(self, report_id, **kwargs):
                return ('<get_reports_response status="200"><report><report>'
                        '<scan_start>2026-01-01T00:00:00Z</scan_start>'
                        '<scan_end>2026-01-01T00:01:00Z</scan_end>'
                        '<results><result><host>192.0.2.1</host></result></results>'
                        '</report></report></get_reports_response>')

        gmp = MissingHost()
        with self.assertRaisesRegex(controller.ReviewError, 'host metadata'):
            controller.publish_native_report(gmp, self.group())
        self.assertEqual(gmp.sent, 0)

    def test_source_report_pages_and_xml_limit(self):
        class Paged(Gmp):
            firsts = []
            def get_report(self, report_id, **kwargs):
                filter_string = kwargs['filter_string']
                first = int(filter_string.split('first=')[1].split()[0])
                rows = int(filter_string.split('rows=')[1].split()[0])
                self.firsts.append(first)
                results = ''.join(f'<result><host>192.0.2.1</host></result>'
                                  for _ in range(min(rows, 4 - first)))
                return ('<get_reports_response status="200"><report><report>'
                        f'<results>{results}</results></report></report>'
                        '</get_reports_response>')
        old_page = controller.NATIVE_REPORT_PAGE_SIZE
        old_limit = controller.NATIVE_REPORT_XML_LIMIT
        try:
            controller.NATIVE_REPORT_PAGE_SIZE = 2
            gmp = Paged()
            page = controller.paged_source_report(gmp, {'report_id': SOURCE}, 3)
            self.assertEqual(len(page.findall('./results/result')), 3)
            self.assertEqual(gmp.firsts, [1, 3])
            controller.NATIVE_REPORT_XML_LIMIT = 50
            with self.assertRaisesRegex(controller.ReviewError, '25 MiB'):
                controller.paged_source_report(Paged(), {'report_id': SOURCE}, 3)
        finally:
            controller.NATIVE_REPORT_PAGE_SIZE = old_page
            controller.NATIVE_REPORT_XML_LIMIT = old_limit

    def test_definitive_rejection_vs_ambiguous_success(self):
        gmp = Gmp()
        gmp.response = '<create_report_response status="400" status_text="Rejected"/>'
        with self.assertRaisesRegex(controller.ReviewError, 'rejected'):
            controller.publish_native_report(gmp, self.group())
        self.assertEqual(controller.import_attempt(GROUP,
            controller.report_signature(controller.group_summary(gmp, self.group())))['state'], 'failed')
        gmp2 = Gmp()
        gmp2.response = '<create_report_response status="201"/>'
        with self.assertRaises(controller.ReviewError):
            controller.publish_native_report(gmp2, self.group(), manual=True)
        signature = controller.report_signature(controller.group_summary(gmp2, self.group()))
        self.assertEqual(controller.import_attempt(GROUP, signature)['state'], 'creating')
        with self.assertRaises(controller.GroupConflictError):
            controller.delete_group(gmp2, self.group())

    def test_delete_preserves_source_target_and_blocks_pending_import(self):
        gmp = Gmp()
        self.add_import()
        with self.assertRaises(controller.GroupConflictError):
            controller.delete_group(gmp, self.group())
        with sqlite3.connect(controller.DB) as db:
            db.execute("UPDATE native_imports SET state='failed' WHERE group_id=?", (GROUP,))
        self.assertEqual(controller.delete_group(gmp, self.group()), {'deleted': True})
        self.assertEqual(controller.managed_task_ids()['task_ids'], [])
        self.assertIn(('target', TARGET), gmp.deleted)
        self.assertNotIn(('target', SOURCE), gmp.deleted)
        with sqlite3.connect(controller.DB) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM groups').fetchone()[0], 0)

    def test_partial_delete_failure_keeps_group_for_retry(self):
        class FailingGmp(Gmp):
            def delete_task(self, resource_id, **kwargs):
                raise RuntimeError('gvmd unavailable')
        with self.assertRaisesRegex(RuntimeError, 'unavailable'):
            controller.delete_group(FailingGmp(), self.group())
        self.assertEqual(self.group()['id'], GROUP)
        self.assertEqual(controller.delete_group(Gmp(), self.group()), {'deleted': True})

    def test_ambiguous_import_recovery_requires_native_task_removal(self):
        self.add_import(state='creating', report_id=None)
        with sqlite3.connect(controller.DB) as db:
            db.execute('UPDATE native_imports SET previous_report_id=? WHERE group_id=?',
                       (IMPORTED, GROUP))
        with self.assertRaisesRegex(controller.GroupConflictError, 'delete the logical'):
            controller.recover_group(Gmp(), self.group())
        self.assertEqual(controller.import_attempt(GROUP, SIGNATURE)['state'], 'creating')

        class RemovedGmp(Gmp):
            def get_task(self, task_id):
                if task_id == LOGICAL:
                    return '<get_tasks_response status="404"/>'
                return super().get_task(task_id)
        gmp = RemovedGmp()
        with self.assertRaisesRegex(controller.GroupConflictError, 'recreate'):
            controller.recover_group(gmp, self.group())
        self.assertEqual(controller.import_attempt(GROUP, SIGNATURE)['state'], 'blocked')
        self.assertEqual(controller.delete_group(gmp, self.group()), {'deleted': True})

    def test_terminal_ambiguous_child_releases_held_slot(self):
        controller.save_run_state(GROUP, {
            'state': 'failed', 'reports': {}, 'pending': [], 'inflight': [CHILD],
            'launching': {'task_id': CHILD, 'previous_report': None},
            'failed': [{'task_id': CHILD, 'error': 'start response lost'}]})
        self.assertEqual(controller.recover_group(Gmp(), self.group()),
                         {'recovered': True, 'state': 'stopped'})
        state = self.group()['run_state']
        self.assertEqual(state['inflight'], [])
        self.assertIsNone(state['launching'])

    def test_old_report_does_not_clear_ambiguous_child_start(self):
        controller.save_run_state(GROUP, {
            'state': 'failed', 'reports': {}, 'pending': [], 'inflight': [CHILD],
            'launching': {'task_id': CHILD, 'previous_report': SOURCE},
            'failed': [{'task_id': CHILD, 'error': 'start response lost'}]})
        with self.assertRaisesRegex(controller.GroupConflictError, 'uncertain'):
            controller.recover_group(Gmp(), self.group())
        self.assertEqual(self.group()['run_state']['inflight'], [CHILD])


if __name__ == '__main__':
    unittest.main()
