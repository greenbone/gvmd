import io
import socket
import socketserver
import sqlite3
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from xml.etree import ElementTree as ET

import controller


TARGET = "11111111-1111-4111-8111-111111111111"
TARGET_B = "11111111-1111-4111-8111-111111111112"
PORTS = "22222222-2222-4222-8222-222222222222"
DEFAULT = "33333333-3333-4333-8333-333333333333"
OVERRIDE = "44444444-4444-4444-8444-444444444444"
CONFIG = "55555555-5555-4555-8555-555555555555"
SCANNER = "66666666-6666-4666-8666-666666666666"
ASSET = "77777777-7777-4777-8777-777777777777"
ASSET_DUPLICATE = "77777777-7777-4777-8777-777777777778"
UNRELATED_ASSET = "77777777-7777-4777-8777-777777777779"
TASK_A = "88888888-8888-4888-8888-888888888888"
TASK_B = "99999999-9999-4999-8999-999999999999"
REPORT_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
REPORT_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


class FakeGmp:
    def get_targets(self, **_):
        return f'<get_targets_response status="200"><target id="{TARGET}"><name>Source</name><hosts>192.0.2.1,192.0.2.55</hosts></target></get_targets_response>'

    def get_target(self, target_id):
        assert target_id == TARGET
        return f'''<get_targets_response status="200"><target id="{TARGET}">
          <name>Source</name><hosts>192.0.2.1,192.0.2.55</hosts>
          <port_list id="{PORTS}"/><ssh_credential id="{DEFAULT}"><port>2222</port></ssh_credential>
          <smb_credential id=""/></target></get_targets_response>'''

    def get_credentials(self, **_):
        return f'<get_credentials_response status="200"><credential id="{DEFAULT}"><name>B</name></credential><credential id="{OVERRIDE}"><name>A</name></credential></get_credentials_response>'

    def get_scan_configs(self, **_):
        return f'<get_configs_response status="200"><config id="{CONFIG}"><name>Full</name></config></get_configs_response>'

    def get_scanners(self, **_):
        return f'<get_scanners_response status="200"><scanner id="{SCANNER}"><name>OpenVAS</name></scanner></get_scanners_response>'

    def get_hosts(self, **_):
        return f'<get_assets_response status="200"><asset id="{ASSET}"><name>192.0.2.55</name><identifiers><identifier><name>ip</name><value>192.0.2.55</value></identifier></identifiers></asset></get_assets_response>'


class DuplicateAssetGmp(FakeGmp):
    def get_hosts(self, **_):
        return (f'<get_assets_response status="200">'
                f'<asset id="{ASSET}"><name>192.0.2.55</name></asset>'
                f'<asset id="{ASSET_DUPLICATE}"><name>192.0.2.55</name></asset>'
                f'<asset id="{UNRELATED_ASSET}"><name>192.0.2.99</name></asset>'
                '</get_assets_response>')


class SixHostGmp(FakeGmp):
    def get_target(self, target_id):
        if target_id == TARGET:
            hosts = "192.0.2.1,192.0.2.2,192.0.2.3"
        else:
            assert target_id == TARGET_B
            hosts = "192.0.2.4,192.0.2.5,192.0.2.6"
        return (f'<get_targets_response status="200"><target id="{target_id}">'
                f'<name>{"A" if target_id == TARGET else "B"}</name>'
                f'<hosts>{hosts}</hosts><port_list id="{PORTS}"/>'
                f'<ssh_credential id="{DEFAULT}"><port>22</port></ssh_credential>'
                '</target></get_targets_response>')

    def get_hosts(self, **_):
        return (f'<get_assets_response status="200"><asset id="{ASSET}">'
                '<name>192.0.2.3</name></asset></get_assets_response>')


class FakeReportGmp:
    def get_task(self, task_id):
        report_id = REPORT_A if task_id == TASK_A else REPORT_B
        return (f'<get_tasks_response status="200"><task id="{task_id}">'
                f'<status>Done</status><last_report><report id="{report_id}"/>'
                '</last_report></task></get_tasks_response>')

    def get_results(self, *, filter_string, details):
        import re
        report_id = re.search(r'report_id=([\w-]+)', filter_string).group(1)
        first = int(re.search(r'first=(\d+)', filter_string).group(1))
        rows = int(re.search(r'rows=(\d+)', filter_string).group(1))
        host = '192.0.2.1' if report_id == REPORT_A else '192.0.2.2'
        names = ['A1', 'A2'] if report_id == REPORT_A else ['B1']
        page = names[first - 1:first - 1 + rows]
        results = ''.join(
            f'<result id="{index + 1:08d}-1111-4111-8111-111111111111">'
            f'<name>{name}</name><host>{host}</host><severity>5.0</severity>'
            f'<description>Evidence for {name}</description></result>'
            for index, name in enumerate(page, start=first - 1))
        return (f'<get_results_response status="200">{results}'
                f'<result_count><filtered>{len(names)}</filtered></result_count>'
                '</get_results_response>')


class ControllerTests(unittest.TestCase):
    def request(self):
        return {"name": "Review", "target_ids": [TARGET], "config_id": CONFIG,
                "scanner_id": SCANNER,
                "overrides": [{"host": "192.0.2.55", "asset_id": ASSET,
                               "service": "ssh", "credential_id": OVERRIDE}]}

    def test_override_is_confined_to_asset_host(self):
        plan = controller.build_plan(FakeGmp(), self.request())
        self.assertEqual(len(plan["units"]), 2)
        self.assertEqual(plan["units"][0]["credentials"]["ssh"], DEFAULT)
        self.assertEqual(plan["units"][1]["credentials"]["ssh"], OVERRIDE)
        root = ET.fromstring(controller.target_xml("group", plan["units"][1]))
        self.assertEqual(root.find("hosts").text, "192.0.2.55")
        self.assertEqual(root.find("ssh_credential").get("id"), OVERRIDE)
        self.assertEqual(root.find("ssh_credential/port").text, "2222")

    def test_scan_units_keep_source_targets_and_group_equal_credentials(self):
        request = {**self.request(), "target_ids": [TARGET, TARGET_B],
                   "overrides": []}
        no_override = controller.build_plan(SixHostGmp(), request)
        self.assertEqual(len(no_override["units"]), 6)
        self.assertEqual([unit["hosts"] for unit in no_override["scan_units"]],
                         [["192.0.2.1", "192.0.2.2", "192.0.2.3"],
                          ["192.0.2.4", "192.0.2.5", "192.0.2.6"]])

        saved = ({"asset_id": ASSET, "service": "ssh",
                  "credential_id": OVERRIDE},)
        with_override = controller.build_plan(SixHostGmp(), request,
                                              saved_overrides=saved)
        self.assertEqual([unit["hosts"] for unit in with_override["scan_units"]],
                         [["192.0.2.1", "192.0.2.2"], ["192.0.2.3"],
                          ["192.0.2.4", "192.0.2.5", "192.0.2.6"]])
        self.assertEqual([unit["id"] for unit in with_override["scan_units"]],
                         [TARGET, TARGET, TARGET_B])
        self.assertEqual([unit["credentials"]["ssh"]
                          for unit in with_override["scan_units"]],
                         [DEFAULT, OVERRIDE, DEFAULT])
        target = ET.fromstring(controller.target_xml(
            "group", with_override["scan_units"][0]))
        self.assertEqual(target.findtext("hosts"), "192.0.2.1,192.0.2.2")

    def test_create_group_creates_one_child_per_scan_unit(self):
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

        request = {**self.request(), "target_ids": [TARGET, TARGET_B],
                   "overrides": []}
        saved = ({"asset_id": ASSET, "service": "ssh",
                  "credential_id": OVERRIDE},)
        plan = controller.build_plan(SixHostGmp(), request,
                                     saved_overrides=saved)
        gmp = CreatingGmp()
        original_db = controller.DB
        original_create_native_task = controller.create_native_task
        with tempfile.TemporaryDirectory() as directory:
            controller.DB = Path(directory) / "groups.sqlite"
            controller.create_native_task = lambda *_: SCANNER
            try:
                controller.init_db()
                group = controller.create_group(gmp, plan)
                self.assertEqual(len(group["children"]), 3)
                self.assertEqual(gmp.targets,
                                 ["192.0.2.1,192.0.2.2", "192.0.2.3",
                                  "192.0.2.4,192.0.2.5,192.0.2.6"])
                self.assertEqual(len(gmp.tasks), 3)
                self.assertEqual(sum(len(child["hosts"])
                                     for child in group["children"]), 6)
            finally:
                controller.DB = original_db
                controller.create_native_task = original_create_native_task

    def test_saved_asset_override_applies_without_task_override(self):
        request = self.request()
        request["overrides"] = []
        saved = ({"asset_id": ASSET, "service": "ssh", "credential_id": OVERRIDE},)
        plan = controller.build_plan(FakeGmp(), request, saved_overrides=saved)
        self.assertEqual([unit["credentials"]["ssh"] for unit in plan["units"]],
                         [DEFAULT, OVERRIDE])

    def test_duplicate_assets_with_one_override_route_to_selected_host(self):
        request = self.request()
        request["overrides"] = []
        saved = ({"asset_id": ASSET, "service": "ssh", "credential_id": OVERRIDE},)
        plan = controller.build_plan(DuplicateAssetGmp(), request,
                                     saved_overrides=saved)
        self.assertEqual([unit["credentials"]["ssh"] for unit in plan["units"]],
                         [DEFAULT, OVERRIDE])

    def test_duplicate_assets_with_matching_overrides_are_allowed(self):
        request = self.request()
        request["overrides"] = []
        saved = ({"asset_id": ASSET, "service": "ssh", "credential_id": OVERRIDE},
                 {"asset_id": ASSET_DUPLICATE, "service": "ssh",
                  "credential_id": OVERRIDE})
        plan = controller.build_plan(DuplicateAssetGmp(), request,
                                     saved_overrides=saved)
        self.assertEqual(plan["units"][1]["credentials"]["ssh"], OVERRIDE)

    def test_duplicate_assets_with_conflicting_overrides_are_explained(self):
        request = self.request()
        request["overrides"] = []
        saved = ({"asset_id": ASSET, "service": "ssh", "credential_id": OVERRIDE},
                 {"asset_id": ASSET_DUPLICATE, "service": "ssh",
                  "credential_id": DEFAULT})
        with self.assertRaisesRegex(controller.ReviewError,
                                    "Conflicting asset overrides for 192.0.2.55/ssh"):
            controller.build_plan(DuplicateAssetGmp(), request,
                                  saved_overrides=saved)

    def test_unrelated_saved_override_does_not_block_plan(self):
        request = self.request()
        request["overrides"] = []
        saved = ({"asset_id": UNRELATED_ASSET, "service": "ssh",
                  "credential_id": "00000000-0000-4000-8000-000000000000"},)
        plan = controller.build_plan(DuplicateAssetGmp(), request,
                                     saved_overrides=saved)
        self.assertEqual(plan["units"][1]["credentials"]["ssh"], DEFAULT)

    def test_explicit_duplicate_asset_override_is_allowed(self):
        request = self.request()
        request["overrides"][0]["asset_id"] = ASSET_DUPLICATE
        plan = controller.build_plan(DuplicateAssetGmp(), request)
        self.assertEqual(plan["units"][1]["credentials"]["ssh"], OVERRIDE)

    def test_backend_mode_must_be_selected_for_enhanced_api(self):
        with self.assertRaisesRegex(controller.ReviewError, "multi-target mode"):
            controller.require_enhanced_mode({"backend_mode": "standard"})
        with self.assertRaisesRegex(controller.ReviewError, "multi-target mode"):
            controller.require_enhanced_mode({})
        with self.assertRaisesRegex(controller.ReviewError, "multi-target mode"):
            controller.require_enhanced_mode([])
        controller.require_enhanced_mode({"backend_mode": "enhanced"})

    def test_existing_override_migrates_and_can_be_paused(self):
        original_db = controller.DB
        with tempfile.TemporaryDirectory() as directory:
            controller.DB = Path(directory) / "groups.sqlite"
            try:
                with sqlite3.connect(controller.DB) as db:
                    db.execute("CREATE TABLE asset_overrides (asset_id TEXT NOT NULL, service TEXT NOT NULL, credential_id TEXT NOT NULL, PRIMARY KEY(asset_id, service))")
                    db.execute("INSERT INTO asset_overrides VALUES (?, ?, ?)",
                               (ASSET, "ssh", OVERRIDE))
                controller.init_db()
                self.assertTrue(controller.get_saved_overrides()[0]["enabled"])

                controller.set_asset_override_enabled(ASSET, "ssh", False)
                self.assertEqual(controller.get_saved_overrides(), ())
                paused = controller.get_saved_overrides(include_disabled=True)
                self.assertFalse(paused[0]["enabled"])
                request = self.request()
                request["overrides"] = []
                plan = controller.build_plan(FakeGmp(), request,
                                             saved_overrides=paused)
                self.assertEqual([unit["credentials"]["ssh"] for unit in plan["units"]],
                                 [DEFAULT, DEFAULT])

                controller.set_asset_override_enabled(ASSET, "ssh", True)
                plan = controller.build_plan(FakeGmp(), request,
                                             saved_overrides=controller.get_saved_overrides())
                self.assertEqual([unit["credentials"]["ssh"] for unit in plan["units"]],
                                 [DEFAULT, OVERRIDE])
            finally:
                controller.DB = original_db

    def test_asset_host_mismatch_rejected(self):
        request = self.request()
        request["overrides"][0]["host"] = "192.0.2.1"
        with self.assertRaisesRegex(controller.ReviewError, "does not identify"):
            controller.build_plan(FakeGmp(), request)

    def test_cidr_source_rejected(self):
        class CidrGmp(FakeGmp):
            def get_target(self, target_id):
                return super().get_target(target_id).replace("192.0.2.1,192.0.2.55", "192.0.2.0/24")
        with self.assertRaisesRegex(controller.ReviewError, "explicit IPs"):
            controller.build_plan(CidrGmp(), self.request())

    def test_dns_source_rejected_before_credentials_are_routed(self):
        class DnsGmp(FakeGmp):
            def get_target(self, target_id):
                return super().get_target(target_id).replace(
                    "192.0.2.1,192.0.2.55", "scan.example.test,192.0.2.55")

        with self.assertRaisesRegex(controller.ReviewError, "DNS source host"):
            controller.build_plan(DnsGmp(), self.request())

    def test_unix_socket_serves_http_responses(self):
        original = controller.TRUST_GSA_PROXY
        try:
            controller.TRUST_GSA_PROXY = True
            with tempfile.TemporaryDirectory() as directory:
                path = str(Path(directory) / "controller.sock")
                with socketserver.ThreadingUnixStreamServer(path, controller.Handler) as server:
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    for header, expected in (("", b" 401 "),
                                             ("X-Review-Authenticated: 1\r\n", b" 404 ")):
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                            client.connect(path)
                            client.sendall(("GET /api/nonexistent HTTP/1.0\r\n" + header +
                                            "\r\n").encode())
                            response = client.recv(1024)
                        self.assertIn(expected, response)
                    server.shutdown()
                    thread.join(timeout=2)
        finally:
            controller.TRUST_GSA_PROXY = original

    def test_proxy_requires_gsad_authorization_header(self):
        class Request:
            def __init__(self, headers):
                self.headers = headers
                self.status = None

            def send_response(self, status):
                self.status = status

            def send_header(self, *_):
                pass

            def end_headers(self):
                pass

        original = controller.TRUST_GSA_PROXY
        try:
            controller.TRUST_GSA_PROXY = True
            for headers in ({}, {"X-Review-Authenticated": "0"},
                            {"Authorization": "Basic forged"},
                            {"X-Review-Operator-Authorization": "Basic forged"}):
                request = Request(headers)
                self.assertFalse(controller.Handler._authorized(request))
                self.assertEqual(request.status, 401)
            self.assertTrue(controller.Handler._authorized(Request({
                "X-Review-Authenticated": "1"})))
        finally:
            controller.TRUST_GSA_PROXY = original

    def test_numeric_host_range_rejected(self):
        with self.assertRaises(controller.ReviewError):
            controller.host_key("192.0.2.1-55")

    def test_combined_report_pages_across_native_reports(self):
        group = {"id": TARGET, "name": "Combined", "children": [
            {"host": "192.0.2.1", "task_id": TASK_A, "target_id": TARGET},
            {"host": "192.0.2.2", "task_id": TASK_B, "target_id": PORTS}]}
        report = controller.group_report(FakeReportGmp(), group, offset=2, limit=1)
        self.assertEqual(report["status"], "Done")
        self.assertEqual(report["report_count"], 2)
        self.assertEqual(report["result_count"], 3)
        self.assertEqual([(item["host"], item["name"]) for item in report["results"]],
                         [("192.0.2.2", "B1")])
        self.assertTrue(report["complete"])
        csv_data = controller.group_report_csv(FakeReportGmp(), group)
        self.assertIn("Evidence for A1", csv_data)
        self.assertIn("Evidence for B1", csv_data)
        self.assertEqual(len(csv_data.splitlines()), 4)
        group["name"] = "=unsafe()"
        self.assertIn("'=unsafe()", controller.group_report_csv(FakeReportGmp(), group))

    def test_existing_group_gets_one_native_task(self):
        class NativeGmp:
            commands = []

            def send_command(self, command):
                self.commands.append(command)
                return f'<create_task_response status="201" id="{TASK_A}"/>'

        original_db = controller.DB
        with tempfile.TemporaryDirectory() as directory:
            controller.DB = Path(directory) / "groups.sqlite"
            try:
                controller.init_db()
                controller.save_group(TARGET, {"name": "Review"}, [], None)
                gmp = NativeGmp()
                group = controller.group_by_id(TARGET)
                self.assertEqual(controller.attach_native_task(gmp, group), TASK_A)
                self.assertEqual(controller.attach_native_task(gmp, controller.group_by_id(TARGET)), TASK_A)
                self.assertEqual(len(gmp.commands), 1)
                self.assertIn('<target id="0"/>', gmp.commands[0])
            finally:
                controller.DB = original_db

    def test_native_report_publishes_once_for_completed_hosts(self):
        class NativeReportGmp(FakeReportGmp):
            imports = []

            def get_report(self, report_id, **_):
                host = "192.0.2.1" if report_id == REPORT_A else "192.0.2.2"
                return (f'<get_reports_response status="200"><report><report>'
                        f'<scan_start>2026-10-16T01:00:00Z</scan_start>'
                        f'<host><ip>{host}</ip></host>'
                        f'<results><result id="{TASK_A if report_id == REPORT_A else TASK_B}">'
                        f'<host>{host}</host><name>Finding</name></result></results>'
                        f'<scan_end>2026-10-16T01:01:00Z</scan_end>'
                        '</report></report></get_reports_response>')

            def send_command(self, command):
                self.imports.append(command)
                return f'<create_report_response status="201" id="{REPORT_A}"/>'

        original_db = controller.DB
        with tempfile.TemporaryDirectory() as directory:
            controller.DB = Path(directory) / "groups.sqlite"
            try:
                controller.init_db()
                children = [
                    {"host": "192.0.2.1", "task_id": TASK_A, "target_id": TARGET},
                    {"host": "192.0.2.2", "task_id": TASK_B, "target_id": PORTS},
                ]
                controller.save_group(TARGET, {"name": "Review"}, children, SCANNER)
                group = controller.group_by_id(TARGET)
                gmp = NativeReportGmp()
                first = controller.publish_native_report(gmp, group)
                second = controller.publish_native_report(gmp, group)
                self.assertFalse(first["existing"])
                self.assertTrue(second["existing"])
                self.assertEqual(len(gmp.imports), 1)
                payload = ET.fromstring(gmp.imports[0])
                self.assertEqual(payload.find("task").get("id"), SCANNER)
                self.assertEqual(len(payload.findall("./report/results/result")), 2)
            finally:
                controller.DB = original_db

    def test_native_report_import_preserves_two_hosts_from_one_scan(self):
        class MultiHostReportGmp(FakeReportGmp):
            imported = ""

            def get_report(self, _report_id, **_):
                return (f'<get_reports_response status="200"><report><report>'
                        '<scan_start>2026-10-16T01:00:00Z</scan_start>'
                        '<host><ip>192.0.2.1</ip></host>'
                        '<host><ip>192.0.2.2</ip></host>'
                        f'<results><result id="{TASK_A}"><host>192.0.2.1</host>'
                        '<name>First</name></result>'
                        f'<result id="{TASK_B}"><host>192.0.2.2</host>'
                        '<name>Second</name></result></results>'
                        '<scan_end>2026-10-16T01:01:00Z</scan_end>'
                        '</report></report></get_reports_response>')

            def send_command(self, command):
                self.imported = command
                return f'<create_report_response status="201" id="{REPORT_B}"/>'

        original_db = controller.DB
        with tempfile.TemporaryDirectory() as directory:
            controller.DB = Path(directory) / "groups.sqlite"
            try:
                controller.init_db()
                children = [{"host": "192.0.2.1, 192.0.2.2",
                             "hosts": ["192.0.2.1", "192.0.2.2"],
                             "task_id": TASK_A, "target_id": TARGET}]
                controller.save_group(TARGET, {"name": "Review"}, children,
                                      SCANNER)
                gmp = MultiHostReportGmp()
                report = controller.publish_native_report(
                    gmp, controller.group_by_id(TARGET))
                self.assertEqual(report["report_id"], REPORT_B)
                body = ET.fromstring(gmp.imported).find("report")
                self.assertEqual([host.findtext("ip") for host in body.findall("host")],
                                 ["192.0.2.1", "192.0.2.2"])
                self.assertEqual(len(body.findall("./results/result")), 2)
            finally:
                controller.DB = original_db

    def test_failed_restart_never_combines_or_exports_stale_reports(self):
        class PartiallyStartingGmp(FakeReportGmp):
            def start_task(self, task_id):
                if task_id == TASK_B:
                    raise controller.ReviewError("Second child could not start")
                return (f'<start_task_response status="202"><report_id>'
                        f'{REPORT_A}</report_id></start_task_response>')

        original_db = controller.DB
        with tempfile.TemporaryDirectory() as directory:
            controller.DB = Path(directory) / "groups.sqlite"
            try:
                controller.init_db()
                children = [
                    {"host": "192.0.2.1", "task_id": TASK_A, "target_id": TARGET},
                    {"host": "192.0.2.2", "task_id": TASK_B, "target_id": PORTS},
                ]
                controller.save_group(TARGET, {"name": "Review"}, children, SCANNER)
                gmp = PartiallyStartingGmp()
                result = controller.start_group(gmp, controller.group_by_id(TARGET))
                self.assertEqual(result["started"], [TASK_A])
                self.assertEqual(len(result["failed"]), 1)
                group = controller.group_by_id(TARGET)
                self.assertEqual(group["run_state"]["state"], "failed")
                self.assertIsNone(controller.publish_native_report(gmp, group))
                self.assertFalse(controller.group_report(gmp, group)["complete"])
                with self.assertRaisesRegex(controller.ReviewError, "incomplete"):
                    controller.group_report_csv(gmp, group)
            finally:
                controller.DB = original_db

    def test_empty_source_report_does_not_block_combined_import(self):
        class EmptySourceGmp(FakeReportGmp):
            imported = ""

            def get_report(self, report_id, **_):
                host = "192.0.2.2" if report_id == REPORT_B else None
                host_xml = f'<host><ip>{host}</ip></host>' if host else ''
                result_xml = (f'<result id="{TASK_B}"><host>{host}</host></result>'
                              if host else '')
                return (f'<get_reports_response status="200"><report><report>'
                        f'<scan_start>2026-10-16T01:00:00Z</scan_start>{host_xml}'
                        f'<results>{result_xml}</results>'
                        f'<scan_end>2026-10-16T01:01:00Z</scan_end>'
                        '</report></report></get_reports_response>')

            def send_command(self, command):
                self.imported = command
                return f'<create_report_response status="201" id="{REPORT_A}"/>'

        original_db = controller.DB
        with tempfile.TemporaryDirectory() as directory:
            controller.DB = Path(directory) / "groups.sqlite"
            try:
                controller.init_db()
                children = [
                    {"host": "192.0.2.1", "task_id": TASK_A, "target_id": TARGET},
                    {"host": "192.0.2.2", "task_id": TASK_B, "target_id": PORTS},
                ]
                controller.save_group(TARGET, {"name": "Review"}, children, SCANNER)
                gmp = EmptySourceGmp()
                self.assertIsNotNone(controller.publish_native_report(
                    gmp, controller.group_by_id(TARGET)))
                self.assertEqual(len(ET.fromstring(gmp.imported).findall("./report/results/result")), 1)
            finally:
                controller.DB = original_db


    def test_current_run_rejects_previous_report_ids(self):
        original_db = controller.DB
        with tempfile.TemporaryDirectory() as directory:
            controller.DB = Path(directory) / "groups.sqlite"
            try:
                controller.init_db()
                children = [{"host": "192.0.2.1", "task_id": TASK_A,
                             "target_id": TARGET}]
                controller.save_group(TARGET,
                                      {"name": "Review"}, children, SCANNER)
                controller.save_run_state(TARGET, {
                    "id": str(uuid.uuid4()), "state": "active",
                    "reports": {TASK_A: "00000000-0000-4000-8000-000000000001"},
                    "failed": []})
                group = controller.group_by_id(TARGET)
                summary = controller.group_summary(FakeReportGmp(), group)
                self.assertNotEqual(summary["status"], "Done")
                self.assertEqual(summary["report_count"], 0)
                self.assertEqual(summary["done_count"], 0)
                self.assertIsNone(controller.publish_native_report(
                    FakeReportGmp(), group))
            finally:
                controller.DB = original_db


    def test_mutation_loads_group_after_acquiring_lock(self):
        lock = threading.Lock()
        original = (controller.MUTATION_LOCK, controller.manager,
                    controller.group_by_id, controller.start_group)

        class Manager:
            def __enter__(self):
                return object()
            def __exit__(self, *_):
                return False

        class Request:
            path = f"/api/groups/{TARGET}/start"
            headers = {"Content-Length": "2"}
            rfile = io.BytesIO(b"{}")
            status = None
            def _authorized(self):
                return True
            def _send(self, status, _result):
                self.status = status

        def load_group(_group_id):
            self.assertTrue(lock.locked())
            return {"id": TARGET}

        try:
            controller.MUTATION_LOCK = lock
            controller.manager = Manager
            controller.group_by_id = load_group
            controller.start_group = lambda *_: {"started": []}
            request = Request()
            controller.Handler.do_POST(request)
            self.assertEqual(request.status, 200)
        finally:
            (controller.MUTATION_LOCK, controller.manager,
             controller.group_by_id, controller.start_group) = original

    def test_cve_scanner_is_rejected_before_any_child_is_created(self):
        class CveGmp(FakeGmp):
            def get_scanners(self, **_):
                return (f'<get_scanners_response status="200"><scanner id="{SCANNER}">'
                        '<type>3</type></scanner></get_scanners_response>')

        with self.assertRaisesRegex(controller.ReviewError, "CVE scanners"):
            controller.build_plan(CveGmp(), self.request())

    def test_native_in_use_states_block_restart(self):
        class BusyGmp(FakeReportGmp):
            status = "Processing"
            def get_task(self, task_id):
                return (f'<get_tasks_response status="200"><task id="{task_id}">'
                        f'<status>{self.status}</status></task></get_tasks_response>')

        original_db = controller.DB
        with tempfile.TemporaryDirectory() as directory:
            controller.DB = Path(directory) / "groups.sqlite"
            try:
                controller.init_db()
                controller.save_group(TARGET, {"name": "Review"},
                                      [{"host": "192.0.2.1", "task_id": TASK_A,
                                        "target_id": TARGET}], SCANNER)
                gmp = BusyGmp()
                for status in ("Processing", "Stop Requested", "Stop Waiting",
                               "Delete Requested"):
                    gmp.status = status
                    with self.assertRaisesRegex(controller.ReviewError, "active host scans"):
                        controller.start_group(gmp, controller.group_by_id(TARGET))
                    self.assertIsNone(controller.group_by_id(TARGET)["run_state"])
            finally:
                controller.DB = original_db

    def test_interrupted_launch_recovers_only_fully_recorded_reports(self):
        children = [{"host": "192.0.2.1", "task_id": TASK_A, "target_id": TARGET},
                    {"host": "192.0.2.4", "task_id": TASK_B, "target_id": TARGET_B}]
        original_db = controller.DB
        with tempfile.TemporaryDirectory() as directory:
            controller.DB = Path(directory) / "groups.sqlite"
            try:
                controller.init_db()
                controller.save_group(TARGET, {"name": "Review"}, children, SCANNER)
                controller.save_run_state(TARGET, {
                    "id": str(uuid.uuid4()), "state": "starting",
                    "reports": {TASK_A: REPORT_A, TASK_B: REPORT_B}, "failed": []})
                recovered = controller.recover_starting_run(
                    controller.group_by_id(TARGET))
                self.assertEqual(recovered["run_state"]["state"], "active")
                self.assertEqual(controller.group_summary(FakeReportGmp(), recovered)["status"], "Done")
                controller.save_run_state(TARGET, {
                    "id": str(uuid.uuid4()), "state": "starting",
                    "reports": {TASK_A: REPORT_A}, "failed": []})
                recovered = controller.recover_starting_run(
                    controller.group_by_id(TARGET))
                self.assertEqual(recovered["run_state"]["state"], "failed")
                self.assertIn(TASK_B, recovered["run_state"]["failed"][0]["task_id"])
                self.assertIsNone(controller.publish_native_report(FakeReportGmp(), recovered))
            finally:
                controller.DB = original_db


if __name__ == "__main__":
    unittest.main()
