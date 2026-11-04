"""Experimental multi-target review orchestration.

All concrete hosts from one source target share one child scan. This is a
separate review service, not a native gvmd feature.
"""

from __future__ import annotations

import base64
import copy
import csv
import hashlib
import hmac
import ipaddress
import io
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape, quoteattr

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import GMP


SOCKET = os.environ.get("GMP_SOCKET", "/run/gvmd/gvmd.sock")
DB = Path(os.environ.get("REVIEW_DB", "/var/lib/credential-review/groups.sqlite"))
USERNAME = os.environ.get("REVIEW_USERNAME", "admin")
PASSWORD = os.environ.get("REVIEW_PASSWORD", "admin")
GMP_USERNAME = os.environ.get("GMP_USERNAME", "admin")
GMP_PASSWORD = os.environ.get("GMP_PASSWORD", "admin")
TRUST_GSA_PROXY = os.environ.get("TRUST_GSA_PROXY", "0") == "1"
SERVICES = ("ssh", "ssh_elevate", "smb", "esxi", "snmp", "krb5")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")
DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
MUTATION_LOCK = threading.Lock()
REPORT_FILTER = "min_qod=70 apply_overrides=0"
REPORT_PAGE_SIZE = 100
CSV_RESULT_LIMIT = 5000
NATIVE_REPORT_RESULT_LIMIT = 10000
NATIVE_REPORT_XML_LIMIT = 25 * 1024 * 1024


class ReviewError(ValueError):
    pass


def require_enhanced_mode(body: dict):
    if not isinstance(body, dict) or body.get("backend_mode") != "enhanced":
        raise ReviewError("Select multi-target mode to use the review backend")


def require_uuid(value: str) -> str:
    if not isinstance(value, str) or not UUID_RE.fullmatch(value):
        raise ReviewError(f"Invalid UUID: {value!r}")
    return str(uuid.UUID(value))


def check_response(xml: str) -> ET.Element:
    root = ET.fromstring(xml)
    status = root.get("status", "")
    if not status.startswith("2"):
        raise ReviewError(f"GMP {root.tag}: {status} {root.get('status_text', '')}")
    return root


@contextmanager
def manager():
    with GMP(UnixSocketConnection(path=SOCKET)) as gmp:
        check_response(gmp.authenticate(GMP_USERNAME, GMP_PASSWORD))
        yield gmp


def host_key(value: str) -> str:
    host = value.strip()
    if not host or "/" in host or "*" in host or "," in host or any(c.isspace() for c in host):
        raise ReviewError(f"Only explicit IPs or DNS names are supported: {host!r}")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        labels = host.rstrip(".").split(".")
        if (len(host) > 253 or any(not DNS_LABEL_RE.fullmatch(label) for label in labels)
                or all(c.isdigit() or c in ".-" for c in host)):
            raise ReviewError(f"Invalid host: {host!r}")
        return host.rstrip(".").lower()


def split_hosts(raw: str) -> list[str]:
    hosts = [host_key(h) for h in raw.split(",") if h.strip()]
    if not hosts or len(hosts) > 128:
        raise ReviewError("Each source target must contain 1–128 explicit hosts")
    if len(set(hosts)) != len(hosts):
        raise ReviewError("Duplicate host in source target")
    return hosts


def child_text(element: ET.Element, tag: str, default: str = "") -> str:
    return element.findtext(tag) or default


def inventory(gmp) -> dict:
    targets = check_response(gmp.get_targets(filter_string="rows=-1"))
    credentials = check_response(gmp.get_credentials(filter_string="rows=-1"))
    configs = check_response(gmp.get_scan_configs(filter_string="rows=-1"))
    scanners = check_response(gmp.get_scanners(filter_string="rows=-1"))

    def entries(root, tag):
        return [{"id": item.get("id"), "name": child_text(item, "name"),
                 "type": child_text(item, "type"), "hosts": child_text(item, "hosts"),
                 "review_managed": (tag == "target" and child_text(item, "comment") ==
                                    "Created by credential review controller")}
                for item in root.findall(tag)]

    return {"targets": entries(targets, "target"),
            "credentials": entries(credentials, "credential"),
            "configs": entries(configs, "config"),
            "scanners": entries(scanners, "scanner"),
            "assets": []}


def _target_settings(target: ET.Element) -> dict:
    if target.find("asset_hosts") is not None:
        raise ReviewError("Dynamic asset-filter targets are not supported in this review")
    if child_text(target, "exclude_hosts").strip():
        raise ReviewError("Source target exclusions need manual host expansion first")
    port_list = target.find("port_list")
    if port_list is None or not port_list.get("id"):
        raise ReviewError("Source target has no port list")
    creds = {}
    for service in SERVICES:
        element = target.find(f"{service}_credential")
        if element is not None and element.get("id"):
            creds[service] = require_uuid(element.get("id"))
    ssh_element = target.find("ssh_credential")
    ssh_port = child_text(ssh_element, "port", "22") if ssh_element is not None else "22"
    if not ssh_port.isdigit() or not 1 <= int(ssh_port) <= 65535:
        raise ReviewError("Invalid SSH port in source target")
    return {"id": require_uuid(target.get("id")), "name": child_text(target, "name"),
            "hosts": split_hosts(child_text(target, "hosts")),
            "port_list_id": require_uuid(port_list.get("id")), "credentials": creds,
            "ssh_port": ssh_port,
            "alive_tests": [e.text or "" for e in target.findall("./alive_tests/alive_test")],
            "reverse_lookup_only": child_text(target, "reverse_lookup_only", "0"),
            "reverse_lookup_unify": child_text(target, "reverse_lookup_unify", "0"),
            "allow_simultaneous_ips": child_text(target, "allow_simultaneous_ips", "1")}


def build_plan(gmp, request: dict, *, require_scan_setup: bool = True) -> dict:
    name = str(request.get("name", "")).strip()
    if not 1 <= len(name) <= 80:
        raise ReviewError("Logical task name must contain 1–80 characters")
    target_ids = request.get("target_ids", [])
    if not isinstance(target_ids, list) or not 1 <= len(target_ids) <= 16:
        raise ReviewError("Select 1–16 source targets")
    target_ids = [require_uuid(value) for value in target_ids]
    if len(set(target_ids)) != len(target_ids):
        raise ReviewError("Duplicate source target")
    if request.get("overrides"):
        raise ReviewError("Credential overrides require the combined feature tier")
    config_id = require_uuid(request.get("config_id")) if request.get("config_id") else None
    scanner_id = require_uuid(request.get("scanner_id")) if request.get("scanner_id") else None
    if require_scan_setup and (not config_id or not scanner_id):
        raise ReviewError("Select a scan config and scanner before creating tasks")
    inv = inventory(gmp)
    for collection, item_id in (("configs", config_id), ("scanners", scanner_id)):
        if item_id and item_id not in {entry["id"] for entry in inv[collection]}:
            raise ReviewError(f"Selected {collection[:-1]} is unavailable")
    units = []
    scan_units = []
    seen_hosts = set()
    for target_id in target_ids:
        response = check_response(gmp.get_target(target_id))
        target = response.find("target")
        if target is None:
            raise ReviewError(f"Target {target_id} not found")
        settings = _target_settings(target)
        hosts = settings.pop("hosts")
        scan_units.append({**settings, "hosts": hosts, "applied_overrides": [],
                           "host_decisions": [{"host": host, "applied_overrides": []}
                                              for host in hosts]})
        for host in hosts:
            if host in seen_hosts:
                raise ReviewError(f"Host {host} occurs in more than one source target")
            seen_hosts.add(host)
            units.append({**settings, "host": host, "applied_overrides": []})
    if len(units) > 128:
        raise ReviewError("Logical task exceeds 128 hosts")
    return {"name": name, "backend_mode": "enhanced", "config_id": config_id,
            "scanner_id": scanner_id, "units": units, "scan_units": scan_units,
            "warning": "Each source target is one native gvmd task and report."}


def target_xml(group_id: str, unit: dict) -> str:
    credentials = unit["credentials"]
    hosts = unit.get("hosts") or [unit["host"]]
    parts = ["<create_target>",
             f"<name>{escape('Review ' + group_id[:8] + ' ' + hosts[0])}</name>",
             f"<hosts>{escape(','.join(hosts))}</hosts>",
             f"<port_list id={quoteattr(unit['port_list_id'])}/>",
             "<comment>Created by credential review controller</comment>"]
    for setting in ("reverse_lookup_only", "reverse_lookup_unify", "allow_simultaneous_ips"):
        value = unit.get(setting, "0")
        if value not in ("0", "1"):
            raise ReviewError(f"Invalid {setting} in source target")
        parts.append(f"<{setting}>{value}</{setting}>")
    if unit["alive_tests"]:
        parts.append("<alive_tests>" + "".join(
            f"<alive_test>{escape(test)}</alive_test>" for test in unit["alive_tests"]
        ) + "</alive_tests>")
    for service in SERVICES:
        if service in credentials:
            extra = f"<port>{unit['ssh_port']}</port>" if service == "ssh" else ""
            parts.append(f"<{service}_credential id={quoteattr(credentials[service])}>"
                         f"{extra}</{service}_credential>")
    parts.append("</create_target>")
    return "".join(parts)


def init_db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB) as db:
        db.execute("CREATE TABLE IF NOT EXISTS groups (id TEXT PRIMARY KEY, name TEXT NOT NULL, plan TEXT NOT NULL, children TEXT NOT NULL)")
        group_columns = {row[1] for row in db.execute("PRAGMA table_info(groups)")}
        if "native_task_id" not in group_columns:
            db.execute("ALTER TABLE groups ADD COLUMN native_task_id TEXT")
        if "native_error" not in group_columns:
            db.execute("ALTER TABLE groups ADD COLUMN native_error TEXT")
        db.execute("CREATE TABLE IF NOT EXISTS native_reports (group_id TEXT NOT NULL, signature TEXT NOT NULL, report_id TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(group_id, signature), UNIQUE(report_id))")


def save_group(group_id, plan, children, native_task_id):
    with sqlite3.connect(DB) as db:
        db.execute("INSERT INTO groups (id, name, plan, children, native_task_id) VALUES (?, ?, ?, ?, ?)",
                   (group_id, plan["name"], json.dumps(plan), json.dumps(children), native_task_id))


def get_groups():
    with sqlite3.connect(DB) as db:
        rows = db.execute("SELECT id, name, plan, children, native_task_id, native_error FROM groups ORDER BY rowid DESC").fetchall()
    return [{"id": row[0], "name": row[1], "plan": json.loads(row[2]),
             "children": json.loads(row[3]), "native_task_id": row[4],
             "native_error": row[5]} for row in rows]


def create_native_task(gmp, group: dict) -> str:
    """Create the normal gvmd task record used as the logical scan entry."""
    command = ("<create_task><target id=\"0\"/>"
               f"<name>{escape(group['name'])}</name>"
               f"<comment>Multi-target review task; group {group['id']}</comment>"
               "<usage_type>scan</usage_type></create_task>")
    return require_uuid(check_response(gmp.send_command(command)).get("id"))


def attach_native_task(gmp, group: dict) -> str:
    """Idempotently attach a native task to a group created by older builds."""
    if group.get("native_task_id"):
        return require_uuid(group["native_task_id"])
    task_id = create_native_task(gmp, group)
    with sqlite3.connect(DB) as db:
        changed = db.execute("UPDATE groups SET native_task_id=? WHERE id=? AND native_task_id IS NULL",
                             (task_id, group["id"])).rowcount
    if changed != 1:
        check_response(gmp.delete_task(task_id, ultimate=True))
        return group_by_id(group["id"])["native_task_id"]
    return task_id


def native_report_for_group(group_id: str) -> dict | None:
    if not DB.exists():
        return None
    with sqlite3.connect(DB) as db:
        try:
            row = db.execute("SELECT report_id, signature, created_at FROM native_reports WHERE group_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
                             (group_id,)).fetchone()
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc):
                raise
            return None
    return {"id": row[0], "signature": row[1], "created_at": row[2]} if row else None


def group_by_id(group_id: str) -> dict:
    group_id = require_uuid(group_id)
    group = next((item for item in get_groups() if item["id"] == group_id), None)
    if group is None:
        raise ReviewError("Unknown scan group")
    return group


def group_summary(gmp, group: dict) -> dict:
    """Describe one logical group while retaining native task/report identities."""
    children = []
    for child in group["children"]:
        hosts = child.get("hosts") or [child["host"]]
        entry = {"host": ", ".join(hosts), "hosts": hosts, "task_id": child["task_id"],
                 "target_id": child["target_id"], "status": "Unavailable",
                 "report_id": None}
        try:
            task = check_response(gmp.get_task(child["task_id"])).find("task")
            if task is None:
                raise ReviewError("Task is missing")
            entry["status"] = child_text(task, "status", "Unknown")
            last_report = task.find("./last_report/report")
            if last_report is not None and last_report.get("id"):
                entry["report_id"] = require_uuid(last_report.get("id"))
        except (ReviewError, ValueError, ET.ParseError) as exc:
            entry["error"] = str(exc)
        children.append(entry)
    statuses = [child["status"] for child in children]
    if statuses and all(status == "Done" for status in statuses):
        status = "Done"
    elif statuses and all(status == "New" for status in statuses):
        status = "New"
    elif any(status in ("Running", "Requested", "Queued") for status in statuses):
        status = "Running"
    elif any(status == "Unavailable" for status in statuses):
        status = "Attention needed"
    else:
        status = "Partial"
    native_report = native_report_for_group(group["id"])
    return {"id": group["id"], "name": group["name"], "status": status,
            "native_task_id": group.get("native_task_id"),
            "native_report_id": native_report["id"] if native_report else None,
            "native_error": group.get("native_error"),
            "host_count": sum(len(child["hosts"]) for child in children),
            "done_count": sum(len(child["hosts"]) for child in children
                              if child["status"] == "Done"),
            "report_count": sum(bool(child["report_id"]) for child in children),
            "children": children}


def report_signature(summary: dict) -> str:
    report_ids = [item["report_id"] for item in summary["children"]]
    if (summary["status"] != "Done" or not report_ids
            or any(report_id is None for report_id in report_ids)):
        raise ReviewError("All host scans must be complete before publishing one report")
    return hashlib.sha256("\n".join(report_ids).encode()).hexdigest()


def publish_native_report(gmp, group: dict) -> dict | None:
    """Publish a completed run in the normal gvmd Reports list.

    Source reports remain authoritative: GMP import does not preserve every
    internal relation, so this review path has a strict size limit.
    """
    summary = group_summary(gmp, group)
    if summary["status"] != "Done" or summary["report_count"] != len(summary["children"]):
        return None
    signature = report_signature(summary)
    with sqlite3.connect(DB) as db:
        existing = db.execute("SELECT report_id FROM native_reports WHERE group_id=? AND signature=?",
                              (group["id"], signature)).fetchone()
    if existing:
        return {"report_id": existing[0], "signature": signature, "existing": True}

    native_task_id = attach_native_task(gmp, group)
    sources = []
    result_total = 0
    for child in summary["children"]:
        response = check_response(gmp.get_report(
            child["report_id"], details=True, ignore_pagination=True,
            filter_string="min_qod=0 apply_overrides=0 rows=-1"))
        outer = response.find("report")
        inner = outer.find("report") if outer is not None else None
        if inner is None or inner.find("results") is None:
            raise ReviewError(f"Native source report {child['report_id']} is incomplete")
        expected_hosts = set(child["hosts"])
        report_hosts = inner.findall("./host")
        if not report_hosts or any(host.findtext("ip") not in expected_hosts
                                   for host in report_hosts):
            raise ReviewError(f"Source host metadata for {child['host']} is incomplete")
        if any(result.findtext("host") not in expected_hosts
               for result in inner.findall("./results/result")):
            raise ReviewError(f"Source results contain a host outside {child['host']}")
        result_total += len(inner.findall("./results/result"))
        if result_total > NATIVE_REPORT_RESULT_LIMIT:
            raise ReviewError("Native review import exceeds 10000 results; host reports remain available")
        sources.append((child, inner))

    envelope = ET.Element("create_report")
    ET.SubElement(envelope, "in_assets").text = "0"
    body = ET.SubElement(envelope, "report")
    starts = [inner.findtext("scan_start") for _, inner in sources]
    ends = [inner.findtext("scan_end") for _, inner in sources]
    if not all(starts) or not all(ends):
        raise ReviewError("Source scan times are incomplete")
    ET.SubElement(body, "scan_start").text = min(starts)
    results = ET.SubElement(body, "results", {"start": "1", "max": "-1"})
    for _, inner in sources:
        for host in inner.findall("./host"):
            body.append(copy.deepcopy(host))
        for result in inner.findall("./results/result"):
            results.append(copy.deepcopy(result))
        for error in inner.findall("./errors/error"):
            errors = body.find("errors")
            if errors is None:
                errors = ET.SubElement(body, "errors")
            errors.append(copy.deepcopy(error))
    ET.SubElement(body, "scan_end").text = max(ends)
    ET.SubElement(envelope, "task", {"id": native_task_id})
    payload = ET.tostring(envelope, encoding="unicode")
    if len(payload.encode()) > NATIVE_REPORT_XML_LIMIT:
        raise ReviewError("Native review import exceeds 25 MiB; host reports remain available")
    report_id = require_uuid(check_response(gmp.send_command(payload)).get("id"))
    with sqlite3.connect(DB) as db:
        db.execute("INSERT INTO native_reports (group_id, signature, report_id, created_at) VALUES (?, ?, ?, ?)",
                   (group["id"], signature, report_id, int(time.time())))
        db.execute("UPDATE groups SET native_error=NULL WHERE id=?", (group["id"],))
    return {"report_id": report_id, "signature": signature, "existing": False}


def synchronize_native_reports() -> None:
    """Background reconciliation keeps completed runs in native Reports."""
    while True:
        try:
            with MUTATION_LOCK, manager() as gmp:
                for group in get_groups():
                    if not group.get("native_task_id"):
                        continue
                    try:
                        publish_native_report(gmp, group)
                    except Exception as exc:
                        with sqlite3.connect(DB) as db:
                            db.execute("UPDATE groups SET native_error=? WHERE id=?",
                                       (str(exc)[:500], group["id"]))
        except Exception:
            pass  # gvmd may be temporarily unavailable during startup/restart.
        time.sleep(30)


def result_filter(report_id: str, first: int, rows: int) -> str:
    return f"report_id={require_uuid(report_id)} {REPORT_FILTER} first={first} rows={rows}"


def result_count(gmp, report_id: str) -> int:
    response = check_response(gmp.get_results(
        filter_string=result_filter(report_id, 1, 1), details=False))
    count = response.findtext("result_count/filtered")
    if count is None or not count.isdigit():
        raise ReviewError(f"Cannot count results for report {report_id}")
    return int(count)


def report_results(gmp, report_id: str, first: int, rows: int) -> list[dict]:
    if rows < 1:
        return []
    response = check_response(gmp.get_results(
        filter_string=result_filter(report_id, first, rows), details=True))
    return [{"id": require_uuid(item.get("id")),
             "name": child_text(item, "name"), "host": child_text(item, "host"),
             "port": child_text(item, "port"), "severity": child_text(item, "severity"),
             "threat": child_text(item, "threat"),
             "nvt_oid": item.find("nvt").get("oid", "") if item.find("nvt") is not None else "",
             "description": child_text(item, "description")}
            for item in response.findall("result")]


def group_report(gmp, group: dict, *, offset: int = 0,
                 limit: int = REPORT_PAGE_SIZE) -> dict:
    if offset < 0 or not 1 <= limit <= REPORT_PAGE_SIZE:
        raise ReviewError("Invalid combined report page")
    summary = group_summary(gmp, group)
    remaining = limit
    skipped = offset
    total = 0
    results = []
    for child in summary["children"]:
        report_id = child["report_id"]
        if report_id is None:
            child["result_count"] = 0
            continue
        try:
            count = result_count(gmp, report_id)
            child["result_count"] = count
        except (ReviewError, ValueError, ET.ParseError) as exc:
            child["result_count"] = 0
            child["error"] = str(exc)
            continue
        total += count
        if skipped >= count:
            skipped -= count
            continue
        if remaining:
            take = min(remaining, count - skipped)
            page = report_results(gmp, report_id, skipped + 1, take)
            results.extend({**item, "task_id": child["task_id"],
                            "report_id": report_id} for item in page)
            remaining -= len(page)
        skipped = 0
    summary.update({"result_count": total, "offset": offset, "limit": limit,
                    "results": results, "filter": REPORT_FILTER,
                    "complete": not any(child.get("error") for child in summary["children"])})
    return summary


def group_report_csv(gmp, group: dict) -> str:
    summary = group_report(gmp, group, limit=1)
    if not summary["complete"]:
        raise ReviewError("A child report is unavailable; export would be incomplete")
    if summary["result_count"] > CSV_RESULT_LIMIT:
        raise ReviewError(f"Combined CSV is limited to {CSV_RESULT_LIMIT} results")
    output = io.StringIO()
    writer = csv.writer(output)

    def safe_cell(value: str) -> str:
        # Scan results and group names can contain spreadsheet formulas.
        return "'" + value if re.match(r"\s*[=+@-]", value) else value

    writer.writerow(("Group", "Host", "Severity", "Threat", "Result", "Port",
                     "NVT OID", "Description", "Native task ID", "Native report ID", "Result ID"))
    for child in summary["children"]:
        report_id = child["report_id"]
        for first in range(1, child["result_count"] + 1, 500):
            page = report_results(gmp, report_id, first,
                                  min(500, child["result_count"] - first + 1))
            for item in page:
                writer.writerow((safe_cell(group["name"]), safe_cell(item["host"]),
                                 item["severity"], safe_cell(item["threat"]),
                                 safe_cell(item["name"]), safe_cell(item["port"]),
                                 safe_cell(item["nvt_oid"]), safe_cell(item["description"]),
                                 child["task_id"], report_id, item["id"]))
    return output.getvalue()


def create_group(gmp, plan: dict) -> dict:
    group_id = str(uuid.uuid4())
    children = []
    native_task_id = None
    try:
        scan_units = plan.get("scan_units", plan["units"])
        for index, unit in enumerate(scan_units, start=1):
            target_response = check_response(gmp.send_command(target_xml(group_id, unit)))
            child_target_id = require_uuid(target_response.get("id"))
            hosts = unit.get("hosts") or [unit["host"]]
            child = {"host": ", ".join(hosts), "hosts": hosts,
                     "target_id": child_target_id,
                     "source_target_id": unit["id"], "credentials": unit["credentials"],
                     "applied_overrides": unit["applied_overrides"],
                     "host_decisions": unit.get("host_decisions", [])}
            children.append(child)
            task_response = check_response(gmp.create_task(
                name=f"{plan['name'][:45]} [{index}/{len(scan_units)}] {unit['name'][:20]}",
                config_id=plan["config_id"], target_id=child_target_id,
                scanner_id=plan["scanner_id"],
                comment=f"Credential review group {group_id}; source target {unit['id']}"))
            child["task_id"] = require_uuid(task_response.get("id"))
        native_task_id = create_native_task(gmp, {"id": group_id, "name": plan["name"]})
        save_group(group_id, plan, children, native_task_id)
    except Exception:
        if native_task_id:
            try:
                gmp.delete_task(native_task_id, ultimate=True)
            except Exception:
                pass
        for child in reversed(children):
            if child.get("task_id"):
                try:
                    gmp.delete_task(child["task_id"], ultimate=True)
                except Exception:
                    pass
            try:
                gmp.delete_target(child["target_id"], ultimate=True)
            except Exception:
                pass
        raise
    return {"id": group_id, "name": plan["name"],
            "native_task_id": native_task_id, "children": children}


def start_group(gmp, group: dict) -> dict:
    summary = group_summary(gmp, group)
    if any(child["status"] in ("Running", "Requested", "Queued")
           for child in summary["children"]):
        raise ReviewError("This multi-target task already has active host scans")
    started, failed = [], []
    for child in group["children"]:
        try:
            check_response(gmp.start_task(child["task_id"]))
            started.append(child["task_id"])
        except Exception as exc:
            failed.append({"task_id": child["task_id"], "error": str(exc)})
    return {"started": started, "failed": failed}


def stop_group(gmp, group: dict) -> dict:
    summary = group_summary(gmp, group)
    stopped, failed = [], []
    for child in summary["children"]:
        if child["status"] not in ("Running", "Requested", "Queued"):
            continue
        try:
            check_response(gmp.stop_task(child["task_id"]))
            stopped.append(child["task_id"])
        except Exception as exc:
            failed.append({"task_id": child["task_id"], "error": str(exc)})
    return {"stopped": stopped, "failed": failed}


class Handler(BaseHTTPRequestHandler):
    def _authorized(self):
        # nginx alone sets this header after an auth_request against the
        # existing GSAD session. The controller has no published port when
        # proxy authentication is enabled in the integrated review stack.
        if TRUST_GSA_PROXY:
            if self.headers.get("X-Review-Authenticated") == "1":
                return True
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False
        auth = self.headers.get("Authorization", "")
        expected = "Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
        if hmac.compare_digest(auth, expected):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Credential review"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def _send(self, status, data, content_type="application/json"):
        content = data.encode() if isinstance(data, str) else json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self):
        if not self._authorized():
            return
        try:
            parsed = urlsplit(self.path)
            path = parsed.path
            if path == "/api/health":
                with manager() as gmp:
                    check_response(gmp.get_version())
                self._send(200, {"ready": True})
            elif path == "/api/inventory":
                with manager() as gmp:
                    self._send(200, inventory(gmp))
            elif path == "/api/groups":
                self._send(200, get_groups())
            elif path == "/api/groups/summary":
                with manager() as gmp:
                    self._send(200, [group_summary(gmp, group) for group in get_groups()])
            elif re.fullmatch(r"/api/groups/[0-9a-fA-F-]{36}/report(?:\.csv)?", path):
                group = group_by_id(path.split("/")[3])
                with manager() as gmp:
                    if path.endswith(".csv"):
                        content = group_report_csv(gmp, group).encode("utf-8-sig")
                        self.send_response(200)
                        self.send_header("Content-Type", "text/csv; charset=utf-8")
                        self.send_header("Content-Disposition", "attachment; filename=combined-scan-results.csv")
                        self.send_header("Cache-Control", "no-store")
                        self.send_header("X-Content-Type-Options", "nosniff")
                        self.send_header("Content-Length", str(len(content)))
                        self.end_headers()
                        self.wfile.write(content)
                    else:
                        query = parse_qs(parsed.query, strict_parsing=True)
                        if set(query) - {"offset", "limit"}:
                            raise ReviewError("Unsupported combined report parameter")
                        offset = int(query.get("offset", ["0"])[0])
                        limit = int(query.get("limit", [str(REPORT_PAGE_SIZE)])[0])
                        self._send(200, group_report(gmp, group, offset=offset, limit=limit))
            else:
                self._send(404, {"error": "Not found"})
        except (ReviewError, ValueError) as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:
            self._send(503, {"error": str(exc)})

    def do_POST(self):
        if not self._authorized():
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 65536:
                raise ReviewError("Request body is too large")
            body = json.loads(self.rfile.read(length))
            if self.path == "/api/preview":
                require_enhanced_mode(body)
                with manager() as gmp:
                    result = build_plan(gmp, body, require_scan_setup=False)
            elif self.path == "/api/groups":
                require_enhanced_mode(body)
                with MUTATION_LOCK, manager() as gmp:
                    result = create_group(gmp, build_plan(gmp, body))
            elif re.fullmatch(r"/api/groups/[0-9a-fA-F-]{36}/(?:start|stop|publish)", self.path):
                group = group_by_id(self.path.split("/")[3])
                with MUTATION_LOCK, manager() as gmp:
                    if self.path.endswith("/start"):
                        result = start_group(gmp, group)
                    elif self.path.endswith("/stop"):
                        result = stop_group(gmp, group)
                    else:
                        result = publish_native_report(gmp, group)
            else:
                self._send(404, {"error": "Not found"})
                return
            self._send(200, result)
        except (ReviewError, ValueError, KeyError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:
            self._send(503, {"error": str(exc)})


if __name__ == "__main__":
    init_db()
    threading.Thread(target=synchronize_native_reports, daemon=True,
                     name="native-report-reconciliation").start()
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
