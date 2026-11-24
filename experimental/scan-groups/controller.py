"""Temporary, loopback-only review orchestration for per-asset credentials.

Hosts with identical effective credentials share a child scan within their
source target. This is a separate review service, not a native gvmd feature.
"""

from __future__ import annotations

import base64
import copy
import csv
import fcntl
import hashlib
import hmac
import ipaddress
import io
import json
import os
import re
import sqlite3
import socketserver
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
USERNAME = os.environ.get("REVIEW_USERNAME", "")
PASSWORD = os.environ.get("REVIEW_PASSWORD", "")
GMP_USERNAME = os.environ.get("GMP_USERNAME", "admin")
GMP_PASSWORD = os.environ.get("GMP_PASSWORD", "admin")
TRUST_GSA_PROXY = os.environ.get("TRUST_GSA_PROXY", "0") == "1"
NATIVE_BACKEND = os.environ.get("NATIVE_BACKEND", "0") == "1"
HTTP_SOCKET = os.environ.get("REVIEW_HTTP_SOCKET", "")
SERVICES = ("ssh", "ssh_elevate", "smb", "esxi", "snmp", "krb5")
CREDENTIAL_TYPES = {
    "ssh": {"up", "usk"}, "ssh_elevate": {"up"},
    "smb": {"up"}, "esxi": {"up"}, "snmp": {"snmp"},
    "krb5": {"krb5"},
}
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")
DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
MUTATION_LOCK = threading.Lock()
REPORT_LOCK = threading.Lock()
MAX_SCAN_PARTITIONS = 16
MAX_OUTSTANDING_CHILDREN = 64
MAX_GROUP_ACTIVE_CHILDREN = 2
MAX_SCANNER_ACTIVE_CHILDREN = 2
MAX_GLOBAL_ACTIVE_CHILDREN = 2
REPORT_FILTER = "min_qod=70 apply_overrides=0"
REPORT_PAGE_SIZE = 100
CSV_RESULT_LIMIT = 5000
NATIVE_REPORT_RESULT_LIMIT = 10000
NATIVE_REPORT_XML_LIMIT = 25 * 1024 * 1024
NATIVE_REPORT_PAGE_SIZE = 250
NATIVE_REPORT_RETRY_BASE = 60
NATIVE_REPORT_RETRY_MAX = 3600
ACTIVE_TASK_STATUSES = {"Requested", "Running", "Queued", "Stop Requested",
                        "Stop Waiting", "Processing", "Delete Requested",
                        "Delete Waiting", "Ultimate Delete Requested",
                        "Ultimate Delete Waiting"}


class ReviewError(ValueError):
    pass


class MissingTaskError(ReviewError):
    """Authenticated GMP confirms that a child task no longer exists."""


class PlanChangedError(ReviewError):
    """The number of background scans changed after preview."""


class GroupConflictError(ReviewError):
    """A native scan or report still needs operator action."""


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
    for host in hosts:
        try:
            ipaddress.ip_address(host)
        except ValueError as exc:
            raise ReviewError(
                f"DNS source host {host!r} is not supported until report IP mapping is available") from exc
    if len(set(hosts)) != len(hosts):
        raise ReviewError("Duplicate host in source target")
    return hosts


def child_text(element: ET.Element, tag: str, default: str = "") -> str:
    return element.findtext(tag) or default


def inventory(gmp, *, include_assets: bool = True) -> dict:
    targets = check_response(gmp.get_targets(filter_string="rows=-1"))
    credentials = check_response(gmp.get_credentials(filter_string="rows=-1"))
    configs = check_response(gmp.get_scan_configs(filter_string="rows=-1"))
    scanners = check_response(gmp.get_scanners(filter_string="rows=-1"))
    assets = (check_response(gmp.get_hosts(filter_string="rows=-1"))
              if include_assets else None)

    def entries(root, tag):
        return [{"id": item.get("id"), "name": child_text(item, "name"),
                 "type": child_text(item, "type"), "hosts": child_text(item, "hosts"),
                 "review_managed": (tag == "target" and child_text(item, "comment") ==
                                    "Created by credential review controller")}
                for item in root.findall(tag)]

    def asset_ip(asset):
        return next((child_text(identifier, "value")
                     for identifier in asset.findall("./identifiers/identifier")
                     if child_text(identifier, "name") == "ip"), "")

    return {"targets": entries(targets, "target"),
            "credentials": entries(credentials, "credential"),
            "configs": entries(configs, "config"),
            "scanners": entries(scanners, "scanner"),
            "assets": [{"id": h.get("id"), "name": child_text(h, "name"),
                        "ip": asset_ip(h)} for h in assets.findall("asset")]
            if assets is not None else []}


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


def with_plan_fingerprint(plan: dict) -> dict:
    """Bind creation to the full server-resolved preview, including credentials."""
    canonical = {key: value for key, value in plan.items()
                 if key not in ("warning", "plan_fingerprint")}
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("utf-8")
    return {**plan, "plan_fingerprint": hashlib.sha256(encoded).hexdigest()}


def build_plan(gmp, request: dict, *, require_scan_setup: bool = True,
               saved_overrides: tuple[dict, ...] = ()) -> dict:
    name = str(request.get("name", "")).strip()
    if not 1 <= len(name) <= 80:
        raise ReviewError("Logical task name must contain 1–80 characters")
    target_ids = request.get("target_ids", [])
    if not isinstance(target_ids, list) or not 1 <= len(target_ids) <= 16:
        raise ReviewError("Select 1–16 source targets")
    target_ids = [require_uuid(x) for x in target_ids]
    if len(set(target_ids)) != len(target_ids):
        raise ReviewError("Duplicate source target")
    config_id = require_uuid(request.get("config_id")) if request.get("config_id") else None
    scanner_id = require_uuid(request.get("scanner_id")) if request.get("scanner_id") else None
    if require_scan_setup and (not config_id or not scanner_id):
        raise ReviewError("Select a scan config and scanner before creating tasks")
    overrides = request.get("overrides", [])
    if not isinstance(overrides, list) or len(overrides) > 128:
        raise ReviewError("Overrides must be a list of at most 128 entries")
    inv = inventory(gmp, include_assets=bool(overrides or saved_overrides))
    for collection, item_id in (("configs", config_id), ("scanners", scanner_id)):
        if item_id and item_id not in {entry["id"] for entry in inv[collection]}:
            raise ReviewError(f"Selected {collection[:-1]} is unavailable")
    if scanner_id and any(entry["id"] == scanner_id and entry["type"] == "3"
                          for entry in inv["scanners"]):
        raise ReviewError("CVE scanners cannot provide trackable child report IDs")
    available_creds = {entry["id"] for entry in inv["credentials"]}
    asset_hosts = {}
    for entry in inv["assets"]:
        identity = entry["ip"] or entry["name"]
        if identity:
            try:
                normalized = host_key(identity)
                asset_hosts[entry["id"]] = normalized
            except ReviewError:
                continue
    source_units = []
    seen_hosts = set()
    for target_id in target_ids:
        response = check_response(gmp.get_target(target_id))
        target = response.find("target")
        if target is None:
            raise ReviewError(f"Target {target_id} not found")
        settings = _target_settings(target)
        for host in settings.pop("hosts"):
            if host in seen_hosts:
                raise ReviewError(f"Host {host} occurs in more than one source target")
            seen_hosts.add(host)
            source_units.append({**settings, "host": host})
    if len(source_units) > 128:
        raise ReviewError("Logical task exceeds 128 hosts")

    by_host = {}
    for item in saved_overrides:
        if not item.get("enabled", True):
            continue
        asset_id = item["asset_id"]
        host = asset_hosts.get(asset_id)
        if host in seen_hosts:
            if item["credential_id"] not in available_creds:
                raise ReviewError(
                    f"Stored credential for {host}/{item['service']} is unavailable. "
                    "Edit or disable its override in Assets > Hosts.")
            key = (host, item["service"])
            previous = by_host.get(key)
            if previous and previous["credential_id"] != item["credential_id"]:
                raise ReviewError(
                    f"Conflicting asset overrides for {host}/{item['service']}: "
                    f"assets {previous['asset_id']} and {asset_id} select different "
                    "credentials. Edit or disable one override in Assets > Hosts.")
            by_host[key] = {
                "credential_id": item["credential_id"], "asset_id": asset_id}
    one_off_hosts = set()
    for item in overrides:
        if not isinstance(item, dict):
            raise ReviewError("Invalid override entry")
        host = host_key(str(item.get("host", "")))
        asset_id = item.get("asset_id")
        if asset_id:
            asset_id = require_uuid(asset_id)
            if asset_hosts.get(asset_id) != host:
                raise ReviewError(f"Asset {asset_id} does not identify {host}")
        service = item.get("service")
        if service not in SERVICES:
            raise ReviewError(f"Unsupported credential service: {service}")
        credential_id = require_uuid(item.get("credential_id"))
        if credential_id not in available_creds:
            raise ReviewError(f"Credential {credential_id} is unavailable")
        key = (host, service)
        if key in by_host:
            if by_host[key]["credential_id"] == credential_id:
                continue
            raise ReviewError(
                f"Conflicting override for {host}/{service}. Edit or disable the "
                "saved override in Assets > Hosts, or remove the task override.")
        by_host[key] = {"credential_id": credential_id, "asset_id": asset_id}
        one_off_hosts.add(host)
    unknown = one_off_hosts - seen_hosts
    if unknown:
        raise ReviewError(f"Override host is outside selected targets: {', '.join(sorted(unknown))}")
    units = []
    for source in source_units:
        host = source["host"]
        credentials = dict(source["credentials"])
        applied = []
        for service in SERVICES:
            selected = by_host.get((host, service))
            if selected:
                credentials[service] = selected["credential_id"]
                applied.append({"service": service, **selected})
        if "ssh_elevate" in credentials and "ssh" not in credentials:
            raise ReviewError(f"SSH elevate credential for {host} needs an SSH credential")
        units.append({**source, "credentials": credentials,
                      "applied_overrides": applied})
    scan_units = []
    by_scan_key = {}
    for unit in units:
        # Never merge different source targets: they may have different port
        # lists, alive tests, exclusions, or other scanner settings.
        key = (unit["id"], tuple(sorted(unit["credentials"].items())))
        if key not in by_scan_key:
            grouped = {**unit, "hosts": [], "applied_overrides": []}
            grouped.pop("host")
            grouped["host_decisions"] = []
            by_scan_key[key] = grouped
            scan_units.append(grouped)
        grouped = by_scan_key[key]
        grouped["hosts"].append(unit["host"])
        grouped["applied_overrides"].extend(unit["applied_overrides"])
        grouped["host_decisions"].append({"host": unit["host"],
                                           "applied_overrides": unit["applied_overrides"]})
    if len(scan_units) > MAX_SCAN_PARTITIONS:
        raise ReviewError(
            f"Plan needs {len(scan_units)} background scans; safety limit is "
            f"{MAX_SCAN_PARTITIONS}. Reduce distinct credential sets or split the plan")
    return with_plan_fingerprint({"name": name, "backend_mode": "enhanced",
                                  "config_id": config_id, "scanner_id": scanner_id,
                                  "units": units, "scan_units": scan_units,
                                  "warning": "Each source-target/credential group is one native gvmd task and report."})


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


def dispatch_state_for_run(run_state: dict | None) -> str:
    if not run_state:
        return "idle"
    if "pending" in run_state:
        return ("queued" if run_state.get("pending") or run_state.get("inflight")
                or run_state.get("launching") else "idle")
    if (run_state.get("state") in ("starting", "active", "failed")
            and not run_state.get("legacy_settled")):
        return "legacy"
    return "idle"


@contextmanager
def database():
    """Commit or roll back a SQLite transaction and always close its handle."""
    connection = sqlite3.connect(DB)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def claim_single_controller():
    """Keep one dispatcher per SQLite database so admission caps remain valid."""
    DB.parent.mkdir(parents=True, exist_ok=True)
    handle = open(DB.with_suffix(DB.suffix + ".lock"), "a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        handle.close()
        raise RuntimeError("Another scan group controller owns this database") from exc
    return handle


def init_db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    with database() as db:
        db.execute("CREATE TABLE IF NOT EXISTS groups (id TEXT PRIMARY KEY, name TEXT NOT NULL, plan TEXT NOT NULL, children TEXT NOT NULL)")
        group_columns = {row[1] for row in db.execute("PRAGMA table_info(groups)")}
        if "native_task_id" not in group_columns:
            db.execute("ALTER TABLE groups ADD COLUMN native_task_id TEXT")
        if "native_error" not in group_columns:
            db.execute("ALTER TABLE groups ADD COLUMN native_error TEXT")
        if "run_state" not in group_columns:
            db.execute("ALTER TABLE groups ADD COLUMN run_state TEXT")
        db.execute("CREATE TABLE IF NOT EXISTS native_reports (group_id TEXT NOT NULL, signature TEXT NOT NULL, report_id TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(group_id, signature), UNIQUE(report_id))")
        db.execute("CREATE TABLE IF NOT EXISTS managed_tasks (task_id TEXT PRIMARY KEY, group_id TEXT NOT NULL)")
        db.execute("CREATE INDEX IF NOT EXISTS managed_tasks_group_idx ON managed_tasks(group_id)")
        for group_id, children_json, logical_id in db.execute(
                "SELECT id, children, native_task_id FROM groups"):
            task_ids = [child["task_id"] for child in json.loads(children_json)]
            if logical_id:
                task_ids.append(logical_id)
            db.executemany("INSERT OR IGNORE INTO managed_tasks (task_id, group_id) VALUES (?, ?)",
                           ((require_uuid(task_id), group_id) for task_id in task_ids))
        db.execute("CREATE TABLE IF NOT EXISTS native_imports (group_id TEXT NOT NULL, signature TEXT NOT NULL, report_id TEXT, previous_report_id TEXT, expected_results INTEGER NOT NULL, state TEXT NOT NULL, failures INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0, error TEXT, PRIMARY KEY(group_id, signature))")
        if "dispatch_state" not in group_columns:
            db.execute("ALTER TABLE groups ADD COLUMN dispatch_state TEXT")
        if "report_state" not in group_columns:
            db.execute("ALTER TABLE groups ADD COLUMN report_state TEXT")
        if "report_due" not in group_columns:
            db.execute("ALTER TABLE groups ADD COLUMN report_due INTEGER NOT NULL DEFAULT 0")
        if "created_at" not in group_columns:
            db.execute("ALTER TABLE groups ADD COLUMN created_at INTEGER")
        if "completed_at" not in group_columns:
            db.execute("ALTER TABLE groups ADD COLUMN completed_at INTEGER")
        # One-time migration of pre-queue groups. Normal dispatch queries use the index.
        for group_id, raw_state in db.execute(
                "SELECT id, run_state FROM groups WHERE dispatch_state IS NULL"):
            run_state = json.loads(raw_state) if raw_state else None
            db.execute("UPDATE groups SET dispatch_state=? WHERE id=?",
                       (dispatch_state_for_run(run_state), group_id))
        db.execute("CREATE INDEX IF NOT EXISTS groups_dispatch_state_idx "
                   "ON groups(dispatch_state)")
        # Old groups are inspected once; subsequent runs are indexed by save_run_state.
        db.execute("UPDATE groups SET report_state='ready' WHERE report_state IS NULL")
        # A killed process cannot still own an in-memory publication lease.
        # The persisted native_imports row prevents a duplicate import.
        db.execute("UPDATE groups SET report_state='ready' WHERE report_state='processing'")
        db.execute("CREATE INDEX IF NOT EXISTS groups_report_due_idx "
                   "ON groups(report_state, report_due)")
        db.execute("CREATE INDEX IF NOT EXISTS groups_report_due_native_idx "
                   "ON groups(report_state, report_due) "
                   "WHERE native_task_id IS NOT NULL")
        db.execute("CREATE TABLE IF NOT EXISTS asset_overrides (asset_id TEXT NOT NULL, service TEXT NOT NULL, credential_id TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(asset_id, service))")
        columns = {row[1] for row in db.execute("PRAGMA table_info(asset_overrides)")}
        if "enabled" not in columns:
            db.execute("ALTER TABLE asset_overrides ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")


def get_saved_overrides(*, include_disabled: bool = False) -> tuple[dict, ...]:
    with database() as db:
        query = "SELECT asset_id, service, credential_id, enabled FROM asset_overrides"
        if not include_disabled:
            query += " WHERE enabled = 1"
        rows = db.execute(query + " ORDER BY asset_id, service").fetchall()
    return tuple({"asset_id": a, "service": s, "credential_id": c,
                  "enabled": bool(enabled)} for a, s, c, enabled in rows)


def save_asset_override(asset_id: str, service: str, credential_id: str):
    asset_id = require_uuid(asset_id)
    credential_id = require_uuid(credential_id)
    if service not in SERVICES:
        raise ReviewError("Unsupported credential service")
    with database() as db:
        db.execute("INSERT INTO asset_overrides (asset_id, service, credential_id, enabled) VALUES (?, ?, ?, 1) ON CONFLICT(asset_id, service) DO UPDATE SET credential_id=excluded.credential_id, enabled=1",
                   (asset_id, service, credential_id))


def set_asset_override_enabled(asset_id: str, service: str, enabled: bool):
    asset_id = require_uuid(asset_id)
    if service not in SERVICES:
        raise ReviewError("Unsupported credential service")
    if not isinstance(enabled, bool):
        raise ReviewError("Override enabled must be true or false")
    with database() as db:
        result = db.execute("UPDATE asset_overrides SET enabled=? WHERE asset_id=? AND service=?",
                            (int(enabled), asset_id, service))
        if result.rowcount != 1:
            raise ReviewError("Override does not exist")


def delete_asset_override(asset_id: str, service: str):
    asset_id = require_uuid(asset_id)
    if service not in SERVICES:
        raise ReviewError("Unsupported credential service")
    with database() as db:
        db.execute("DELETE FROM asset_overrides WHERE asset_id=? AND service=?", (asset_id, service))


def save_group(group_id, plan, children, native_task_id):
    with database() as db:
        db.execute("INSERT INTO groups (id, name, plan, children, native_task_id, "
                   "dispatch_state, report_state, created_at) "
                   "VALUES (?, ?, ?, ?, ?, 'idle', 'idle', ?)",
                   (group_id, plan["name"], json.dumps(plan), json.dumps(children),
                    native_task_id, int(time.time())))
        task_ids = [child["task_id"] for child in children]
        if native_task_id:
            task_ids.append(native_task_id)
        db.executemany("INSERT INTO managed_tasks (task_id, group_id) VALUES (?, ?)",
                       ((require_uuid(task_id), group_id) for task_id in task_ids))


def group_from_row(row) -> dict:
    return {"id": row[0], "name": row[1], "plan": json.loads(row[2]),
            "children": json.loads(row[3]), "native_task_id": row[4],
            "native_error": row[5],
            "run_state": json.loads(row[6]) if row[6] else None}


def get_groups():
    with database() as db:
        rows = db.execute("SELECT id, name, plan, children, native_task_id, native_error, "
                          "run_state FROM groups ORDER BY rowid DESC").fetchall()
    return [group_from_row(row) for row in rows]


def managed_task_ids() -> dict:
    """Return generated task IDs without polling gvmd for scan state."""
    with database() as db:
        rows = db.execute("SELECT task_id FROM managed_tasks ORDER BY task_id").fetchall()
    return {"task_ids": [row[0] for row in rows]}


def require_task_ids(candidate_ids: list[str]) -> list[str]:
    if not isinstance(candidate_ids, list) or len(candidate_ids) > 100:
        raise ReviewError("Submit at most 100 task IDs")
    return [require_uuid(task_id) for task_id in candidate_ids]


def get_groups_for_task_ids(candidate_ids: list[str]) -> list[dict]:
    """Summarize only groups represented on the current GSA page."""
    ids = require_task_ids(candidate_ids)
    if not ids:
        return []
    marks = ",".join("?" for _ in ids)
    with database() as db:
        rows = db.execute(
            "SELECT id, name, plan, children, native_task_id, native_error, run_state "
            "FROM groups WHERE id IN (SELECT group_id FROM managed_tasks "
            f"WHERE task_id IN ({marks})) ORDER BY rowid DESC", ids).fetchall()
    return [group_from_row(row) for row in rows]


def task_membership(candidate_ids: list[str]) -> dict:
    """Return managed IDs to the operator authorized by GSAD and nginx."""
    ids = require_task_ids(candidate_ids)
    if not ids:
        return {"managed_task_ids": []}
    marks = ",".join("?" for _ in ids)
    with database() as db:
        rows = db.execute(f"SELECT task_id FROM managed_tasks WHERE task_id IN ({marks})",
                          ids).fetchall()
    return {"managed_task_ids": sorted(row[0] for row in rows)}


def get_dispatch_groups():
    with database() as db:
        rows = db.execute("SELECT id, name, plan, children, native_task_id, native_error, "
                          "run_state FROM groups WHERE dispatch_state IN ('queued', 'legacy') "
                          "ORDER BY rowid DESC").fetchall()
    return [group_from_row(row) for row in rows]


def outstanding_child_count(*, exclude_group: str | None = None) -> int:
    """Count native children still awaiting a completed or cancelled run."""
    total = 0
    for group in get_dispatch_groups():
        if group["id"] == exclude_group:
            continue
        run = group.get("run_state")
        if run is None:
            continue  # Unstarted groups do not consume dispatch capacity.
        elif "pending" in run:
            total += len(run["pending"]) + len(run["inflight"])
        elif run.get("state") in ("starting", "active", "failed") and not run.get("legacy_settled"):
            total += len(group["children"])  # Conservative until legacy run is reconciled.
    return total


def save_run_state(group_id: str, run_state: dict):
    with database() as db:
        report_state = "ready" if run_state.get("state") == "done" else "idle"
        if db.execute("UPDATE groups SET run_state=?, dispatch_state=?, "
                      "report_state=CASE WHEN report_state='processing' THEN 'processing' "
                      "ELSE ? END, report_due=0, completed_at=? WHERE id=?",
                      (json.dumps(run_state), dispatch_state_for_run(run_state),
                       report_state,
                       int(time.time()) if run_state.get("state") == "done" else None,
                       group_id)).rowcount != 1:
            raise ReviewError("Unknown scan group")


def get_report_candidates(limit: int = 2) -> list[dict]:
    with database() as db:
        rows = db.execute("SELECT id, name, plan, children, native_task_id, native_error, "
                          "run_state FROM groups WHERE native_task_id IS NOT NULL "
                          "AND report_state IN ('ready', 'pending') "
                          "AND report_due <= ? ORDER BY report_due, rowid LIMIT ?",
                          (int(time.time()), limit)).fetchall()
    return [group_from_row(row) for row in rows]


def recover_starting_run(group: dict) -> dict:
    """Recover a launch interrupted after its state was saved to disk."""
    run_state = group.get("run_state")
    if not run_state or run_state.get("state") != "starting":
        return group
    child_ids = {child["task_id"] for child in group["children"]}
    reports = run_state.get("reports", {})
    run_state = copy.deepcopy(run_state)
    if (set(reports) == child_ids and
            all(UUID_RE.fullmatch(report_id) for report_id in reports.values())):
        run_state["state"] = "active"
    else:
        run_state["state"] = "failed"
        run_state["failed"] = run_state.get("failed", []) + [{
            "task_id": child_id,
            "error": "Controller interrupted while starting scans; inspect child tasks before retrying"}
            for child_id in sorted(child_ids - set(reports) or child_ids)]
    save_run_state(group["id"], run_state)
    return {**group, "run_state": run_state}


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
    with database() as db:
        changed = db.execute("UPDATE groups SET native_task_id=? WHERE id=? AND native_task_id IS NULL",
                             (task_id, group["id"])).rowcount
        if changed == 1:
            db.execute("INSERT INTO managed_tasks (task_id, group_id) VALUES (?, ?)",
                       (task_id, group["id"]))
    if changed != 1:
        check_response(gmp.delete_task(task_id, ultimate=True))
        return group_by_id(group["id"])["native_task_id"]
    return task_id


def native_report_for_group(group_id: str) -> dict | None:
    if not DB.exists():
        return None
    with database() as db:
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
    with database() as db:
        row = db.execute("SELECT id, name, plan, children, native_task_id, native_error, "
                         "run_state FROM groups WHERE id=?", (group_id,)).fetchone()
    if row is None:
        raise ReviewError("Unknown scan group")
    return group_from_row(row)


def group_summary(gmp, group: dict) -> dict:
    """Describe one logical group while retaining native task/report identities."""
    if group.get("plan", {}).get("native_backend"):
        return native_group_summary(gmp, group)
    children = []
    run_state = group.get("run_state")
    expected_reports = (run_state or {}).get("reports", {})
    for child in group["children"]:
        hosts = child.get("hosts") or [child["host"]]
        entry = {"host": ", ".join(hosts), "hosts": hosts, "task_id": child["task_id"],
                 "target_id": child["target_id"], "status": "Unavailable",
                 "report_id": None}
        if run_state and child["task_id"] in run_state.get("pending", []):
            entry["status"] = "Queued"
            children.append(entry)
            continue
        try:
            task = check_response(gmp.get_task(child["task_id"])).find("task")
            if task is None:
                raise ReviewError("Task is missing")
            entry["status"] = child_text(task, "status", "Unknown")
            last_report = task.find("./last_report/report")
            if last_report is not None and last_report.get("id"):
                entry["report_id"] = require_uuid(last_report.get("id"))
            if run_state and entry["report_id"] != expected_reports.get(child["task_id"]):
                entry["report_id"] = None
                entry["error"] = "No completed report for the current run"
        except (ReviewError, ValueError, ET.ParseError) as exc:
            entry["error"] = str(exc)
        children.append(entry)
    statuses = [child["status"] for child in children]
    if run_state and run_state["state"] == "failed":
        status = "Attention needed"
    elif run_state and run_state["state"] == "stopped":
        status = "Stopped"
    elif run_state and run_state["state"] == "queued":
        status = "Queued"
    elif run_state and run_state.get("pending"):
        status = "Running"
    elif (statuses and all(status == "Done" for status in statuses)
          and all(child["report_id"] for child in children)):
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
    import_row = None
    if DB.exists():
        with database() as db:
            import_row = db.execute(
                "SELECT state FROM native_imports WHERE group_id=? ORDER BY rowid DESC LIMIT 1",
                (group["id"],)).fetchone()
    return {"id": group["id"], "name": group["name"], "status": status,
            "native_task_id": group.get("native_task_id"),
            "native_report_id": native_report["id"] if native_report else None,
            "native_import_state": import_row[0] if import_row else None,
            "native_error": group.get("native_error") or
                            "; ".join(item["error"] for item in run_state.get("failed", []))
                            if run_state else group.get("native_error"),
            "host_count": sum(len(child["hosts"]) for child in children),
            "done_count": sum(len(child["hosts"]) for child in children
                              if child["status"] == "Done" and child["report_id"]),
            "report_count": sum(bool(child["report_id"]) for child in children),
            "children": children}


def native_group_record(gmp, group: dict) -> ET.Element:
    parent_id = require_uuid(group["native_task_id"])
    response = check_response(gmp.send_command(
        f'<get_multi_target_tasks task_id="{parent_id}" rows="1"/>'))
    record = response.find("multi_target_task")
    if record is None or record.get("id") != parent_id:
        raise GroupConflictError("Native multi-target task is unavailable")
    return record


def native_group_summary(gmp, group: dict) -> dict:
    record = native_group_record(gmp, group)
    native_children = record.findall("child")
    if len(native_children) != len(group["children"]):
        raise GroupConflictError("Native child mapping changed")
    names = {"new": "New", "pending": "Queued", "starting": "Requested",
             "running": "Running", "done": "Done", "failed": "Interrupted",
             "uncertain": "Attention needed", "stopped": "Stopped",
             "canceled": "Stopped"}
    children = []
    for saved, native in zip(group["children"], native_children):
        if (native.get("task_id") != saved["task_id"] or
                native.get("target_id") != saved["target_id"] or
                native.get("source_target_id") != saved["source_target_id"]):
            raise GroupConflictError("Native child identity changed")
        hosts = saved.get("hosts") or [saved["host"]]
        state = native.get("state", "new")
        report_id = native.get("report_id") if state == "done" else None
        children.append({"host": ", ".join(hosts), "hosts": hosts,
                         "task_id": saved["task_id"],
                         "target_id": saved["target_id"],
                         "status": names.get(state, "Attention needed"),
                         "report_id": require_uuid(report_id) if report_id else None})
    run_state = record.get("run_state", "new")
    status = {"new": "New", "queued": "Queued", "running": "Running",
              "done": "Done", "partial": "Attention needed",
              "blocked": "Attention needed", "stopping": "Running",
              "stopped": "Stopped"}.get(run_state, "Attention needed")
    native_report = native_report_for_group(group["id"])
    with database() as db:
        import_row = db.execute(
            "SELECT state FROM native_imports WHERE group_id=? ORDER BY rowid DESC LIMIT 1",
            (group["id"],)).fetchone()
        if status == "Done" and all(child["report_id"] for child in children):
            signature = hashlib.sha256("\n".join(
                child["report_id"] for child in children).encode()).hexdigest()
            imported = db.execute(
                "SELECT 1 FROM native_reports WHERE group_id=? AND signature=?",
                (group["id"], signature)).fetchone()
            if not imported:
                db.execute("UPDATE groups SET report_state='ready', report_due=0 "
                           "WHERE id=? AND report_state='idle'", (group["id"],))
    return {"id": group["id"], "name": group["name"], "status": status,
            "native_task_id": group["native_task_id"],
            "native_report_id": native_report["id"] if native_report else None,
            "native_import_state": import_row[0] if import_row else None,
            "native_error": group.get("native_error") or (
                "Native scan start requires operator review" if run_state == "blocked" else None),
            "host_count": sum(len(child["hosts"]) for child in children),
            "done_count": sum(len(child["hosts"]) for child in children
                              if child["status"] == "Done" and child["report_id"]),
            "report_count": sum(bool(child["report_id"]) for child in children),
            "children": children}


def report_signature(summary: dict) -> str:
    report_ids = [item["report_id"] for item in summary["children"]]
    if (summary["status"] != "Done" or not report_ids
            or any(report_id is None for report_id in report_ids)):
        raise ReviewError("All host scans must be complete before publishing one report")
    return hashlib.sha256("\n".join(report_ids).encode()).hexdigest()


def unfiltered_result_count(gmp, report_id: str) -> int:
    response = check_response(gmp.get_results(
        filter_string=f"report_id={require_uuid(report_id)} min_qod=0 "
                      "apply_overrides=0 first=1 rows=1", details=False))
    value = response.findtext("result_count/filtered")
    if value is None or not value.isdigit():
        raise ReviewError("Source report result count is unavailable")
    return int(value)


def imported_report_status(gmp, report_id: str) -> str:
    """Check the import report itself, not a task status from an earlier run."""
    response = check_response(gmp.get_report(
        require_uuid(report_id), details=False, ignore_pagination=False,
        filter_string="first=1 rows=1"))
    outer = response.find("report")
    if outer is None:
        raise ReviewError("Native imported report is unavailable")
    visible_id = outer.get("id") or (
        outer.find("report").get("id") if outer.find("report") is not None else None)
    if not visible_id or require_uuid(visible_id) != report_id:
        raise ReviewError("Native imported report identity changed")
    status = (outer.findtext("scan_run_status")
              or outer.findtext("./report/scan_run_status"))
    if not status:
        raise ReviewError("Native imported report status is unavailable")
    return status


def paged_source_report(gmp, child: dict, expected_count: int) -> ET.Element:
    """Bound each GMP response and aggregate at most the approved result count."""
    inner = None
    received = 0
    bytes_received = 0
    for first in range(1, max(expected_count, 1) + 1, NATIVE_REPORT_PAGE_SIZE):
        rows = min(NATIVE_REPORT_PAGE_SIZE, expected_count - received) if expected_count else 1
        raw = gmp.get_report(
            child["report_id"], details=True, ignore_pagination=False,
            filter_string=f"min_qod=0 apply_overrides=0 first={first} rows={rows}")
        bytes_received += len(raw.encode("utf-8"))
        if bytes_received > NATIVE_REPORT_XML_LIMIT:
            raise ReviewError("Native review import exceeds 25 MiB; host reports remain available")
        response = check_response(raw)
        outer = response.find("report")
        page = outer.find("report") if outer is not None else None
        if page is None or page.find("results") is None:
            raise ReviewError(f"Native source report {child['report_id']} is incomplete")
        page_results = page.findall("./results/result")
        if len(page_results) > rows:
            raise ReviewError("Source report returned more results than requested")
        if inner is None:
            inner = page
        else:
            inner.find("results").extend(page_results)
        received += len(page_results)
        if expected_count and not page_results:
            raise ReviewError("Source report pagination ended before its result count")
    if inner is None or received != expected_count:
        raise ReviewError("Source report result count changed during import")
    return inner


def import_attempt(group_id: str, signature: str) -> dict | None:
    with database() as db:
        row = db.execute(
            "SELECT report_id, previous_report_id, expected_results, state, failures, "
            "next_attempt, error FROM native_imports WHERE group_id=? AND signature=?",
            (group_id, signature)).fetchone()
    if row is None:
        return None
    return dict(zip(("report_id", "previous_report_id", "expected_results", "state",
                     "failures", "next_attempt", "error"), row))


def mark_import_failure(group_id: str, signature: str, error: str, *,
                        permanent: bool = False) -> None:
    with database() as db:
        row = db.execute("SELECT failures FROM native_imports WHERE group_id=? AND signature=?",
                         (group_id, signature)).fetchone()
        failures = (row[0] if row else 0) + 1
        delay = min(NATIVE_REPORT_RETRY_MAX,
                    NATIVE_REPORT_RETRY_BASE * (2 ** min(failures - 1, 6)))
        db.execute("INSERT INTO native_imports "
                   "(group_id, signature, expected_results, state, failures, next_attempt, error) "
                   "VALUES (?, ?, 0, ?, ?, ?, ?) "
                   "ON CONFLICT(group_id, signature) DO UPDATE SET "
                   "state=excluded.state, failures=excluded.failures, "
                   "next_attempt=excluded.next_attempt, error=excluded.error",
                   (group_id, signature, "blocked" if permanent else "failed",
                    failures, int(time.time()) + delay, error[:500]))
        db.execute("UPDATE groups SET native_error=?, report_state=?, report_due=? "
                   "WHERE id=?", (error[:500], "blocked" if permanent else "ready",
                                  int(time.time()) + delay, group_id))


def reconcile_import(gmp, group: dict, signature: str, attempt: dict) -> dict:
    """Publish only after the specific asynchronous gvmd import is complete."""
    report_id = attempt["report_id"]
    if attempt["state"] == "creating":
        status, current_report = task_state(gmp, group["native_task_id"])
        if current_report and current_report != attempt["previous_report_id"]:
            report_id = current_report
            with database() as db:
                db.execute("UPDATE native_imports SET report_id=?, state='pending' "
                           "WHERE group_id=? AND signature=?",
                           (report_id, group["id"], signature))
        elif status in ACTIVE_TASK_STATUSES:
            with database() as db:
                db.execute("UPDATE groups SET report_state='pending', report_due=? WHERE id=?",
                           (int(time.time()) + 30, group["id"]))
            return {"state": "pending", "report_id": None}
        else:
            with database() as db:
                db.execute("UPDATE groups SET native_error=?, report_state='blocked' "
                           "WHERE id=?",
                           ("Native report import start is uncertain; inspect the logical task",
                            group["id"]))
            raise GroupConflictError(
                "Report import start is uncertain; inspect the logical native task before retrying")
    if not report_id:
        raise GroupConflictError("Report import ID is unavailable")
    status, current_report = task_state(gmp, group["native_task_id"])
    if status == "Interrupted" and current_report == report_id:
        mark_import_failure(group["id"], signature,
                            "Native report import was interrupted")
        return {"state": "failed", "report_id": report_id}
    if status != "Done" or current_report != report_id:
        # A slow accepted import may still be running beyond the initial
        # deadline. Never remove its report and submit a competing import.
        if status in ACTIVE_TASK_STATUSES:
            with database() as db:
                db.execute("UPDATE groups SET report_state='pending', report_due=? WHERE id=?",
                           (int(time.time()) + 30, group["id"]))
            return {"state": "pending", "report_id": report_id}
        if int(time.time()) >= attempt["next_attempt"]:
            mark_import_failure(group["id"], signature,
                                "Native report import did not complete before its timeout")
            return {"state": "failed", "report_id": report_id}
        with database() as db:
            db.execute("UPDATE groups SET report_state='pending', report_due=? WHERE id=?",
                       (int(time.time()) + 30, group["id"]))
        return {"state": "pending", "report_id": report_id}
    try:
        report_status = imported_report_status(gmp, report_id)
    except (ReviewError, ValueError, ET.ParseError):
        # A missing or temporarily unreadable report is not proof that an
        # accepted asynchronous import has ended.
        with database() as db:
            db.execute("UPDATE groups SET report_state='pending', report_due=? WHERE id=?",
                       (int(time.time()) + 30, group["id"]))
        return {"state": "pending", "report_id": report_id}
    if report_status != "Done":
        if report_status not in ("Interrupted", "Stopped"):
            with database() as db:
                db.execute("UPDATE groups SET report_state='pending', report_due=? WHERE id=?",
                           (int(time.time()) + 30, group["id"]))
            return {"state": "pending", "report_id": report_id}
        mark_import_failure(group["id"], signature,
                            f"Native report import ended with {report_status}")
        return {"state": "failed", "report_id": report_id}
    count = unfiltered_result_count(gmp, report_id)
    if count != attempt["expected_results"]:
        mark_import_failure(group["id"], signature,
                            "Native report import result count does not match source reports")
        return {"state": "failed", "report_id": report_id}
    with database() as db:
        db.execute("INSERT OR IGNORE INTO native_reports "
                   "(group_id, signature, report_id, created_at) VALUES (?, ?, ?, ?)",
                   (group["id"], signature, report_id, int(time.time())))
        db.execute("DELETE FROM native_imports WHERE group_id=? AND signature=?",
                   (group["id"], signature))
        db.execute("UPDATE groups SET native_error=NULL, report_state='idle', "
                   "report_due=0 WHERE id=?", (group["id"],))
    return {"state": "complete", "report_id": report_id}


def publish_native_report(gmp, group: dict, *, manual: bool = False) -> dict | None:
    """Publish a completed run in the normal gvmd Reports list.

    Source reports remain authoritative: GMP import does not preserve every
    internal relation, so this review path has a strict size limit.
    """
    group = recover_starting_run(group)
    summary = group_summary(gmp, group)
    if group.get("run_state") and group["run_state"]["state"] not in ("active", "done"):
        with database() as db:
            db.execute("UPDATE groups SET report_state='idle' WHERE id=?", (group["id"],))
        return None
    if summary["status"] != "Done" or summary["report_count"] != len(summary["children"]):
        with database() as db:
            db.execute("UPDATE groups SET report_state=?, report_due=? WHERE id=?",
                       ("pending" if summary["status"] == "Running" else "idle",
                        int(time.time()) + 30, group["id"]))
        return None
    signature = report_signature(summary)
    with database() as db:
        existing = db.execute("SELECT report_id FROM native_reports WHERE group_id=? AND signature=?",
                              (group["id"], signature)).fetchone()
    if existing:
        with database() as db:
            db.execute("UPDATE groups SET report_state='idle', report_due=0 "
                       "WHERE id=?", (group["id"],))
        return {"report_id": existing[0], "signature": signature, "existing": True}

    native_task_id = attach_native_task(gmp, group)
    attempt = import_attempt(group["id"], signature)
    if attempt and attempt["state"] in ("pending", "creating"):
        return {**reconcile_import(gmp, group, signature, attempt),
                "signature": signature, "existing": True}
    if attempt and not manual and (attempt["state"] == "blocked"
                                   or attempt["next_attempt"] > int(time.time())):
        return {"state": attempt["state"], "signature": signature,
                "error": attempt["error"], "existing": True}
    if attempt:
        if attempt["report_id"]:
            delete_native_resource(gmp, "delete_report", attempt["report_id"])
        with database() as db:
            db.execute("DELETE FROM native_imports WHERE group_id=? AND signature=?",
                       (group["id"], signature))

    sources = []
    result_total = 0
    try:
        for child in summary["children"]:
            count = unfiltered_result_count(gmp, child["report_id"])
            result_total += count
            if result_total > NATIVE_REPORT_RESULT_LIMIT:
                raise ReviewError("Native review import exceeds 10000 results; host reports remain available")
            inner = paged_source_report(gmp, child, count)
            expected_hosts = set(child["hosts"])
            report_hosts = inner.findall("./host")
            source_results = inner.findall("./results/result")
            report_host_ips = {host.findtext("ip") for host in report_hosts}
            if (not report_host_ips.issubset(expected_hosts)
                    or any(result.findtext("host") not in report_host_ips
                           for result in source_results)):
                raise ReviewError(f"Source host metadata for {child['host']} is incomplete")
            if any(result.findtext("host") not in expected_hosts
                   for result in source_results):
                raise ReviewError(f"Source results contain a host outside {child['host']}")
            sources.append((child, inner))
    except Exception as exc:
        mark_import_failure(group["id"], signature, str(exc),
                            permanent="exceeds" in str(exc))
        raise

    try:
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
    except Exception as exc:
        mark_import_failure(group["id"], signature, str(exc),
                            permanent=isinstance(exc, ReviewError))
        raise
    _, previous_report = task_state(gmp, native_task_id)
    with database() as db:
        db.execute("INSERT INTO native_imports "
                   "(group_id, signature, previous_report_id, expected_results, state, next_attempt) "
                   "VALUES (?, ?, ?, ?, 'creating', ?)",
                   (group["id"], signature, previous_report, result_total,
                    int(time.time()) + 600))
    response = ET.fromstring(gmp.send_command(payload))
    if not response.get("status", "").startswith("2"):
        # A concrete GMP rejection is definitive; network and parse errors
        # remain ambiguous and retain the durable creating marker.
        with database() as db:
            db.execute("DELETE FROM native_imports WHERE group_id=? AND signature=?",
                       (group["id"], signature))
        mark_import_failure(group["id"], signature,
                            "Native report import was rejected: " +
                            response.get("status_text", response.get("status", "")))
        raise ReviewError("Native report import was rejected by gvmd")
    report_id = require_uuid(response.get("id"))
    with database() as db:
        db.execute("UPDATE native_imports SET report_id=?, state='pending' "
                   "WHERE group_id=? AND signature=?", (report_id, group["id"], signature))
        db.execute("UPDATE groups SET native_error=NULL, report_state='pending', "
                   "report_due=? WHERE id=?", (int(time.time()) + 30, group["id"]))
    return {"report_id": report_id, "signature": signature,
            "state": "pending", "existing": False}


def synchronize_native_reports() -> None:
    """Background reconciliation keeps completed runs in native Reports."""
    while True:
        try:
            for candidate in get_report_candidates():
                if not candidate.get("native_task_id"):
                    continue
                with REPORT_LOCK:
                    with MUTATION_LOCK, database() as db:
                        reserved = db.execute(
                            "UPDATE groups SET report_state='processing' WHERE id=? "
                            "AND report_state IN ('ready', 'pending') AND report_due<=?",
                            (candidate["id"], int(time.time()))).rowcount == 1
                        if not reserved:
                            continue
                        group = group_by_id(candidate["id"])
                    try:
                        with manager() as gmp:
                            publish_native_report(gmp, group)
                    except Exception as exc:
                        with database() as db:
                            db.execute("UPDATE groups SET native_error=? WHERE id=?",
                                       (str(exc)[:500], group["id"]))
                    finally:
                        with database() as db:
                            db.execute("UPDATE groups SET report_state='ready', report_due=? "
                                       "WHERE id=? AND report_state='processing'",
                                       (int(time.time()) + 30, group["id"]))
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
            child.setdefault("error", "A child report is unavailable")
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
                    "complete": summary["status"] == "Done" and
                                not any(child.get("error") for child in summary["children"])})
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


def require_expected_scan_count(body: dict, plan: dict) -> None:
    expected = body.get("expected_scan_count")
    if type(expected) is not int or expected < 1 or expected > MAX_SCAN_PARTITIONS:
        raise ReviewError("Create requires a valid expected_scan_count from preview; reload GSA and preview again")
    if expected != len(plan["scan_units"]):
        raise PlanChangedError(
            "Scan plan changed since preview; review the background scan count and try again")
    fingerprint = body.get("expected_plan_fingerprint")
    if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
        raise ReviewError("Create requires a valid expected_plan_fingerprint from preview; reload GSA and preview again")
    if fingerprint != plan["plan_fingerprint"]:
        raise PlanChangedError(
            "Scan plan changed since preview; review the background scans and try again")


def create_group(gmp, plan: dict) -> dict:
    if NATIVE_BACKEND:
        return create_native_group(gmp, plan)
    group_id = str(uuid.uuid4())
    children = []
    native_task_id = None
    try:
        scan_units = plan.get("scan_units", plan["units"])
        if len(scan_units) > MAX_SCAN_PARTITIONS:
            raise ReviewError(f"Plan needs {len(scan_units)} background scans; safety limit is {MAX_SCAN_PARTITIONS}")
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


def create_native_group(gmp, plan: dict) -> dict:
    """Let gvmd own the parent, children, and queue; keep GUI metadata here."""
    group_id = str(uuid.uuid4())
    children = []
    parent_id = None
    scan_units = plan.get("scan_units", plan["units"])
    if not 1 <= len(scan_units) <= MAX_SCAN_PARTITIONS:
        raise ReviewError("Select 1 to 16 background scans")
    try:
        for unit in scan_units:
            target_response = check_response(gmp.send_command(target_xml(group_id, unit)))
            target_id = require_uuid(target_response.get("id"))
            hosts = unit.get("hosts") or [unit["host"]]
            children.append({"host": ", ".join(hosts), "hosts": hosts,
                             "target_id": target_id, "source_target_id": unit["id"],
                             "credentials": unit["credentials"],
                             "applied_overrides": unit["applied_overrides"],
                             "host_decisions": unit.get("host_decisions", [])})
        mode = ("overrides" if any(child["applied_overrides"] for child in children)
                else "targets")
        request = ET.Element("create_multi_target_task", {
            "name": plan["name"], "config_id": plan["config_id"],
            "scanner_id": plan["scanner_id"], "mode": mode})
        for child in children:
            ET.SubElement(request, "target", {
                "id": child["target_id"],
                "source_target_id": child["source_target_id"]})
        response = check_response(gmp.send_command(
            ET.tostring(request, encoding="unicode")))
        parent_id = require_uuid(response.get("id"))
        record = native_group_record(gmp, {"native_task_id": parent_id})
        native_children = record.findall("child")
        if len(native_children) != len(children):
            raise GroupConflictError("Native manager returned an incomplete child mapping")
        for saved, native in zip(children, native_children):
            if (native.get("target_id") != saved["target_id"] or
                    native.get("source_target_id") != saved["source_target_id"]):
                raise GroupConflictError("Native manager returned a changed child mapping")
            saved["task_id"] = require_uuid(native.get("task_id"))
        plan = {**plan, "native_backend": True}
        save_group(group_id, plan, children, parent_id)
    except Exception as exc:
        if parent_id:
            raise GroupConflictError(
                f"Native task {parent_id} was created but GUI registration failed: {exc}") from exc
        for child in reversed(children):
            try:
                gmp.delete_target(child["target_id"], ultimate=True)
            except Exception:
                pass
        raise
    # Return the same complete shape as subsequent reads.  Callers can
    # immediately start or summarize the new native task without falling
    # through the legacy controller queue.
    return group_by_id(group_id)


def start_group(gmp, group: dict) -> dict:
    if group.get("plan", {}).get("native_backend"):
        with database() as db:
            if db.execute("SELECT 1 FROM native_imports WHERE group_id=? "
                          "AND state IN ('creating', 'pending') LIMIT 1",
                          (group["id"],)).fetchone():
                raise GroupConflictError("Resolve the combined report import before restarting")
        check_response(gmp.start_task(require_uuid(group["native_task_id"])))
        with database() as db:
            db.execute("UPDATE groups SET native_error=NULL WHERE id=?", (group["id"],))
        return {"queued": [child["task_id"] for child in group["children"]],
                "started": [], "failed": []}
    group = recover_starting_run(group)
    with database() as db:
        if db.execute("SELECT 1 FROM native_imports WHERE group_id=? "
                      "AND state IN ('creating', 'pending') LIMIT 1",
                      (group["id"],)).fetchone():
            raise GroupConflictError("Resolve the native report import before starting a new run")
        if db.execute("SELECT 1 FROM groups WHERE id=? AND report_state='processing'",
                      (group["id"],)).fetchone():
            raise GroupConflictError("Report publication is in progress")
    if (outstanding_child_count(exclude_group=group["id"]) + len(group["children"])
            > MAX_OUTSTANDING_CHILDREN):
        raise ReviewError(f"Outstanding scan safety limit is {MAX_OUTSTANDING_CHILDREN} children")
    previous = group.get("run_state")
    if previous and (previous.get("pending") or previous.get("inflight") or
                     previous.get("launching")):
        raise ReviewError("This multi-target task already has queued or active host scans")
    summary = group_summary(gmp, group)
    if any(child["status"] in ACTIVE_TASK_STATUSES
           for child in summary["children"]):
        raise ReviewError("This multi-target task already has active host scans")
    pending = [child["task_id"] for child in group["children"]]
    run_state = {"id": str(uuid.uuid4()), "state": "queued", "reports": {},
                 "pending": pending, "inflight": [], "launching": None,
                 "failed": [], "last_dispatch": 0}
    with database() as db:
        db.execute("UPDATE groups SET native_error=NULL WHERE id=?", (group["id"],))
    save_run_state(group["id"], run_state)
    return {"queued": pending, "started": [], "failed": []}


def task_state(gmp, task_id: str) -> tuple[str, str | None]:
    response = ET.fromstring(gmp.get_task(task_id))
    if response.get("status") == "404":
        raise MissingTaskError(f"Child task {task_id} is missing")
    status = response.get("status", "")
    if not status.startswith("2"):
        raise ReviewError(f"GMP {response.tag}: {status} {response.get('status_text', '')}")
    task = response.find("task")
    if task is None:
        raise ReviewError(f"Child task {task_id} response is incomplete")
    last_report = task.find("./last_report/report")
    report_id = (require_uuid(last_report.get("id")) if last_report is not None
                 and last_report.get("id") else None)
    return child_text(task, "status", "Unknown"), report_id


def confirmed_missing_task(gmp, task_id: str) -> bool:
    """Require two authenticated missing responses before releasing a slot."""
    try:
        task_state(gmp, task_id)
    except MissingTaskError:
        return True
    except (ReviewError, ValueError, ET.ParseError):
        pass
    return False


def dispatch_scan_queue_once(gmp) -> list[str]:
    """Reconcile durable launches, then fairly start within the slot limits.

    The caller holds MUTATION_LOCK. A persisted launching marker prevents a
    restart from issuing the same GMP start twice after an ambiguous reply.
    """
    groups = get_dispatch_groups()
    active_total = 0
    active_by_scanner = {}
    ready = []
    for group in groups:
        if (group.get("run_state") or {}).get("state") == "starting":
            group = recover_starting_run(group)
        run = group.get("run_state")
        if not run:
            continue
        if "pending" not in run:
            # Legacy runs may already have active scanner jobs when upgraded.
            if run.get("state") in ("starting", "active", "failed") and not run.get("legacy_settled"):
                statuses = []
                for child in group["children"]:
                    try:
                        status, _ = task_state(gmp, child["task_id"])
                    except MissingTaskError:
                        status = ("Missing" if confirmed_missing_task(gmp, child["task_id"])
                                  else "Unknown")
                    except (ReviewError, ValueError, ET.ParseError):
                        status = "Unknown"
                    statuses.append(status)
                occupied = sum(status in ACTIVE_TASK_STATUSES or status == "Unknown"
                               for status in statuses)
                scanner_id = group["plan"].get("scanner_id")
                active_total += occupied
                active_by_scanner[scanner_id] = active_by_scanner.get(scanner_id, 0) + occupied
                if not occupied:
                    updated = copy.deepcopy(run)
                    if updated["state"] != "failed":
                        updated["state"] = ("done" if statuses and all(
                            status == "Done" for status in statuses) else "failed")
                    updated["legacy_settled"] = True
                    save_run_state(group["id"], updated)
            continue
        run = copy.deepcopy(run)
        if run.get("launching"):
            marker = run["launching"]
            task_id = marker["task_id"]
            try:
                status, report_id = task_state(gmp, task_id)
                if report_id and report_id != marker.get("previous_report"):
                    run["reports"][task_id] = report_id
                    run["launching"] = None
                else:
                    run["state"] = "failed"
                    run["pending"] = []
                    if not any(item["task_id"] == task_id for item in run["failed"]):
                        run["failed"].append({"task_id": task_id,
                                              "error": "Ambiguous scan start; inspect child task before retrying"})
                    # Even a terminal status may belong to the previous run.
                    # Hold capacity until a new report or verified deletion;
                    # never retry an ambiguous GMP start automatically.
            except MissingTaskError:
                if confirmed_missing_task(gmp, task_id):
                    run["state"] = "failed"
                    run["pending"] = []
                    run["launching"] = None
                    run["inflight"].remove(task_id)
                    run["failed"].append({"task_id": task_id,
                                          "error": "Child task was deleted during scan start"})
            except (ReviewError, ValueError, ET.ParseError):
                # Keep the slot reserved until GMP becomes readable again.
                pass
        for task_id in list(run["inflight"]):
            if (run.get("launching") or {}).get("task_id") == task_id:
                continue
            try:
                status, report_id = task_state(gmp, task_id)
            except MissingTaskError:
                if confirmed_missing_task(gmp, task_id):
                    run["inflight"].remove(task_id)
                    run["state"] = "failed"
                    run["pending"] = []
                    run["failed"].append({"task_id": task_id,
                                          "error": "Child task was deleted while scan was active"})
                continue
            except (ReviewError, ValueError, ET.ParseError):
                continue  # Unknown state must still occupy capacity.
            if status in ACTIVE_TASK_STATUSES or status == "Unknown":
                continue
            run["inflight"].remove(task_id)
            if status != "Done" or report_id != run["reports"].get(task_id):
                if run["state"] != "stopping":
                    run["state"] = "failed"
                    run["pending"] = []
                    run["failed"].append({"task_id": task_id,
                                          "error": f"Child scan ended with status {status}"})
        if run["state"] == "stopping" and not run["inflight"]:
            run["state"] = "stopped"
        elif run["state"] in ("active", "queued") and not run["pending"] and not run["inflight"]:
            run["state"] = "done"
        if run != group["run_state"]:
            save_run_state(group["id"], run)
        scanner_id = group["plan"].get("scanner_id")
        active_total += len(run["inflight"])
        active_by_scanner[scanner_id] = (active_by_scanner.get(scanner_id, 0) +
                                         len(run["inflight"]))
        if run["state"] in ("queued", "active") and run["pending"] and len(run["inflight"]) < MAX_GROUP_ACTIVE_CHILDREN:
            ready.append((run["last_dispatch"], group["id"], scanner_id, run))

    started = []
    for _, group_id, scanner_id, run in sorted(ready):
        if active_total >= MAX_GLOBAL_ACTIVE_CHILDREN:
            break
        if active_by_scanner.get(scanner_id, 0) >= MAX_SCANNER_ACTIVE_CHILDREN:
            continue
        task_id = run["pending"][0]
        try:
            status, previous_report = task_state(gmp, task_id)
        except MissingTaskError:
            if confirmed_missing_task(gmp, task_id):
                run["state"] = "failed"
                run["pending"] = []
                run["failed"].append({"task_id": task_id,
                                      "error": "Queued child task was deleted"})
                save_run_state(group_id, run)
            continue
        except (ReviewError, ValueError, ET.ParseError):
            continue  # One unreadable group must not block other queued groups.
        if status in ACTIVE_TASK_STATUSES:
            run["state"] = "failed"
            run["pending"] = []
            run["inflight"].append(task_id)
            run["failed"].append({"task_id": task_id,
                                  "error": "Child task was started outside this scan group"})
            save_run_state(group_id, run)
            active_total += 1
            active_by_scanner[scanner_id] = active_by_scanner.get(scanner_id, 0) + 1
            continue
        run["pending"].pop(0)
        run["launching"] = {"task_id": task_id, "previous_report": previous_report}
        run["inflight"].append(task_id)
        run["last_dispatch"] = time.time_ns()
        run["state"] = "active"
        save_run_state(group_id, run)
        active_total += 1
        active_by_scanner[scanner_id] = active_by_scanner.get(scanner_id, 0) + 1
        try:
            response = check_response(gmp.start_task(task_id))
            run["reports"][task_id] = require_uuid(response.findtext("report_id"))
            run["launching"] = None
            save_run_state(group_id, run)
            started.append(task_id)
        except Exception as exc:
            # GMP may have accepted the start before the connection failed.
            # Leave launching/inflight persisted; never retry automatically.
            run["state"] = "failed"
            run["pending"] = []
            run["failed"].append({"task_id": task_id,
                                  "error": f"Scan start uncertain: {exc}"})
            save_run_state(group_id, run)
    return started


def dispatch_scan_queue() -> None:
    while True:
        try:
            with MUTATION_LOCK, manager() as gmp:
                dispatch_scan_queue_once(gmp)
        except Exception:
            pass  # GMP can be unavailable during restart; durable queue remains.
        time.sleep(5)


def stop_group(gmp, group: dict) -> dict:
    if group.get("plan", {}).get("native_backend"):
        check_response(gmp.stop_task(require_uuid(group["native_task_id"])))
        return {"stopped": [child["task_id"] for child in group["children"]],
                "failed": []}
    run = group.get("run_state")
    active_ids = set(run["inflight"]) if run and "pending" in run else None
    if run and "pending" in run:
        run = copy.deepcopy(run)
        run["pending"] = []
        run["state"] = "stopping" if run["inflight"] else "stopped"
        save_run_state(group["id"], run)
    summary = group_summary(gmp, group)
    stopped, failed = [], []
    for child in summary["children"]:
        if active_ids is not None and child["task_id"] not in active_ids:
            continue
        if child["status"] not in ("Running", "Requested", "Queued"):
            continue
        try:
            check_response(gmp.stop_task(child["task_id"]))
            stopped.append(child["task_id"])
        except Exception as exc:
            failed.append({"task_id": child["task_id"], "error": str(exc)})
    return {"stopped": stopped, "failed": failed}


def delete_native_resource(gmp, method: str, resource_id: str) -> None:
    """Treat an already removed generated resource as successful cleanup."""
    resource_id = require_uuid(resource_id)
    if method == "delete_report":
        response = ET.fromstring(gmp.delete_report(resource_id))
    else:
        response = ET.fromstring(getattr(gmp, method)(resource_id, ultimate=True))
    if response.get("status") != "404":
        check_response(ET.tostring(response, encoding="unicode"))


def delete_group(gmp, group: dict) -> dict:
    """Remove generated resources only after every native task is inactive."""
    if group.get("plan", {}).get("native_backend"):
        raise GroupConflictError(
            "Native task deletion needs manager-owned cleanup; it is disabled in this prototype")
    run = group.get("run_state") or {}
    if run.get("pending") or run.get("inflight") or run.get("launching"):
        raise GroupConflictError("Stop the group and resolve active or uncertain child scans before deletion")
    with database() as db:
        if db.execute("SELECT 1 FROM groups WHERE id=? AND report_state='processing'",
                      (group["id"],)).fetchone():
            raise GroupConflictError("Report publication is in progress; retry deletion later")
        if db.execute("SELECT 1 FROM native_imports WHERE group_id=? "
                      "AND state IN ('creating', 'pending') LIMIT 1",
                      (group["id"],)).fetchone():
            raise GroupConflictError(
                "Native report import is active or uncertain; resolve it before deleting the group")
    task_ids = [child["task_id"] for child in group["children"]]
    if group.get("native_task_id"):
        task_ids.append(group["native_task_id"])
    for task_id in task_ids:
        try:
            status, current_report = task_state(gmp, task_id)
        except MissingTaskError:
            if not confirmed_missing_task(gmp, task_id):
                raise GroupConflictError("Native task status is uncertain; retry deletion later")
            continue
        except (ReviewError, ValueError, ET.ParseError) as exc:
            raise GroupConflictError(f"Cannot verify native task status: {exc}") from exc
        if status in ACTIVE_TASK_STATUSES or status == "Unknown":
            raise GroupConflictError("Stop all native scans and report imports before deletion")
    with database() as db:
        report_ids = [row[0] for row in db.execute(
            "SELECT report_id FROM native_reports WHERE group_id=?", (group["id"],))]
        report_ids += [row[0] for row in db.execute(
            "SELECT report_id FROM native_imports WHERE group_id=? AND report_id IS NOT NULL",
            (group["id"],))]
    for report_id in report_ids:
        delete_native_resource(gmp, "delete_report", report_id)
    for task_id in task_ids:
        delete_native_resource(gmp, "delete_task", task_id)
    for child in group["children"]:
        delete_native_resource(gmp, "delete_target", child["target_id"])
    with database() as db:
        db.execute("DELETE FROM native_reports WHERE group_id=?", (group["id"],))
        db.execute("DELETE FROM native_imports WHERE group_id=?", (group["id"],))
        db.execute("DELETE FROM managed_tasks WHERE group_id=?", (group["id"],))
        if db.execute("DELETE FROM groups WHERE id=?", (group["id"],)).rowcount != 1:
            raise ReviewError("Unknown scan group")
    return {"deleted": True}


def recover_group(gmp, group: dict) -> dict:
    """Resolve a failed run without guessing whether GMP accepted a start."""
    if group.get("plan", {}).get("native_backend"):
        raise GroupConflictError(
            "Native run recovery needs manager-owned reconciliation; inspect gvmd state")
    with database() as db:
        imports = db.execute(
            "SELECT signature, report_id, previous_report_id, expected_results, "
            "state, failures, next_attempt, error FROM native_imports WHERE group_id=? "
            "AND state IN ('creating', 'pending')", (group["id"],)).fetchall()
    for row in imports:
        signature = row[0]
        attempt = dict(zip(("report_id", "previous_report_id", "expected_results",
                            "state", "failures", "next_attempt", "error"), row[1:]))
        try:
            status, current_report = task_state(gmp, group["native_task_id"])
        except MissingTaskError:
            if not confirmed_missing_task(gmp, group["native_task_id"]):
                raise GroupConflictError("Logical task status is uncertain; retry recovery later")
            mark_import_failure(group["id"], signature,
                                "Logical native task was removed; recreate the group",
                                permanent=True)
            raise GroupConflictError(
                "Logical native task is gone; import capacity is released. Delete and recreate this group")
        if status in ACTIVE_TASK_STATUSES:
            raise GroupConflictError(
                "Native report import may still be active; stop it before recovery")
        if (attempt["state"] == "creating"
                and current_report == attempt["previous_report_id"]):
            raise GroupConflictError(
                "Report import acceptance is uncertain. Stop and delete the logical native task, "
                "then retry Recover before deleting the group")
        outcome = reconcile_import(gmp, group, signature, attempt)
        if outcome["state"] == "pending":
            raise GroupConflictError("Native report import is still pending; retry recovery later")
    run = group.get("run_state")
    if not run or run.get("state") in ("done", "stopped"):
        return {"recovered": True, "state": "stopped"}
    if run.get("state") not in ("failed", "starting"):
        raise GroupConflictError("Stop queued and running scans before recovery")
    run = copy.deepcopy(run)
    if run.get("pending"):
        run["pending"] = []
    missing = False
    task_ids = [child["task_id"] for child in group["children"]]
    for task_id in task_ids:
        try:
            status, current_report = task_state(gmp, task_id)
        except MissingTaskError:
            if not confirmed_missing_task(gmp, task_id):
                raise GroupConflictError("Native task status is uncertain; retry recovery later")
            missing = True
            if "inflight" in run and task_id in run["inflight"]:
                run["inflight"].remove(task_id)
            if (run.get("launching") or {}).get("task_id") == task_id:
                run["launching"] = None
            continue
        except (ReviewError, ValueError, ET.ParseError) as exc:
            raise GroupConflictError(f"Cannot verify native task status: {exc}") from exc
        launch = run.get("launching") or {}
        uncertain = (task_id in run.get("inflight", [])
                     or launch.get("task_id") == task_id)
        known_report = run.get("reports", {}).get(task_id)
        accepted_terminal = (
            (known_report and current_report == known_report)
            or (launch.get("task_id") == task_id and current_report
                and current_report != launch.get("previous_report")))
        if (status in ACTIVE_TASK_STATUSES or status == "Unknown"
                or (uncertain and (status not in ("Done", "Stopped", "Interrupted")
                                   or not accepted_terminal))):
            raise GroupConflictError(
                "Native scan start remains active or uncertain; inspect and stop or delete the child task before retrying recovery")
    if missing:
        run["state"] = "failed"
        run["pending"] = []
        run["inflight"] = []
        run["launching"] = None
        save_run_state(group["id"], run)
        raise GroupConflictError("A child task was deleted; its capacity is released. Delete this group and recreate it")
    run.update({"state": "stopped", "pending": [], "inflight": [],
                "launching": None, "failed": [], "legacy_settled": True})
    save_run_state(group["id"], run)
    with database() as db:
        db.execute("UPDATE groups SET native_error=NULL WHERE id=?", (group["id"],))
    return {"recovered": True, "state": "stopped"}


def publish_group_request(group_id: str) -> dict | None:
    """Reserve publication briefly, then keep long GMP I/O off MUTATION_LOCK."""
    with REPORT_LOCK:
        with MUTATION_LOCK:
            group = group_by_id(group_id)
            with database() as db:
                state = db.execute("SELECT report_state FROM groups WHERE id=?",
                                   (group_id,)).fetchone()
                if not state or state[0] == "processing":
                    raise GroupConflictError("Report publication is already in progress")
                db.execute("UPDATE groups SET report_state='processing' WHERE id=?",
                           (group_id,))
        try:
            with manager() as gmp:
                return publish_native_report(gmp, group, manual=True)
        finally:
            with database() as db:
                db.execute("UPDATE groups SET report_state='ready', report_due=? "
                           "WHERE id=? AND report_state='processing'",
                           (int(time.time()) + 30, group_id))


class Handler(BaseHTTPRequestHandler):
    def address_string(self):
        if isinstance(self.client_address, str):
            return "local-socket"
        return super().address_string()

    def _authorized(self):
        # Only nginx can reach the private Unix socket in proxy mode. It sets
        # this header after GSAD confirms the session belongs to the GMP user.
        if TRUST_GSA_PROXY:
            if self.headers.get("X-Review-Authenticated") == "1":
                return True
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False
        if not USERNAME or not PASSWORD:
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False
        auth = self.headers.get("Authorization", "")
        expected = "Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
        if hmac.compare_digest(auth, expected):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Scan group operator"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def _send(self, status, data, content_type="application/json"):
        content = data.encode() if isinstance(data, str) else json.dumps(data).encode()
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except (BrokenPipeError, ConnectionResetError):
            pass  # The client disconnected after the request was handled.

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
            elif path == "/api/groups/managed-task-ids":
                self._send(200, managed_task_ids())
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
            elif path == "/api/asset-overrides":
                self._send(200, get_saved_overrides(include_disabled=True))
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
            if not isinstance(body, dict):
                raise ReviewError("Request body must be a JSON object")
            if self.path == "/api/preview":
                require_enhanced_mode(body)
                with manager() as gmp:
                    result = build_plan(gmp, body, require_scan_setup=False,
                                        saved_overrides=get_saved_overrides())
            elif self.path == "/api/groups/summary":
                with manager() as gmp:
                    result = [group_summary(gmp, group) for group in
                              get_groups_for_task_ids(body.get("task_ids"))]
            elif self.path == "/api/groups/task-membership":
                result = task_membership(body.get("task_ids"))
            elif self.path == "/api/groups":
                require_enhanced_mode(body)
                with MUTATION_LOCK, manager() as gmp:
                    plan = build_plan(gmp, body,
                                      saved_overrides=get_saved_overrides())
                    require_expected_scan_count(body, plan)
                    result = create_group(gmp, plan)
            elif self.path == "/api/asset-overrides":
                with MUTATION_LOCK, manager() as gmp:
                    asset_id = require_uuid(body.get("asset_id"))
                    credential_id = require_uuid(body.get("credential_id"))
                    inv = inventory(gmp)
                    if asset_id not in {item["id"] for item in inv["assets"]}:
                        raise ReviewError("Asset is unavailable")
                    if credential_id not in {item["id"] for item in inv["credentials"]}:
                        raise ReviewError("Credential is unavailable")
                    service = body.get("service")
                    if service not in CREDENTIAL_TYPES:
                        raise ReviewError("Unsupported credential service")
                    credential_type = next(item["type"] for item in inv["credentials"]
                                           if item["id"] == credential_id)
                    if credential_type not in CREDENTIAL_TYPES[service]:
                        raise ReviewError(f"Credential type {credential_type} cannot be used for {service}")
                    save_asset_override(asset_id, service, credential_id)
                    result = {"saved": True}
            elif self.path == "/api/asset-overrides/toggle":
                with MUTATION_LOCK:
                    set_asset_override_enabled(body.get("asset_id"), body.get("service"),
                                               body.get("enabled"))
                    result = {"enabled": body["enabled"]}
            elif self.path == "/api/asset-overrides/delete":
                with MUTATION_LOCK:
                    delete_asset_override(body.get("asset_id"), body.get("service"))
                    result = {"deleted": True}
            elif re.fullmatch(r"/api/groups/[0-9a-fA-F-]{36}/publish", self.path):
                result = publish_group_request(self.path.split("/")[3])
            elif re.fullmatch(r"/api/groups/[0-9a-fA-F-]{36}/(?:start|stop|recover|delete)", self.path):
                with MUTATION_LOCK, manager() as gmp:
                    group = group_by_id(self.path.split("/")[3])
                    if self.path.endswith("/start"):
                        result = start_group(gmp, group)
                    elif self.path.endswith("/stop"):
                        result = stop_group(gmp, group)
                    elif self.path.endswith("/recover"):
                        result = recover_group(gmp, group)
                    elif self.path.endswith("/delete"):
                        result = delete_group(gmp, group)
            else:
                self._send(404, {"error": "Not found"})
                return
            self._send(200, result)
        except (PlanChangedError, GroupConflictError) as exc:
            self._send(409, {"error": str(exc)})
        except (ReviewError, ValueError, KeyError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:
            self._send(503, {"error": str(exc)})


if __name__ == "__main__":
    if TRUST_GSA_PROXY and not HTTP_SOCKET:
        raise SystemExit("REVIEW_HTTP_SOCKET is required in proxy mode")
    controller_lock = claim_single_controller()
    init_db()
    threading.Thread(target=dispatch_scan_queue, daemon=True,
                     name="scan-group-dispatch").start()
    threading.Thread(target=synchronize_native_reports, daemon=True,
                     name="native-report-reconciliation").start()
    if TRUST_GSA_PROXY:
        socket_path = Path(HTTP_SOCKET)
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        socket_path.unlink(missing_ok=True)
        with socketserver.ThreadingUnixStreamServer(str(socket_path), Handler) as server:
            os.chmod(socket_path, 0o666)
            server.serve_forever()
    else:
        ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
