# Experimental native multi-target scan tasks

This branch combines multi-target tasks and asset credential overrides. The
controller groups explicit IP hosts by source target and full effective
credential set. Six hosts across two source targets make two child scans
without overrides, or three when one host has a different credential.

Set `GVMD_NATIVE_MULTI_TARGET=1` in gvmd and `NATIVE_BACKEND=1` in the
companion controller. In this mode, the controller creates one scanner target
per partition and calls `create_multi_target_task`. Gvmd creates and owns the
logical parent task, child tasks, host membership, durable run state, and scan
dispatch. Starting or stopping the parent uses the normal GMP task commands;
`get_multi_target_tasks` exposes the native group and child status. The
controller retains GUI metadata, saved asset overrides, and the bounded
combined-report import bridge in SQLite. Source reports remain available.

The controller uses python-gvm and the gvmd Unix socket. For the integrated
GSA/GSAD path, set `TRUST_GSA_PROXY=1` and
`REVIEW_HTTP_SOCKET=/run/credential-review/controller.sock`, and publish no
controller TCP port. GSAD validates the existing GSA session; its
`SCAN_GROUP_GMP_USERNAME` must equal the controller's `GMP_USERNAME`. Only that
administrator-equivalent account may use the API because the controller's
shared GMP account can read every group. The matching nginx configuration
forwards requests only after the GSAD check.

The plan accepts at most 16 source targets and 128 explicit IP hosts. A plan
with more than 16 credential partitions is rejected before creating scanner
resources. Gvmd validates child target membership, duplicate hosts, and the
same 16-partition and 128-host limits for direct GMP callers. The native queue
allows at most 64 outstanding children, one active child per group, and two
native children total. It keeps uncertain starts blocked instead of blindly
retrying. A partial or stopped parent can be started again with a new run.

These are review limits, not appliance capacity measurements. The native
dispatcher checks ordinary scans on the selected scanner, but cannot reserve
capacity atomically against ordinary task starts. Production admission needs
a shared gvmd start path or a dedicated scanner.

The combined report bridge reads child reports in pages of at most 250
results and refuses imports above 10,000 results or 25 MiB of XML. It tracks
ambiguous imports durably and publishes one combined report on the logical
parent. Native parent deletion and uncertain-run recovery remain disabled in
the controller until gvmd owns safe cleanup and reconciliation. Do not use
this branch as a production capacity guarantee.

The previous controller dispatch path remains available when `NATIVE_BACKEND`
is disabled. `test_controller.py` and the other tests in this directory cover
partitioning, authorization, queue behavior, report lifecycle, and the native
adapter. The isolated review stack also completed real two-child and
three-child scans, combined reports, and an ordinary scan.
