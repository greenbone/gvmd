# Experimental multi-target scan groups with credential overrides

This companion controller drives one logical GSA task across selected source
targets. It resolves saved per-asset credentials, groups concrete hosts by
**source target and full effective credential set**, and creates one scanner
target and child task per group. Six hosts across two targets therefore make
two scans without overrides, or three when one host differs. The logical task
appears as a normal gvmd task record; a completed run publishes a combined
report while retaining source reports.

The service uses python-gvm and a Unix gvmd socket. In the integrated
review stack, set `TRUST_GSA_PROXY=1` and
`REVIEW_HTTP_SOCKET=/run/credential-review/controller.sock`. The controller
then listens only on that private Unix socket, shared with the matching
experimental GSAD nginx proxy. GSAD validates the GSA session and permits
only the account named by `SCAN_GROUP_GMP_USERNAME`, which must equal this
controller's `GMP_USERNAME` because the shared GMP account can access every
review group. Nginx forwards an authorization header only after that check.
Do not publish a controller TCP port in this mode. Standalone mode still
supports HTTP Basic credentials for local development.

Source targets must contain explicit IP addresses. DNS names are rejected
before a scan plan is created because native reports identify hosts by IP.
Persistent group and override state lives in `REVIEW_DB` (SQLite).

`test_controller.py` covers partitioning, child creation, override routing,
and combined report publication. The 9443 review stack runs this exact source.

This is a separate experimental controller. Native gvmd multi-target storage,
launch, resume, and report aggregation are not implemented by this directory.
