# Experimental multi-target scan groups

This companion controller drives one logical GSA task across selected source
targets. It expands explicit hosts for validation, then creates **one scanner
target and child task per selected source target**, preserving the target's
ports and credentials. The logical task appears as a normal gvmd task record;
a completed run publishes a combined report while retaining source reports.

The service uses python-gvm and a Unix gvmd socket. Run it only behind the
GSAD-authenticated reverse proxy in the matching experimental GSAD branch.
The `TRUST_GSA_PROXY=1` mode assumes the proxy alone can reach port 8080.
Persistent group state lives in `REVIEW_DB` (SQLite).

Credential overrides are rejected in this tier. `test_controller.py` checks
six hosts across two targets produce exactly two child tasks.

This is a separate experimental controller. Native gvmd multi-target storage,
launch, resume, and report aggregation are not implemented by this directory.
