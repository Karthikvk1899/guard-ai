# Security and scope

Guard-AI is a heuristic review aid. It is not a malware detector, dependency vulnerability database, provenance verifier, or security certification. The current main branch is maintained without a response-time SLA.

Use GitHub private vulnerability reporting if available, or request a private contact channel without posting exploit details or secrets. Reports should use synthetic source and identify the affected commit.

## Boundaries

Source is untrusted and is never executed or rewritten. Matched source lines are redacted from reports. Reports still include file paths and package names; treat them as potentially sensitive. Console fields disable Rich markup interpretation. No symlink traversal is performed, but concurrent filesystem changes are not a hardened sandbox boundary. Run scans on an immutable checkout in a restricted environment when analyzing hostile repositories.

Public registry requests require `--check-registry` and use fixed HTTPS registry origins, URL-encoded names, a timeout, no proxy environment inheritance, and no redirects. Package names leave the machine when enabled. A 200 means only that a registry entry exists. A 404 may mean a private dependency, alias, or import/distribution mismatch. Unknown responses fail the default HIGH/MEDIUM gate rather than claiming a clean result.

The local cache under `~/.guard_ai/cache-v2.db` contains package names and availability for up to 24 hours. It is not a trusted security verdict. Default file exclusions, the 1 MiB per-file cap, syntax coverage, and incomplete import resolution limit coverage. There is no performance or false-positive-rate guarantee.
