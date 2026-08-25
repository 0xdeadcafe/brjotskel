---
description: Start a new incident — scope it, record initial intel, get access
argument-hint: "[scope: IP ranges, hostnames, or description]"
---
New incident. Scope: ${@:-not specified yet — ask me for it before proceeding}.

Do this in order:

1. **Scope it** — if scope wasn't given above, ask me for: IP ranges or hostnames, any known compromised hosts, any credentials in hand, and the incident brief summary. Don't proceed without at least one target.

2. **Record initial intel** — for each known host, call intel_add with status "in-scope" or "suspected" as appropriate, platform "unknown" unless told otherwise, source.method "incident brief". Use concise IDs (web01, dc01, etc.) if hostnames are known; fall back to IP-based IDs if not.

3. **Check connectivity** — suggest the nmap command to run against the scope from the harness. Don't run it yet; show me the command first.

4. **Get access** — suggest the first remote_connect call. Prioritize: confirmed compromised host first, then suspected, then initial entry point.

5. **First look** — once connected, first action is always /assess on that session.

Stay tactical. The goal is eyes on a host in under two minutes.
