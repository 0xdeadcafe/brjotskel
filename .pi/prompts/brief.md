---
description: Tactical intel brief — current state, active leads, next move
---
Give a tactical brief on the current investigation. Pull live data from the intel store and build a tight situational picture.

Steps:
1. Run intel_summary() to get counts and status breakdown
2. Run intel_timeline(action="view", count=30) to see recent activity
3. Run intel_query(query_type="all_credentials") to see credential state
4. Run remote_sessions() to see what's currently connected

Then produce a brief in this format:

**HOSTS** — list by status: dirty (compromised), suspected, clean (cleared), unknown
**CREDENTIALS** — active/unvalidated/terminal; note which haven't been validated yet
**SESSIONS** — what's currently open and what platform
**PIVOTS** — active pivot paths and what they reach
**OPEN LEADS** — what's unvalidated, what hosts haven't been triaged, what credentials haven't been tested
**NEXT MOVE** — one clear recommendation: highest-priority action and why

Keep it operator-tight. This is a situational picture, not a report.
