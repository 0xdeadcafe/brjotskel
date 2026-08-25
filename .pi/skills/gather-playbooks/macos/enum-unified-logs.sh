#!/bin/sh
set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
run(){ printf '$ %s\n' "$*"; sh -c "$*" 2>/dev/null || true; }

sec LOG_PREDICATES_HINTS
printf '%s\n' 'Review recent launchd, auth, exec, and network activity from unified logs.'

sec LAST_24H_LAUNCHD
run 'log show --last 24h --style compact --predicate "process == \"launchd\"" | tail -200'

sec LAST_24H_AUTH
run 'log show --last 24h --style compact --predicate "eventMessage CONTAINS[c] \"authentication\" OR eventMessage CONTAINS[c] \"login\"" | tail -200'

sec LAST_24H_EXEC
run 'log show --last 24h --style compact --predicate "eventMessage CONTAINS[c] \"exec\" OR eventMessage CONTAINS[c] \"spawn\"" | tail -200'

sec LAST_24H_NETWORK
run 'log show --last 24h --style compact --predicate "subsystem CONTAINS[c] \"network\" OR process == \"mDNSResponder\"" | tail -200'
