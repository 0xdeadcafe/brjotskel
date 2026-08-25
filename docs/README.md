# Documentation

Reference for brjotskel operators, contributors, and integrators.

---

## Where to start

| If you are… | Start here |
|-------------|-----------|
| Running an incident for the first time | [getting-started.md](getting-started.md) |
| Following a credential trail across a network | [scenario-walkthrough.md](scenario-walkthrough.md) |
| Looking for a specific command or playbook | [runbook.md](runbook.md) |
| Trying to reach a host you can't connect to directly | [relay-pivoting.md](relay-pivoting.md) |
| Recording findings in the intel store | [intel-import-workflow.md](intel-import-workflow.md) |
| Adding a playbook or extending the agent | [../CONTRIBUTING.md](../CONTRIBUTING.md) |

---

## Reference

| Document | What it covers |
|----------|---------------|
| [getting-started.md](getting-started.md) | First-incident walkthrough. Zero to triage in under five minutes. |
| [scenario-walkthrough.md](scenario-walkthrough.md) | Full realistic incident: Linux web server compromise → credential chain → AD pivot → containment. |
| [runbook.md](runbook.md) | Operational reference for the full LAND → VERIFY lifecycle. Commands, decision heuristics, AD attack workflows, containment and eradication patterns. |
| [playbooks.md](playbooks.md) | Complete script inventory — every gather, host-IR, containment, eradication, and privesc script with a description. |
| [intel-import-workflow.md](intel-import-workflow.md) | Intel store schema, lifecycle states, and `bin/intel-snippet` templates for normalizing gather output. |
| [relay-pivoting.md](relay-pivoting.md) | Decision tree for reaching hosts the harness can't access directly. SSH tunnels, SOCKS, native TCP relays, multi-hop chains. |
| [architecture.md](architecture.md) | How the container, agent extensions, and intel store fit together. Extension API and data layer design. |

---

## Safety model

See [../CONSTITUTION.md](../CONSTITUTION.md). Operate only within the authorized incident scope. Collect evidence before disruptive actions. Log everything.
