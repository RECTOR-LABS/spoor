# Spoor

> An autonomous DFIR agent that drives SANS SIFT forensic tools via an MCP server + LangGraph orchestration, with architectural guardrails and a hash-chained audit trail.

**Status:** 📐 Pre-build spec — see [`SPEC.md`](./SPEC.md) and [`PLAN.md`](./PLAN.md).

| | |
|---|---|
| **Hackathon** | "FIND EVIL!" (SANS Institute, Devpost) |
| **Submit by** | Jun 15, 2026 · $22K+ (1st $10K) |
| **Build** | Make "Protocol SIFT" a fully autonomous incident-response agent via MCP |
| **Stack** | Python · MCP · LangGraph · SANS SIFT Workstation |

*Spoor*: the track/trail an animal leaves — you follow the spoor to hunt the quarry. Here: follow forensic artifacts to the threat.

## Notes
- **Public repo.** No secrets in source — env-var only (`.env.example` documents names).
- Standalone (no blockchain; cybersecurity/forensics stack).
- Honest risk: the DFIR domain is the headline ramp — see [`SPEC.md`](./SPEC.md) §Risks.

## License
MIT — see [`LICENSE`](./LICENSE).
