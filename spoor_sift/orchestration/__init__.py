"""LangGraph orchestration: specialist agents over the audited SIFT tools.

A supervisor routes a case to specialists (triage, timeline, IOC, reporter); each
reasons over the structured tool output, and the supervisor handles tool failures
by re-routing/retrying — emergent self-correction, not a fixed pipeline.
"""
