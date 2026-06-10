import json
from pathlib import Path

import pytest

from spoor_sift.audit import AuditLog
from spoor_sift.runner import ToolResult
from spoor_sift.server import build_server, build_server_from_env

PSLIST_JSON = json.dumps(
    [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 372, "PPID": 4, "ImageFileName": "smss.exe"},
        {"PID": 666, "PPID": 372, "ImageFileName": "svch0st.exe"},
    ]
)


class FakeRunner:
    def __init__(self, result: ToolResult):
        self.result = result
        self.calls: list[tuple[str, list[str]]] = []

    def run(self, binary: str, args: list[str]) -> ToolResult:
        self.calls.append((binary, list(args)))
        return self.result


@pytest.fixture
def server(tmp_path: Path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "mem.raw").write_bytes(b"fake memory image")
    runner = FakeRunner(ToolResult(0, PSLIST_JSON, ""))
    audit = AuditLog(tmp_path / "audit.jsonl", clock=lambda: "2026-06-09T12:00:00+00:00")
    return build_server(runner=runner, audit=audit, evidence_root=root)


async def test_server_registers_vol_pslist(server):
    tools = await server.list_tools()
    by_name = {t.name: t for t in tools}
    assert "vol_pslist" in by_name
    assert by_name["vol_pslist"].description  # docstring surfaced to MCP clients


async def test_server_tool_delegates_to_core(server):
    result = await server.call_tool("vol_pslist", {"memory_image": "mem.raw"})
    payload = result if isinstance(result, dict) else json.loads(result[0].text)
    assert payload["process_count"] == 3
    assert len(payload["tool_call_id"]) == 64


def test_build_server_from_env_requires_evidence_root(monkeypatch):
    monkeypatch.delenv("EVIDENCE_ROOT", raising=False)
    with pytest.raises(RuntimeError):
        build_server_from_env()


async def test_server_registers_all_memory_tools(server):
    names = {t.name for t in await server.list_tools()}
    assert {"vol_pslist", "vol_pstree", "vol_netscan", "vol_malfind", "vol_cmdline"} <= names
