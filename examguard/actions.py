"""차단 동작. 기본은 계획만 세우고, apply 는 --yes 를 받은 경우에만 호출된다.

가드: 시스템 경로, 시스템 프로세스, PID<=1, 자기 자신은 절대 대상이 되지 않는다.
"""
from __future__ import annotations

import os
import signal
import time

from .checks import is_system_path
from .model import Finding, INFO

# 차단 대상이 될 수 있는 검사. 메모리 덤프/메뉴바는 프로세스를 특정하지 못한다.
BLOCKABLE = {"capture-excluded-window", "capture-helper-process", "private-hardware-api"}

# 종료시키면 시험이 아니라 OS 가 망가지는 프로세스들.
PROTECTED_NAMES = {
    "launchd", "WindowServer", "loginwindow", "Dock", "Finder", "SystemUIServer",
    "ControlCenter", "NotificationCenter", "sudo", "sshd", "examguard", "python3",
}


def block_candidates(findings: list[Finding], procs: list[dict]) -> list[dict]:
    """Findings → 차단 후보 목록. allowed=False 인 항목은 이유가 붙는다."""
    comm_by_pid = {p.get("pid"): p.get("comm", "") for p in procs}
    self_pid = os.getpid()
    out: list[dict] = []
    seen: set[int] = set()

    for f in findings:
        if f.check not in BLOCKABLE:
            continue
        pid = f.evidence.get("pid")
        path = f.evidence.get("executable") or comm_by_pid.get(pid, "")
        name = f.subject

        why = None
        if not isinstance(pid, int):
            why = "PID 없음"
        elif pid <= 1:
            why = "PID 1 이하"
        elif pid == self_pid:
            why = "자기 자신"
        elif not path:
            why = "실행 경로 미확인"
        elif is_system_path(path):
            why = "시스템 경로"
        elif os.path.basename(path) in PROTECTED_NAMES:
            why = "보호 대상 프로세스"

        if pid in seen:
            continue
        seen.add(pid if isinstance(pid, int) else -1)
        out.append({
            "pid": pid, "name": name, "path": path,
            "reason": f.detail, "check": f.check,
            "allowed": why is None, "blocked_by": why,
        })
    return out


def apply_blocks(candidates: list[dict], grace: float = 2.0) -> list[Finding]:
    """허용된 후보만 SIGTERM → (살아있으면) SIGKILL. 결과를 Finding 으로 반환."""
    results: list[Finding] = []
    for c in candidates:
        if not c["allowed"]:
            continue
        pid = c["pid"]
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as e:
            results.append(_result(c, f"종료 실패: {e}"))
            continue

        deadline = time.monotonic() + grace
        while time.monotonic() < deadline and _alive(pid):
            time.sleep(0.1)
        if _alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
                results.append(_result(c, "SIGTERM 무시 → SIGKILL"))
            except OSError as e:
                results.append(_result(c, f"SIGKILL 실패: {e}"))
        else:
            results.append(_result(c, "SIGTERM 으로 종료"))
    return results


def _alive(pid: int) -> bool:
    # Linux: 좀비는 kill(pid,0) 이 성공하지만 이미 죽은 것이다.
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            state = f.read().split(b")", 1)[1].split()[0]
        if state == b"Z":
            return False
    except (OSError, IndexError):
        pass
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _result(c: dict, detail: str) -> Finding:
    return Finding(
        check="block", severity=INFO, subject=c["name"],
        detail=f"pid {c['pid']} — {detail}",
        evidence={"pid": c["pid"], "path": c["path"], "check": c["check"]},
    )
