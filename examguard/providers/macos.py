"""macOS 입력 수집. 판정은 하지 않는다 — checks.py 로 넘길 형태만 만든다.

필요: macOS 13+, pyobjc-framework-Quartz / pyobjc-framework-Cocoa
     (pip install pyobjc-framework-Quartz pyobjc-framework-Cocoa)
"""
from __future__ import annotations

import os
import subprocess

from .checks import scan_symbols

MAX_BINARY_SCAN = 64 * 1024 * 1024
_POLICY = {0: "regular", 1: "accessory", 2: "prohibited"}


def require_macos() -> None:
    if os.uname().sysname != "Darwin":
        raise SystemExit(
            "examguard 는 macOS 전용입니다. 이 호스트에서는 판정 로직 테스트만 가능합니다."
        )


class MacProvider:
    def __init__(self) -> None:
        try:
            import Quartz  # noqa: F401
            from AppKit import NSWorkspace  # noqa: F401
        except ImportError as e:  # pragma: no cover - macOS only
            raise SystemExit(
                "pyobjc 가 필요합니다: pip install pyobjc-framework-Quartz pyobjc-framework-Cocoa"
            ) from e

    # -- 창 ---------------------------------------------------------------
    def windows(self) -> list[dict]:
        import Quartz
        raw = Quartz.CGWindowListCopyWindowInfo(
            Quartz.kCGWindowListOptionAll, Quartz.kCGNullWindowID
        ) or []
        out = []
        for w in raw:
            b = w.get("kCGWindowBounds") or {}
            out.append({
                "pid": w.get("kCGWindowOwnerPID"),
                "owner": w.get("kCGWindowOwnerName") or "",
                "name": w.get("kCGWindowName") or "",
                "layer": int(w.get("kCGWindowLayer") or 0),
                "onscreen": bool(w.get("kCGWindowIsOnscreen")),
                "sharing": int(w.get("kCGWindowSharingState") or 0),
                "alpha": float(w.get("kCGWindowAlpha") or 1.0),
                "bounds": [b.get("X"), b.get("Y"), b.get("Width"), b.get("Height")],
            })
        return out

    # -- 프로세스 ---------------------------------------------------------
    def processes(self) -> list[dict]:
        r = subprocess.run(
            ["ps", "-axo", "pid=,comm="], capture_output=True, text=True, check=False
        )
        out = []
        for line in r.stdout.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                out.append({"pid": int(parts[0]), "comm": parts[1].strip()})
        return out

    # -- 실행 중 앱 -------------------------------------------------------
    def apps(self) -> list[dict]:
        from AppKit import NSWorkspace
        out = []
        for app in NSWorkspace.sharedWorkspace().runningApplications():
            url = app.executableURL()
            if url is None:
                continue
            path = url.path()
            out.append({
                "name": app.localizedName() or os.path.basename(path),
                "executable": path,
                "policy": _POLICY.get(int(app.activationPolicy()), "unknown"),
                "symbols": self._symbols(path),
            })
        return out

    def _symbols(self, path: str) -> list[str]:
        try:
            with open(path, "rb") as f:
                return scan_symbols(f.read(MAX_BINARY_SCAN))
        except OSError:
            return []
