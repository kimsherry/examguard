"""플랫폼 독립 판정 로직. 입력은 macOS 프로바이더가 만든 dict/list."""
from __future__ import annotations

import os
from .model import Finding, Report, HIGH, INFO

# 정상적으로 화면 캡처에서 제외되는 시스템 창들.
SYSTEM_WINDOW_OWNERS = {
    "Window Server", "Dock", "SystemUIServer", "Control Center",
    "Notification Center", "Spotlight", "loginwindow", "WallpaperAgent",
    "TextInputMenuAgent", "universalAccessAuthWarn",
}

# 사설/저수준 API: 화면에 흔적 없이 답을 전달하는 데 쓰이는 심볼.
PRIVATE_TOKENS = (b"CoreBrightness", b"KeyboardBrightnessClient", b"IOHIDSystem")

CAPTURE_HELPERS = {"screencapture"}


def scan_symbols(blob: bytes) -> list[str]:
    """바이너리에서 사설 API 심볼 참조를 찾는다 (import 문자열 기준)."""
    return [t.decode() for t in PRIVATE_TOKENS if t in blob]


def is_system_path(path: str) -> bool:
    return path.startswith(("/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/"))


def check_windows(windows: list[dict], self_pid: int) -> list[Finding]:
    """sharingState == 0 인 가시 창 = 물리 화면엔 보이지만 화면 공유/녹화엔 안 잡히는 창."""
    out: list[Finding] = []
    for w in windows:
        if w.get("sharing") != 0:
            continue
        if not w.get("onscreen") or w.get("alpha", 1) <= 0.01:
            continue
        if w.get("layer", 0) < 0:
            continue
        if w.get("pid") == self_pid:
            continue
        owner = w.get("owner", "")
        if owner in SYSTEM_WINDOW_OWNERS:
            continue
        title = w.get("name") or "(제목 없음)"
        out.append(Finding(
            check="capture-excluded-window",
            severity=HIGH,
            subject=title,
            detail=f"'{owner}' 창이 화면 공유에서 제외된 상태(sharingType=none)로 표시 중",
            evidence={"pid": w.get("pid"), "layer": w.get("layer"),
                      "bounds": w.get("bounds"), "owner": owner},
        ))
    return out


def check_processes(procs: list[dict]) -> list[Finding]:
    """캡처 헬퍼(/usr/sbin/screencapture)가 떠 있으면 화면을 읽는 중일 수 있다."""
    out: list[Finding] = []
    for p in procs:
        base = os.path.basename(p.get("comm", ""))
        if base in CAPTURE_HELPERS:
            out.append(Finding(
                check="capture-helper-process",
                severity=HIGH,
                subject=base,
                detail="화면 캡처 헬퍼가 실행 중",
                evidence={"pid": p.get("pid"), "comm": p.get("comm")},
            ))
    return out


def check_private_api(apps: list[dict]) -> list[Finding]:
    """번들 바이너리가 사설 밝기/HID 심볼을 참조하면 은닉 신호 전달 가능성이 높다."""
    out: list[Finding] = []
    for a in apps:
        path = a.get("executable", "")
        if not path or is_system_path(path):
            continue
        hits = a.get("symbols") or []
        if not hits:
            continue
        out.append(Finding(
            check="private-hardware-api",
            severity=HIGH,
            subject=a.get("name") or os.path.basename(path),
            detail="사설/저수준 하드웨어 API 참조: " + ", ".join(hits),
            evidence={"executable": path, "symbols": hits,
                      "policy": a.get("policy")},
        ))
    return out


def check_dockless(apps: list[dict]) -> list[Finding]:
    """Dock/⌘Tab 에 안 뜨는 상주 앱은 그 자체로는 정상(메뉴바 앱). 참고용."""
    out: list[Finding] = []
    for a in apps:
        path = a.get("executable", "")
        if not path or is_system_path(path):
            continue
        if a.get("policy") not in ("accessory", "prohibited"):
            continue
        out.append(Finding(
            check="dockless-app",
            severity=INFO,
            subject=a.get("name") or os.path.basename(path),
            detail=f"활성화 정책={a.get('policy')} (Dock 에 표시되지 않음)",
            evidence={"executable": path},
        ))
    return out


def run_all(windows, procs, apps, self_pid: int) -> Report:
    r = Report()
    r.add(*check_windows(windows, self_pid))
    r.add(*check_processes(procs))
    r.add(*check_private_api(apps))
    r.add(*check_dockless(apps))
    return r
