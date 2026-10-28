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

# TCC 서비스 이름 → 사람이 읽는 이름.
TCC_SERVICES = {
    "kTCCServiceScreenCapture": "화면 기록",
    "kTCCServiceAccessibility": "손쉬운 사용",
}

# 시스템처럼 보이는 상태 아이템 이름. 서드파티 앱이 이걸 쓰면 위장 신호.
SYSTEM_STATUS_WORDS = (
    "wi-fi", "wifi", "battery", "bluetooth", "airdrop", "airpods", "volume",
    "sound", "focus", "moon", "screen mirroring", "vpn", "time machine",
    "display", "now playing", "siri", "control center", "input source",
    "keyboard brightness", "clock", "weather",
)

MEMORY_CHUNK = 8 * 1024 * 1024
MEMORY_OVERLAP = 64


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


# --- v0.2: TCC ------------------------------------------------------------

def read_tcc(conn) -> list[dict]:
    """TCC 데이터베이스에서 관심 서비스의 허용 항목을 읽는다. 실패는 빈 목록."""
    import sqlite3
    try:
        cur = conn.execute(
            "SELECT service, client, client_type, auth_value FROM access "
            "WHERE service IN ({})".format(",".join("?" * len(TCC_SERVICES))),
            tuple(TCC_SERVICES),
        )
    except sqlite3.Error:
        return []
    return [
        {"service": s, "client": c, "client_type": t, "auth_value": a}
        for s, c, t, a in cur.fetchall()
    ]


def check_tcc(rows: list[dict]) -> list[Finding]:
    """화면 기록 + 손쉬운 사용을 같은 앱이 둘 다 받았으면 캡처+전역단축키 조합이다."""
    granted: dict[str, set[str]] = {}
    for r in rows:
        if r.get("auth_value") != 2:  # 2 = allowed
            continue
        service = r.get("service")
        if service not in TCC_SERVICES:
            continue
        granted.setdefault(r.get("client") or "?", set()).add(service)

    out: list[Finding] = []
    for client, services in sorted(granted.items()):
        names = sorted(TCC_SERVICES[s] for s in services)
        both = len(services) == 2
        out.append(Finding(
            check="tcc-grant",
            severity=HIGH if both else INFO,
            subject=client,
            detail=("화면 기록 + 손쉬운 사용 동시 허용 (캡처 + 전역 단축키 조합)"
                    if both else "허용된 권한: " + ", ".join(names)),
            evidence={"client": client, "services": sorted(services)},
        ))
    return out


# --- v0.2: 메뉴바 상태 아이템 ---------------------------------------------

def _looks_like_system(label: str) -> bool:
    low = label.lower()
    return any(w in low for w in SYSTEM_STATUS_WORDS)


def check_menu_bar(before: list[dict], after: list[dict]) -> list[Finding]:
    """서드파티 앱 상태 아이템 중 시스템 어휘를 쓰거나 값이 바뀌는 것을 찾는다.

    각 항목: {pid, app, path, index, title, desc}
    """
    prev = {(i.get("pid"), i.get("index")): i.get("title", "") for i in before}
    out: list[Finding] = []
    for item in after:
        path = item.get("path", "")
        if not path or is_system_path(path):
            continue
        key = (item.get("pid"), item.get("index"))
        title, desc = item.get("title", ""), item.get("desc", "")
        label = f"{title} {desc}".strip()
        app = item.get("app") or os.path.basename(path)
        changed = key in prev and prev[key] != title

        if _looks_like_system(label):
            out.append(Finding(
                check="menu-bar-impostor",
                severity=HIGH,
                subject=f"{app}: {label or '(무제)'}",
                detail="서드파티 앱의 메뉴바 항목이 시스템 아이콘처럼 보이는 이름을 사용",
                evidence={"pid": item.get("pid"), "title": title,
                          "desc": desc, "executable": path},
            ))
        elif changed:
            out.append(Finding(
                check="menu-bar-dynamic",
                severity=INFO,
                subject=f"{app}: {prev[key]!r} → {title!r}",
                detail="메뉴바 항목 값이 샘플 사이에 변경됨 (정보 표시 채널일 수 있음)",
                evidence={"pid": item.get("pid"), "before": prev[key],
                          "after": title, "executable": path},
            ))
    return out


# --- v0.2: 메모리 덤프 -----------------------------------------------------

def scan_memory_file(path: str) -> list[str]:
    """코어/덤프 파일을 청크로 훑어 사설 API 심볼을 찾는다 (전체 로드 없음)."""
    found: set[str] = set()
    tail = b""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(MEMORY_CHUNK)
            if not chunk:
                break
            found.update(scan_symbols(tail + chunk))
            tail = (tail + chunk)[-MEMORY_OVERLAP:]
    return sorted(found)

