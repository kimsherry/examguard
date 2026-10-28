from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import __version__
from .checks import check_processes, run_all
from .model import Finding, Report


def _watch_processes(report: Report, seconds: float) -> None:
    """screencapture 는 금방 끝나므로 짧은 구간을 샘플링한다."""
    from .providers import MacProvider
    prov = MacProvider()
    seen: set[int] = set()
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        for f in check_processes(prov.processes()):
            pid = f.evidence.get("pid")
            if pid not in seen:
                seen.add(pid)
                report.add(f)
        time.sleep(0.5)


def _print_text(report: Report) -> None:
    for f in report.findings:
        mark = "!" if f.severity == "high" else "i"
        print(f"[{mark}] {f.check}  {f.subject}")
        print(f"    {f.detail}")
    for s in report.skipped:
        print(f"[skip] {s}")
    print(f"\n요약: high {report.high_count} / total {len(report.findings)}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="examguard",
        description="macOS 시험 무결성 신호 스캐너 (은닉 채널 탐지)",
    )
    p.add_argument("--json", action="store_true", help="JSON 출력")
    p.add_argument("--watch", type=float, default=0.0, metavar="SEC",
                   help="N초 동안 캡처 헬퍼 프로세스를 샘플링")
    args = p.parse_args(argv)

    from .providers import MacProvider, require_macos
    require_macos()

    prov = MacProvider()
    report = run_all(prov.windows(), prov.processes(), prov.apps(), os.getpid())
    if args.watch > 0:
        _watch_processes(report, args.watch)

    if args.json:
        print(json.dumps({**report.as_dict(), "version": __version__}, ensure_ascii=False, indent=1))
    else:
        _print_text(report)
    return 2 if report.high_count else 0


if __name__ == "__main__":
    sys.exit(main())
