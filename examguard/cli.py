from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import __version__
from .checks import (
    check_menu_bar, check_processes, check_tcc, run_all, scan_memory_file,
)
from .model import Finding, Report, HIGH


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


def _menu_bar(report: Report, prov) -> None:
    """상태 아이템을 2초 간격으로 두 번 읽어 값 변화까지 본다."""
    if not prov.ax_trusted():
        report.skip("메뉴바 열거: 손쉬운 사용(Accessibility) 권한 필요")
        return
    before = prov.status_items()
    time.sleep(2)
    report.add(*check_menu_bar(before, prov.status_items()))


def _memory_dump(report: Report, path: str) -> None:
    if not os.path.isfile(path):
        report.skip(f"메모리 덤프 없음: {path}")
        return
    tokens = scan_memory_file(path)
    if not tokens:
        return
    report.add(Finding(
        check="memory-private-api",
        severity=HIGH,
        subject=os.path.basename(path),
        detail="메모리 덤프에서 사설 하드웨어 API 심볼 발견: " + ", ".join(tokens),
        evidence={"path": path, "symbols": tokens},
    ))


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
    p.add_argument("--memory-dump", metavar="PATH",
                   help="코어/메모리 덤프에서 사설 API 심볼 스캔 (root로 획득 필요)")
    p.add_argument("--block", action="store_true",
                   help="차단 계획 출력 (실행은 하지 않음)")
    p.add_argument("--yes", action="store_true",
                   help="--block 과 함께 쓰면 실제로 SIGTERM/SIGKILL 실행")
    args = p.parse_args(argv)

    from .providers import MacProvider, require_macos
    require_macos()

    prov = MacProvider()
    report = run_all(prov.windows(), prov.processes(), prov.apps(), os.getpid())

    rows, why = prov.tcc_rows()
    if why:
        report.skip(why)
    report.add(*check_tcc(rows))
    _menu_bar(report, prov)

    if args.watch > 0:
        _watch_processes(report, args.watch)
    if args.memory_dump:
        _memory_dump(report, args.memory_dump)

    if args.block:
        from .actions import apply_blocks, block_candidates
        cands = block_candidates(report.findings, prov.processes())
        targets = [c for c in cands if c["allowed"]]
        blocked = [c for c in cands if not c["allowed"]]
        if not args.json:
            print("\n차단 계획:")
            for c in targets:
                print(f"  - pid {c['pid']} {c['name']} ({c['path']}) ← {c['reason']}")
            for c in blocked:
                print(f"  x pid {c['pid']} {c['name']} — 건너뜀: {c['blocked_by']}")
            if not targets:
                print("  (대상 없음)")
        if args.yes and targets:
            report.add(*apply_blocks(targets))
        elif targets and not args.json:
            print("  실제 종료는 --yes 를 추가하세요.")

    if args.json:
        payload = {**report.as_dict(), "version": __version__}
        if args.block:
            payload["block_plan"] = cands
        print(json.dumps(payload, ensure_ascii=False, indent=1))
    else:
        _print_text(report)
    return 2 if report.high_count else 0


if __name__ == "__main__":
    sys.exit(main())
