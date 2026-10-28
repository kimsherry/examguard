# examguard

**macOS 시험 무결성 스캐너** — 화면에 안 남는 방식으로 정보를 흘리는 앱을 찾아낸다.

![tests](https://img.shields.io/badge/tests-34%20passing-brightgreen)
![platform](https://img.shields.io/badge/platform-macOS%2013%2B-black)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

```
$ python -m examguard
[!] capture-excluded-window  Invisible Window
    'Suspect' 창이 화면 공유에서 제외된 상태(sharingType=none)로 표시 중
[!] private-hardware-api  Suspect
    사설/저수준 하드웨어 API 참조: CoreBrightness, IOHIDSystem
[!] tcc-grant  com.suspect.app
    화면 기록 + 손쉬운 사용 동시 허용 (캡처 + 전역 단축키 조합)
[i] menu-bar-dynamic  Suspect: '3' → '5'
    메뉴바 항목 값이 샘플 사이에 변경됨 (정보 표시 채널일 수 있음)

요약: high 3 / total 4
```

## 왜 필요한가

화면 공유·녹화는 **프레임버퍼만** 가져간다. 그래서 아래 신호는 화면에 아무것도
남기지 않는다.

- 화면에서 제외된 창 (`sharingType = none`) — 물리 화면엔 보이고 공유엔 안 잡힘
- 키보드 백라이트 / 캡스락 LED / 디스플레이 밝기 — 하드웨어 상태, 캡처 대상 아님
- 시스템처럼 위장한 메뉴바 아이콘 — Dock·⌘Tab 에도 안 뜸

examguard 는 이 **은닉 채널**을 정적·동적으로 훑는다. 아무것도 차단하지 않고,
차단은 명시적으로 켜야 동작한다.

## 검사 항목

| 검사 | 근거 | 심각도 |
|---|---|:---:|
| `capture-excluded-window` | `kCGWindowSharingState == 0` 인 가시 창 | high |
| `capture-helper-process` | `/usr/sbin/screencapture` 실행 | high |
| `private-hardware-api` | 바이너리가 `CoreBrightness` / `KeyboardBrightnessClient` / `IOHIDSystem` 참조 | high |
| `tcc-grant` | TCC `access` 테이블 — 화면 기록 **+** 손쉬운 사용 동시 허용 | high |
| `menu-bar-impostor` | 서드파티 상태 아이템이 `Wi-Fi`·`Battery` 같은 시스템 어휘 사용 | high |
| `menu-bar-dynamic` | 두 샘플 사이에 상태 아이템 값이 바뀜 | info |
| `memory-private-api` | `--memory-dump` 로 준 코어/덤프에 사설 API 심볼 로드됨 | info→high |
| `dockless-app` | 활성화 정책이 `accessory`/`prohibited` (Dock 에 안 뜸) | info |

## 설치

```bash
git clone https://github.com/kimsherry/examguard.git
cd examguard
pip install pyobjc-framework-Quartz pyobjc-framework-Cocoa pyobjc-framework-ApplicationServices
```

Python 3.9+ / macOS 13+. 판정 로직은 의존성 없는 표준 라이브러리만 쓴다.

## 사용

```bash
python -m examguard                      # 스캔
python -m examguard --json               # 기계용 (jq 파이프 가능)
python -m examguard --watch 30           # 30초간 캡처 헬퍼 샘플링 (짧은 프로세스 대응)
sudo python -m examguard --memory-dump /tmp/target.core   # 덤프까지 스캔
```

종료 코드 — `0` 깨끗함, `2` high 발견. CI/감독 스크립트에 바로 붙일 수 있다.

### 필요한 권한

| 기능 | 권한 | 없을 때 |
|---|---|---|
| 창 / 프로세스 / 앱 스캔 | 없음 | — |
| `tcc-grant` | Full Disk Access | `[skip]` 후 계속 |
| `menu-bar-*` | 손쉬운 사용 (Accessibility) | `[skip]` 후 계속 |
| `--memory-dump` | root 로 덤프 획득 | `[skip]` 후 계속 |

권한이 없어도 죽지 않는다. 무엇을 못 봤는지는 `skipped` 에 남는다.

## 차단 (opt-in)

```bash
python -m examguard --block              # 계획만 출력, 아무것도 안 죽임
sudo python -m examguard --block --yes   # 실제 SIGTERM → 2초 → SIGKILL
```

```
차단 계획:
  - pid 1234 Suspect (…/Suspect.app/Contents/MacOS/Suspect) ← 화면 공유에서 제외된 창
  x pid 42 Mail — 건너뜀: 시스템 경로
  실제 종료는 --yes 를 추가하세요.
```

**하드 가드** (우회 불가)

- 시스템 경로(`/System`, `/usr`, `/bin`, `/sbin`) → 거부
- `launchd`, `WindowServer`, `Dock`, `Finder`, `SystemUIServer`, `loginwindow`, `sudo`, `sshd` → 거부
- `PID <= 1`, 자기 자신, 실행 경로 미확인 → 거부
- 차단 대상은 `capture-excluded-window` / `capture-helper-process` / `private-hardware-api` 뿐
  (메뉴바·덤프 검사는 프로세스를 특정하지 못해 계획에 안 들어감)

> **경고** — 대상 앱이 저장 안 한 데이터를 들고 있으면 함께 사라진다. 시험 시작 전에만 쓰고,
> `--json` 의 `block_plan` / `block` 을 감독 기록으로 보관할 것.

## 한계

- **물리 카메라를 대체하지 않는다.** 화면 밖 하드웨어 신호는 카메라로만 확실히 잡힌다.
- `capture-excluded-window` 는 오탐이 있다. 일부 시스템 오버레이도 `sharingState=0` 이라
  소유자 allowlist 로 거르지만, 정당하게 쓰는 서드파티도 있다. **단독 처벌 근거가 아니다.**
- `private-hardware-api` 는 문자열 참조 기반이다. 난독화/동적 로딩으로 우회 가능하므로
  그때는 `--memory-dump` 를 함께 쓴다.
- macOS 는 사설 프레임워크를 dyld shared cache 에 올리고 `task_for_pid` 를 막는다.
  실행 중 프로세스 메모리를 직접 읽는 기능은 의도적으로 없다.

## 개발

```bash
python -m unittest discover -s tests -v   # 34 tests, Linux 에서도 통과
```

구조 — 판정은 `examguard/checks.py` 의 순수 함수, macOS 입력 수집만
`examguard/providers/macos.py` 에 격리, 차단 동작은 `examguard/actions.py`.

## 라이선스

MIT — [LICENSE](LICENSE)
