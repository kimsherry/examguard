# examguard

macOS 시험 감독용 **은닉 채널 탐지기**. 화면 공유·녹화에 잡히지 않는 방식으로 정보를
전달하는 앱을 찾아낸다. 읽기 전용이며 아무것도 차단하거나 종료하지 않는다.

## 무엇을 보나

| 검사 | 신호 | 의미 |
|---|---|---|
| `capture-excluded-window` | `kCGWindowSharingState == 0` 인 가시 창 | 물리 화면엔 보이지만 화면 공유/녹화에는 안 잡히는 창 |
| `capture-helper-process` | `/usr/sbin/screencapture` 실행 | 화면을 읽는 중 (프로그램이 화면을 캡처) |
| `private-hardware-api` | 바이너리가 `CoreBrightness` / `KeyboardBrightnessClient` / `IOHIDSystem` 참조 | 화면 밖 하드웨어(백라이트·캡스락 LED)로 신호 전달 |
| `dockless-app` | 활성화 정책 `accessory`/`prohibited` | Dock·⌘Tab 에 안 뜨는 상주 앱 (참고용, 오탐 많음) |
| `tcc-grant` | TCC `access` 테이블의 허용 항목 | 화면 기록 + 손쉬운 사용을 **같은 앱**이 둘 다 받았으면 캡처+전역 단축키 조합(high) |
| `menu-bar-impostor` | AX 로 열거한 남의 상태 아이템 | 서드파티 앱이 `Wi-Fi`/`Battery` 같은 시스템 어휘로 위장 |
| `menu-bar-dynamic` | 2초 간격 두 샘플의 제목 비교 | 상태 아이템 값이 바뀜 = 정보 전달 채널일 수 있음 |
| `memory-private-api` | `--memory-dump` 로 준 코어/덤프 | 사설 API 심볼이 메모리에 로드됨 (문자열 난독화 우회) |

세 번째 검사가 핵심이다. 화면 캡처·화면 공유는 프레임버퍼만 가져가므로, 밝기나 LED
같은 하드웨어 상태 변화는 원리적으로 잡히지 않는다. 그래서 그런 API를 쓰는 앱을
정적으로 찾는다.

## 설치 / 실행

```bash
pip install pyobjc-framework-Quartz pyobjc-framework-Cocoa pyobjc-framework-ApplicationServices
python -m examguard            # 사람이 읽는 출력
python -m examguard --json     # 기계용
python -m examguard --watch 30 # 30초간 캡처 헬퍼 프로세스 샘플링
sudo python -m examguard --memory-dump /path/to/core   # 덤프까지 스캔
python -m examguard --block          # 차단 계획만 출력 (아무것도 안 죽임)
sudo python -m examguard --block --yes   # 실제 차단
```

종료 코드: `0` 깨끗함, `2` high 발견. CI/감독 스크립트에서 그대로 쓸 수 있다.

## 차단 (opt-in)

`--block` 만 주면 **계획만** 출력한다. `--yes` 를 함께 줘야 SIGTERM → (2초 내 안 죽으면) SIGKILL.

```
차단 계획:
  - pid 1234 Suspect (Applications/Suspect.app/Contents/MacOS/Suspect) ← 화면 공유에서 제외된 창
  x pid 42 Mail — 건너뜀: 시스템 경로
  실제 종료는 --yes 를 추가하세요.
```

하드 가드 (우회 불가):
- 시스템 경로(`/System`, `/usr`, `/bin`, `/sbin`) → 차단 안 함
- `launchd`, `WindowServer`, `Dock`, `Finder`, `SystemUIServer`, `loginwindow`, `sudo`, `sshd` 등 → 차단 안 함
- `PID <= 1`, 자기 자신, 실행 경로 미확인 → 차단 안 함
- 차단 가능한 검사는 `capture-excluded-window`, `capture-helper-process`, `private-hardware-api` 뿐
  (메뉴바/메모리 덤프는 프로세스를 특정하지 못하므로 계획에 안 들어감)

**경고**: 대상 앱이 저장 안 한 데이터를 들고 있으면 같이 날아간다. 시험 시작 전에만 쓰고,
차단 결과는 JSON(`block_plan`, `block`)으로 남겨 감독 기록으로 보관할 것.

### v0.2 추가 검사에 필요한 것

- **TCC 열거**: `TCC.db` 읽기에 **Full Disk Access** 필요. 없으면 `[skip]` 으로 표시하고 계속 진행.
- **메뉴바 열거**: **손쉬운 사용(Accessibility)** 권한 필요. 실행 시간이 2초 늘어난다(두 샘플 비교).
- **메모리 덤프**: macOS 는 사설 프레임워크를 dyld shared cache 에 올리고 `task_for_pid` 를 막아두므로,
  다른 프로세스 메모리를 직접 못 읽는다. 감독자가 root 로 덤프를 뜬 뒤 `--memory-dump` 로 넘기는 방식.
  ```bash
  sudo lldb -p <pid> -o "process save-core /tmp/target.core"
  ```
  정적 심볼 스캔(`private-hardware-api`)은 `LC_LOAD_DYLIB` 경로 문자열 덕분에 링크된 사설 프레임워크도 이미 잡는다.
  덤프 스캔은 문자열을 난독화/동적 로딩한 경우의 보완책이다.

## 한계 (먼저 읽기)

- **물리 카메라를 대체하지 않는다.** 화면 밖 하드웨어 신호는 카메라로만 확실히 잡힌다.
- `capture-excluded-window` 는 오탐이 있다. 일부 시스템 오버레이도 `sharingState=0` 이라
  소유자 allowlist 로 걸러내지만, 서드파티 앱 중에도 정당하게 쓰는 경우가 있다.
  **단독으로 처벌 근거가 되지 않는다.**
- `private-hardware-api` 는 문자열 참조 기반 정적 검사다. 난독화/동적 링크로 우회 가능.
- TCC 권한 보유 앱 열거, 메뉴바 위장 아이콘 탐지는 아직 없다(권한/사설 API 필요).

## 개발

```bash
python3 -m unittest discover -s tests -v   # 플랫폼 독립, Linux 에서도 통과
```

판정 로직(`examguard/checks.py`)은 순수 함수라 macOS 없이 테스트된다.
macOS 입력 수집은 `examguard/providers/macos.py` 에 격리되어 있다.

## 라이선스

MIT
