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

세 번째 검사가 핵심이다. 화면 캡처·화면 공유는 프레임버퍼만 가져가므로, 밝기나 LED
같은 하드웨어 상태 변화는 원리적으로 잡히지 않는다. 그래서 그런 API를 쓰는 앱을
정적으로 찾는다.

## 설치 / 실행

```bash
pip install pyobjc-framework-Quartz pyobjc-framework-Cocoa
python -m examguard            # 사람이 읽는 출력
python -m examguard --json     # 기계용
python -m examguard --watch 30 # 30초간 캡처 헬퍼 프로세스 샘플링
```

종료 코드: `0` 깨끗함, `2` high 발견. CI/감독 스크립트에서 그대로 쓸 수 있다.

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
