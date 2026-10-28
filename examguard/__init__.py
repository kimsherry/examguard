"""examguard — macOS 시험 무결성 신호 스캐너.

은닉 채널(캡처 제외 창, 캡처 헬퍼 프로세스, 사설 밝기/HID API)을 탐지한다.
판정 로직은 플랫폼 독립적이며, 입력은 providers/macos.py 가 공급한다.
"""
__version__ = "0.3.0"
