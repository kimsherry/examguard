from dataclasses import dataclass, field, asdict
from typing import Any

HIGH, INFO = "high", "info"


@dataclass
class Finding:
    check: str
    severity: str          # HIGH | INFO
    subject: str           # 창 제목 / 프로세스명 / 앱 이름
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def add(self, *findings: Finding) -> None:
        self.findings.extend(findings)

    def skip(self, why: str) -> None:
        self.skipped.append(why)

    @property
    def high_count(self) -> int:
        return sum(f.severity == HIGH for f in self.findings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": 1,
            "findings": [f.as_dict() for f in self.findings],
            "skipped": self.skipped,
            "summary": {"high": self.high_count, "total": len(self.findings)},
        }
