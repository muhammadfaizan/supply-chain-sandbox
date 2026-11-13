"""Data types shared by every stage: findings, the report, and the verdict."""
from dataclasses import dataclass, field

SEVERITIES = ("block", "warn", "info")
STAGES = ("static", "dynamic", "tool")


@dataclass(frozen=True)
class Finding:
    severity: str  # one of SEVERITIES
    stage: str     # one of STAGES
    message: str


@dataclass
class Report:
    target: str
    ecosystems: dict = field(default_factory=dict)  # ecosystem -> [manifest paths]
    coverage: dict = field(default_factory=dict)    # ecosystem -> {check: status}
    findings: list = field(default_factory=list)
    install_exit: int | None = None
    events: list = field(default_factory=list)      # raw monitor events (dicts)
    tool_notes: list = field(default_factory=list)

    def add(self, severity: str, stage: str, message: str) -> None:
        if severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {severity}")
        self.findings.append(Finding(severity, stage, message))

    def cover(self, ecosystem: str, check: str, status: str) -> None:
        self.coverage.setdefault(ecosystem, {})[check] = status

    def dedupe(self) -> None:
        """Drop repeated findings, keeping the first occurrence.

        pip runs setup.py more than once (metadata, then wheel), so the same
        event can be logged twice.
        """
        seen, unique = set(), []
        for f in self.findings:
            if f not in seen:
                seen.add(f)
                unique.append(f)
        self.findings = unique

    @property
    def verdict(self) -> str:
        severities = {f.severity for f in self.findings}
        if "block" in severities:
            return "block"
        if "warn" in severities:
            return "warn"
        return "pass"
