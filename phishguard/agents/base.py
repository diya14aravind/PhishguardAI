from dataclasses import dataclass, field


@dataclass
class AgentResult:
    name: str
    score: float = 0.0
    findings: list = field(default_factory=list)  # readable sentences for the user
    signals: list = field(default_factory=list)  # short codes used by fusion and threat intel
    details: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "name": self.name,
            "score": round(self.score, 3),
            "findings": self.findings,
            "signals": self.signals,
            "details": self.details,
        }


def noisy_or(weights):
    """Combine independent evidence: 1 - product of (1 - w)."""
    remaining = 1.0
    for weight in weights:
        remaining *= 1.0 - max(0.0, min(1.0, weight))
    return 1.0 - remaining
