"""Layer 5: deterministic severity floor. The LLM can raise severity above the
floor but can never push the recommendation below it."""
import re
from dataclasses import dataclass, field

SEVERITIES = ("low", "medium", "high", "critical")


def rank(sev: str) -> int:
    return SEVERITIES.index(sev)


def max_sev(a: str, b: str) -> str:
    return a if rank(a) >= rank(b) else b


_CRITICAL = [
    (r"vssadmin(\.exe)?\s+delete\s+shadows", "shadow copy deletion (ransomware precursor)"),
    (r"mimikatz|sekurlsa", "credential-dumping tool"),
    (r"lsass.*(dump|minidump)|(dump|minidump).*lsass", "LSASS memory dump"),
    (r"wevtutil(\.exe)?\s+cl\b", "event log clearing"),
]
_HIGH = [
    (r"(powershell|pwsh).*\s-(enc|encodedcommand)\b", "encoded PowerShell command"),
    (r"certutil.*-urlcache", "certutil used as downloader"),
    (r"\bpsexec(\.exe|svc)?\b", "PsExec remote execution"),
    (r"\bnet1?\s+user\s+.*/add\b", "local account creation"),
    (r"reg(\.exe)?\s+save\s+hklm\\+(sam|security|system)", "registry hive export"),
    (r"bcdedit.*recoveryenabled\s+no", "recovery disabled"),
]


@dataclass
class FloorResult:
    floor: str = "low"
    reasons: list[str] = field(default_factory=list)

    def raise_to(self, sev: str, reason: str) -> None:
        self.reasons.append(f"{sev}: {reason}")
        self.floor = max_sev(self.floor, sev)


def _haystack(payload: dict) -> str:
    parts = [payload.get(k) or "" for k in ("rule_name", "process", "command_line", "raw_message")]
    parts += [str(v) for v in (payload.get("extra") or {}).values()]
    return " ".join(str(p) for p in parts).lower()


def compute_floor(payload: dict, injection_suspected: bool = False) -> FloorResult:
    res = FloorResult()
    text = _haystack(payload)
    for rx, why in _CRITICAL:
        if re.search(rx, text, re.S):
            res.raise_to("critical", why)
    for rx, why in _HIGH:
        if re.search(rx, text, re.S):
            res.raise_to("high", why)
    if payload.get("threat_intel_match"):
        res.raise_to("high", "threat-intel indicator match")
    crit = payload.get("asset_criticality")
    if crit == "critical":
        res.raise_to("high", "critical asset")
    elif crit == "high":
        res.raise_to("medium", "high-value asset")
    vendor = payload.get("vendor_severity")
    if vendor == "critical":
        res.raise_to("high", "vendor severity critical")
    elif vendor == "high":
        res.raise_to("medium", "vendor severity high")
    if injection_suspected:
        res.raise_to("medium", "injection attempt present in alert content")
    return res
