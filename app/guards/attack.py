"""Layer 4: verify model-claimed ATT&CK technique IDs against the official STIX data."""
import json
import re
from pathlib import Path

ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


class AttackCatalog:
    def __init__(self, techniques: dict[str, str]):
        self.techniques = techniques

    @classmethod
    def from_stix(cls, path: str) -> "AttackCatalog":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(
                f"ATT&CK STIX bundle not found at '{path}'. Run: python scripts/fetch_stix.py")
        bundle = json.loads(p.read_text(encoding="utf-8"))
        techniques: dict[str, str] = {}
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            for ref in obj.get("external_references", []):
                ext = ref.get("external_id", "")
                if ref.get("source_name") == "mitre-attack" and ID_RE.match(ext):
                    techniques[ext] = obj["name"]
        return cls(techniques)

    def _full_name(self, tid: str) -> str:
        name = self.techniques[tid]
        if "." in tid:
            parent = self.techniques.get(tid.split(".")[0])
            if parent:
                return f"{parent}: {name}"
        return name

    def verify(self, tid: str, name: str | None = None) -> tuple[str, str | None]:
        """Return (status, canonical_name). status: ok | bad_format | unknown_id | name_mismatch."""
        if not ID_RE.match(tid):
            return "bad_format", None
        if tid not in self.techniques:
            return "unknown_id", None
        canonical = self.techniques[tid]
        if name:
            n = _norm(name)
            candidates = {_norm(canonical), _norm(self._full_name(tid))}
            if not any(n == c or n in c or c in n for c in candidates if c):
                return "name_mismatch", canonical
        return "ok", canonical
