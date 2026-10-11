"""Layer 1: injection pre-filter.

Scans every string in an untrusted alert for prompt-injection patterns BEFORE
any LLM sees it. It is deliberately a cheap, deterministic screen, not a
complete defense: it catches the common cases and lets us skip the LLM
entirely for high-confidence attacks. Later layers cover what it misses.

Known limits: homoglyphs (e.g. Cyrillic look-alikes), letter-spacing
("i g n o r e"), and semantic injections with no trigger words will evade it.
"""
import base64
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterator

_INVISIBLE = "\u200b\u200c\u200d\u2060\ufeff\u00ad"
_STRIP = dict.fromkeys(map(ord, _INVISIBLE), None)

# (rule name, weight, regex). Weight "high" => skip the LLM for this alert.
_RULES = [
    ("override_instructions", "high",
     r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|prior|above|earlier|all|any|system|your)\b.{0,40}\b(instructions?|prompts?|rules?|directions?|guidelines?)\b"),
    ("role_hijack", "high",
     r"\byou are now\b|\bpretend (to be|you are)\b|\bact as (an? |the )?(ai|assistant|system|unrestricted|admin)\b|\bnew instructions?\s*:"),
    ("severity_manipulation", "high",
     r"\b(set|mark|classify|rate|report|label|treat)\b.{0,40}\b(severity|priority|alert|this)\b.{0,40}\b(low|informational|benign|false[- ]positive|harmless)\b"),
    ("verdict_manipulation", "high",
     r"\b(this (alert )?is (a )?(known )?(false[- ]positive|benign|safe|harmless)|do not (escalate|alert|flag|report))\b"),
    ("markup_or_tool_syntax", "high",
     r"<\s*/?\s*(untrusted_alert|tool_use|tool_call|function_call|system|assistant|instructions?)\b|\[/?INST\]|<\|im_(start|end)\|>"),
    ("prompt_probe", "medium",
     r"\b(system prompt|developer message|reveal your (prompt|instructions)|repeat (the|your) (prompt|instructions))\b"),
    ("jailbreak_terms", "medium", r"\b(jailbreak|DAN mode|developer mode)\b"),
    ("exfil_request", "medium",
     r"\b(send|post|exfiltrate|upload|email)\b.{0,30}\b(api[- ]?keys?|secrets?|credentials?|tokens?)\b"),
    ("output_format_hijack", "medium",
     r"\b(respond|reply|answer|output)\s+(only\s+)?(with|in|using)\b.{0,30}\b(json|yaml|text|markdown|the word)\b"),
]
_COMPILED = [(n, w, re.compile(p, re.I | re.S)) for n, w, p in _RULES]
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/=])")


@dataclass
class PrefilterResult:
    findings: list[dict] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return bool(self.findings)

    @property
    def block_llm(self) -> bool:
        return any(f["weight"] == "high" for f in self.findings)


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(_STRIP)
    return re.sub(r"\s+", " ", text)


def _walk(obj: Any, path: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")


def _match_rules(text: str) -> list[tuple[str, str, str]]:
    hits = []
    for name, weight, rx in _COMPILED:
        m = rx.search(text)
        if m:
            hits.append((name, weight, m.group(0)[:80]))
    return hits


def _decoded_blobs(text: str) -> Iterator[str]:
    for blob in _B64.findall(text):
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
        except Exception:
            continue
        for enc in ("utf-8", "utf-16-le"):
            try:
                decoded = raw.decode(enc)
            except UnicodeDecodeError:
                continue
            if decoded.strip():
                yield decoded


def scan_alert(payload: dict, max_field_chars: int = 4000) -> PrefilterResult:
    result = PrefilterResult()
    for path, value in _walk(payload):
        if len(value) > max_field_chars:
            result.findings.append({"field": path, "rule": "oversized_field", "weight": "medium",
                                    "excerpt": f"{len(value)} chars"})
        if any(ch in value for ch in _INVISIBLE):
            result.findings.append({"field": path, "rule": "hidden_characters", "weight": "medium",
                                    "excerpt": "zero-width / soft-hyphen characters present"})
        text = normalize(value)
        for name, weight, excerpt in _match_rules(text):
            result.findings.append({"field": path, "rule": name, "weight": weight, "excerpt": excerpt})
        # Encoded payloads: only flag if the DECODED text trips a rule, so that
        # legitimate base64 (e.g. PowerShell -enc) isn't a false positive.
        for decoded in _decoded_blobs(text):
            hits = _match_rules(normalize(decoded))
            if hits:
                result.findings.append({"field": path, "rule": "encoded_injection", "weight": "high",
                                        "excerpt": hits[0][2]})
    return result
