import json
import re
from typing import Protocol

import httpx

from ..config import Settings
from ..schemas import LLMTriageOutput


class TriageClient(Protocol):
    name: str

    def complete(self, system: str, user: str) -> str: ...


class ClaudeClient:
    def __init__(self, model: str):
        import anthropic  # imported lazily so the mock path needs no API key

        self.client = anthropic.Anthropic()
        self.model = model
        self.name = model

    def complete(self, system: str, user: str) -> str:
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=1000,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")


_MOCK_RULES = [
    (r"mimikatz|sekurlsa|lsass", ("T1003.001", "LSASS Memory"), "critical", "Credential dumping activity."),
    (r"vssadmin(\.exe)? delete shadows", ("T1490", "Inhibit System Recovery"), "critical", "Shadow copies deleted."),
    (r"\s-(enc|encodedcommand)\b", ("T1059.001", "PowerShell"), "high", "Encoded PowerShell execution."),
    (r"psexec", ("T1569.002", "Service Execution"), "high", "Remote service execution via PsExec."),
    (r"certutil", ("T1105", "Ingress Tool Transfer"), "high", "certutil used to fetch a remote file."),
    (r"net1? user .*/add", ("T1136.001", "Local Account"), "high", "Local account created."),
    (r"schtasks", ("T1053.005", "Scheduled Task"), "medium", "Scheduled task created."),
    (r"failed password|failed login", ("T1110", "Brute Force"), "medium", "Repeated authentication failures."),
    (r"port scan|nmap", ("T1046", "Network Service Discovery"), "medium", "Network scanning activity."),
]


class MockClient:
    """Offline heuristic stand-in so the whole pipeline runs without an API key.

    It does NOT read instructions inside alerts, so evaluation numbers produced
    with it say nothing about prompt-injection robustness of a real model.
    """

    name = "mock-heuristic"

    def complete(self, system: str, user: str) -> str:
        body = re.search(r"<untrusted_alert>\n(.*)\n</untrusted_alert>", user, re.S)
        alert = json.loads(body.group(1)) if body else {}
        text = " ".join(str(v) for v in alert.values()).lower()
        for rx, (tid, tname), sev, summary in _MOCK_RULES:
            if re.search(rx, text):
                return json.dumps({
                    "summary": f"{summary} Host: {alert.get('host')}.",
                    "techniques": [{"id": tid, "name": tname}],
                    "rationale": f"Matched indicator in rule/command fields ({alert.get('rule_name')}).",
                    "recommended_severity": sev, "confidence": 0.7, "suspected_injection": False})
        return json.dumps({
            "summary": f"Routine activity on {alert.get('host')}; no malicious indicators.",
            "techniques": [], "rationale": "No suspicious indicators in the supplied fields.",
            "recommended_severity": "low", "confidence": 0.6, "suspected_injection": False})


class OllamaClient:
    """Free, local, private: talks to an Ollama server (no API key, data never leaves your machine)."""

    def __init__(self, base_url: str, model: str, timeout: float = 180.0, transport=None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.name = f"ollama:{model}"
        self._http = httpx.Client(timeout=timeout, transport=transport)

    def complete(self, system: str, user: str) -> str:
        r = self._http.post(f"{self.base_url}/api/chat", json={
            "model": self.model, "stream": False, "format": "json", "options": {"temperature": 0},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
        r.raise_for_status()
        return r.json()["message"]["content"]


class OpenAICompatClient:
    """Any OpenAI-compatible chat endpoint, e.g. free tiers of Groq or Gemini, or OpenRouter."""

    def __init__(self, base_url: str, api_key: str, model: str, timeout: float = 60.0, transport=None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.name = f"openai-compat:{model}"
        self._http = httpx.Client(timeout=timeout, transport=transport)

    def complete(self, system: str, user: str) -> str:
        r = self._http.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"model": self.model, "temperature": 0, "response_format": {"type": "json_object"},
                  "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


def build_client(settings: Settings) -> TriageClient:
    provider = settings.llm_provider
    if provider == "mock":
        return MockClient()
    if provider == "ollama":
        return OllamaClient(settings.ollama_base_url, settings.ollama_model)
    if provider == "openai_compat":
        if not (settings.openai_base_url and settings.openai_api_key and settings.openai_model):
            raise ValueError("openai_compat needs OPENAI_BASE_URL, OPENAI_API_KEY and OPENAI_MODEL")
        return OpenAICompatClient(settings.openai_base_url, settings.openai_api_key, settings.openai_model)
    if provider == "anthropic":
        return ClaudeClient(settings.anthropic_model)
    raise ValueError(f"unknown LLM_PROVIDER '{provider}' (use mock, ollama, openai_compat or anthropic)")


def parse_llm_output(text: str) -> LLMTriageOutput:
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.I)
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in model output")
    return LLMTriageOutput.model_validate(json.loads(cleaned[start:end + 1]))
