import json

import httpx
import pytest

from app.config import Settings
from app.triage.llm import MockClient, OllamaClient, OpenAICompatClient, build_client, parse_llm_output
from tests.conftest import ScriptedClient

OUT = json.dumps({"summary": "s", "techniques": [], "rationale": "r", "recommended_severity": "high",
                  "confidence": 0.9, "suspected_injection": False})


def test_ollama_client_request_shape():
    seen = {}

    def handler(req):
        seen["url"], seen["body"] = str(req.url), json.loads(req.content)
        return httpx.Response(200, json={"message": {"content": OUT}})

    c = OllamaClient("http://ollama:11434/", "llama3.2:3b", transport=httpx.MockTransport(handler))
    text = c.complete("SYS", "USER")
    assert seen["url"] == "http://ollama:11434/api/chat"
    assert seen["body"]["format"] == "json" and seen["body"]["stream"] is False
    assert [m["role"] for m in seen["body"]["messages"]] == ["system", "user"]
    assert parse_llm_output(text).recommended_severity == "high"


def test_openai_compat_client_request_shape():
    seen = {}

    def handler(req):
        seen["url"], seen["auth"] = str(req.url), req.headers["authorization"]
        return httpx.Response(200, json={"choices": [{"message": {"content": OUT}}]})

    c = OpenAICompatClient("https://api.example.com/v1", "k123", "m", transport=httpx.MockTransport(handler))
    assert parse_llm_output(c.complete("s", "u")).confidence == 0.9
    assert seen["url"] == "https://api.example.com/v1/chat/completions" and seen["auth"] == "Bearer k123"


def test_build_client_dispatch():
    assert isinstance(build_client(Settings(llm_provider="mock")), MockClient)
    assert build_client(Settings(llm_provider="ollama", ollama_model="qwen2.5:3b")).name == "ollama:qwen2.5:3b"
    with pytest.raises(ValueError):
        build_client(Settings(llm_provider="openai_compat"))
    with pytest.raises(ValueError):
        build_client(Settings(llm_provider="nope"))


def test_llm_server_down_fails_safe(make_client):
    down = httpx.ConnectError("connection refused")
    c = make_client(ScriptedClient(down, down))
    d = c.post("/alerts", json={"source": "x", "rule_name": "odd"}).json()["triage"]
    assert d["llm_output"] is None and d["recommended_severity"] == "medium" and "ConnectError" in d["error"]
