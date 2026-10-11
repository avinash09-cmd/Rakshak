import json

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.guards.attack import AttackCatalog
from app.main import create_app

CATALOG = AttackCatalog({
    "T1003": "OS Credential Dumping", "T1003.001": "LSASS Memory",
    "T1059": "Command and Scripting Interpreter", "T1059.001": "PowerShell",
    "T1490": "Inhibit System Recovery", "T1110": "Brute Force",
})


class ScriptedClient:
    """Returns scripted model outputs; the last one repeats. Exceptions are raised."""
    name = "scripted"

    def __init__(self, *outputs):
        self.outputs, self.calls = list(outputs), []

    def complete(self, system, user):
        self.calls.append(user)
        out = self.outputs[min(len(self.calls) - 1, len(self.outputs) - 1)]
        if isinstance(out, Exception):
            raise out
        return out


def llm_json(severity="low", techniques=None, injection=False):
    return json.dumps({"summary": "s", "techniques": techniques or [], "rationale": "r",
                       "recommended_severity": severity, "confidence": 0.5,
                       "suspected_injection": injection})


@pytest.fixture
def make_client():
    def _make(llm_client):
        app = create_app(Settings(database_url="sqlite://"), client=llm_client, catalog=CATALOG)
        return TestClient(app)
    return _make


MIMIKATZ = {"source": "edr", "rule_name": "Mimikatz execution", "host": "DC-01", "user": "svc",
            "command_line": "mimikatz.exe sekurlsa::logonpasswords"}
