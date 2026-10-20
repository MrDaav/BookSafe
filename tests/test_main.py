import asyncio

import pytest
from fastapi.testclient import TestClient
from app import main

app = main.app

client = TestClient(app)


@pytest.fixture(autouse=True)
def mocked_isolated_worker(monkeypatch):
    original_runner = main.run_isolated_analysis

    async def run_in_process_for_test(kind, data):
        if kind == "pdf":
            return main.analyze_pdf(data)
        return main.analyze_epub(data)

    monkeypatch.setattr(main, "run_isolated_analysis", run_in_process_for_test)
    yield original_runner


def test_rejects_unknown_extension():
    response = client.post(
        "/scan",
        files={"file": ("test.txt", b"hello", "text/plain")}
    )
    assert response.status_code == 400

def test_pdf_hash_and_type():
    response = client.post(
        "/scan",
        files={"file": ("test.pdf", b"%PDF-1.7\nhello", "application/pdf")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["file"]["detected_type"] == "PDF"
    assert len(data["sha256"]) == 64

def test_epub_suspicious_file():
    import io, zipfile
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        z.writestr("mimetype", "application/epub+zip")
        z.writestr("META-INF/container.xml", "<container/>")
        z.writestr("EPUB/malware.exe", b"not really malware")
    response = client.post(
        "/scan",
        files={"file": ("book.epub", buffer.getvalue(), "application/epub+zip")}
    )
    assert response.status_code == 200
    data = response.json()
    assert any(f["category"] == "embedded_file" for f in data["findings"])

def test_rejects_oversized_upload():
    from app.main import MAX_UPLOAD_SIZE
    response = client.post(
        "/scan",
        files={"file": ("test.pdf", b"x" * (MAX_UPLOAD_SIZE + 1), "application/pdf")}
    )
    assert response.status_code == 413

def test_epub_requires_structure():
    import io, zipfile
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        z.writestr("notes.txt", "not an EPUB")

    response = client.post(
        "/scan",
        files={"file": ("invalid.epub", buffer.getvalue(), "application/epub+zip")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["assessment"]["level"] == "HIGH"
    assert any(f["category"] == "structure" for f in data["findings"])

def test_pdf_reports_security_indicators():
    payload = b"%PDF-1.7\n/OpenAction /JavaScript /URI https://example.test/payload\n%%EOF"
    response = client.post(
        "/scan",
        files={"file": ("suspicious.pdf", payload, "application/pdf")}
    )
    assert response.status_code == 200
    data = response.json()
    categories = {finding["category"] for finding in data["findings"]}
    assert "javascript" in categories
    assert "external_url" in categories
    assert data["security_summary"]["high_or_critical_count"] >= 1

def test_epub_reports_path_anomaly():
    import io, zipfile
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        z.writestr("mimetype", "application/epub+zip")
        z.writestr("META-INF/container.xml", "<container/>")
        z.writestr("../payload.js", "javascript: alert(1)")

    response = client.post(
        "/scan",
        files={"file": ("anomaly.epub", buffer.getvalue(), "application/epub+zip")}
    )
    assert response.status_code == 200
    data = response.json()
    assert any(f["category"] == "path_traversal" for f in data["findings"])

def test_response_includes_copyable_summary_and_virustotal_link():
    response = client.post(
        "/scan",
        files={"file": ("test.pdf", b"%PDF-1.7\nhello", "application/pdf")}
    )
    data = response.json()
    assert "SHA-256:" in data["user_summary"]
    assert data["virustotal"]["url"].startswith(
        "https://www.virustotal.com/gui/file/"
    )


def test_worker_runs_with_restricted_docker_options(monkeypatch, mocked_isolated_worker):
    class FakeInput:
        def write(self, data):
            self.data = data

        async def drain(self):
            return None

        def close(self):
            return None

    class FakeStream:
        def __init__(self, data):
            self.data = data

        async def read(self, size):
            data, self.data = self.data[:size], self.data[size:]
            return data

    class FakeProcess:
        def __init__(self):
            self.stdin = FakeInput()
            self.stdout = FakeStream(
                b'{"parser_valid":false,"pages":null,"urls":[],"entropy":0,'
                b'"findings":[]}'
            )
            self.stderr = FakeStream(b"")
            self.returncode = None

        async def wait(self):
            self.returncode = 0
            return 0

        def kill(self):
            self.returncode = -9

    invoked = {}

    async def fake_create_subprocess_exec(*args, **kwargs):
        invoked["args"] = args
        invoked["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(
        main.asyncio, "create_subprocess_exec", fake_create_subprocess_exec
    )
    result = asyncio.run(mocked_isolated_worker("pdf", b"%PDF-1.7"))

    assert result["findings"] == []
    command = invoked["args"]
    assert invoked["kwargs"]["stdin"] == asyncio.subprocess.PIPE
    assert invoked["kwargs"]["stdout"] == asyncio.subprocess.PIPE
    assert command[:2] == ("docker", "run")
    assert "--rm" in command
    assert "--network" in command and command[command.index("--network") + 1] == "none"
    assert "--memory" in command and command[command.index("--memory") + 1] == "256m"
    assert "--cpus" in command and command[command.index("--cpus") + 1] == "1.0"
    assert "--read-only" in command
    assert "--pids-limit" in command and command[command.index("--pids-limit") + 1] == "64"
    assert "--tmpfs" in command
    assert "--cap-drop" in command and command[command.index("--cap-drop") + 1] == "ALL"
    assert "--security-opt" in command
    assert "no-new-privileges" in command
    assert "--user" in command and command[command.index("--user") + 1] == "10001:10001"
    assert command[-2:] == ("booksafe-worker", "pdf")
    assert not main._valid_worker_result(
        "pdf",
        {
            "parser_valid": False,
            "pages": None,
            "urls": [],
            "entropy": 0,
            "findings": [{"severity": [], "category": "x", "message": "x"}],
        },
    )


def test_virustotal_lookup_without_api_key(monkeypatch):
    monkeypatch.setattr("app.main.virustotal_api_key", lambda: None)
    response = client.get("/virustotal/" + ("a" * 64))
    assert response.status_code == 200
    assert response.json()["available"] is False

def test_virustotal_lookup_with_api_key(monkeypatch):
    import httpx

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url, headers):
            return httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 2,
                                "harmless": 60,
                            },
                            "reputation": 4,
                        }
                    }
                },
                request=httpx.Request("GET", url),
            )

    monkeypatch.setattr("app.main.virustotal_api_key", lambda: "test-key")
    monkeypatch.setattr("app.main.httpx.AsyncClient", lambda timeout: FakeClient())
    response = client.get("/virustotal/" + ("b" * 64))
    assert response.status_code == 200
    assert response.json()["stats"]["malicious"] == 2
