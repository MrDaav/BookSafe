from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse
from pathlib import Path
import asyncio
import hashlib
import io
import json
import logging
import math
import os
import re
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import httpx

app = FastAPI(
    title="BookSafe",
    description="Simple PDF/EPUB security triage tool",
    version="0.1.0",
)

ALLOWED_EXTENSIONS = {".pdf", ".epub"}
MAX_UPLOAD_SIZE = 50 * 1024 * 1024
MAX_ZIP_ENTRIES = 10_000
MAX_ZIP_MEMBER_SIZE = 10 * 1024 * 1024
MAX_ZIP_TOTAL_SIZE = 100 * 1024 * 1024
WORKER_IMAGE = os.getenv("BOOKSAFE_WORKER_IMAGE", "booksafe-worker")
WORKER_TIMEOUT_SECONDS = 45
WORKER_STDOUT_LIMIT = 8 * 1024 * 1024
WORKER_STDERR_LIMIT = 64 * 1024
logger = logging.getLogger(__name__)
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".scr",
    ".apk", ".deb", ".sh", ".msi", ".com", ".jar"
}
URL_PATTERN = re.compile(rb"https?://[^\s<>\"]{4,2048}", re.IGNORECASE)
SUSPICIOUS_PDF_MARKERS = {
    b"/AcroForm": ("form_action", "El PDF contiene un formulario AcroForm.", "low"),
    b"/XFA": ("form_action", "El PDF contiene un formulario XFA.", "medium"),
    b"/GoToR": ("remote_action", "El PDF contiene una acción remota /GoToR.", "medium"),
    b"/GoToE": ("remote_action", "El PDF contiene una acción embebida /GoToE.", "medium"),
    b"/Launch": ("launch_action", "El PDF contiene /Launch, capaz de iniciar recursos externos.", "high"),
    b"/SubmitForm": ("form_action", "El PDF contiene una acción /SubmitForm.", "medium"),
    b"/ImportData": ("data_action", "El PDF contiene una acción /ImportData.", "medium"),
    b"/RichMedia": ("embedded_content", "El PDF contiene contenido RichMedia.", "medium"),
    b"/EmbeddedFile": ("embedded_file", "El PDF contiene un archivo embebido.", "medium"),
}
SUSPICIOUS_SCRIPT_MARKERS = (
    b"powershell", b"cmd.exe", b"wscript", b"mshta", b"certutil",
    b"base64", b"javascript:", b"data:text/html", b"eval(",
)


def virustotal_api_key() -> str | None:
    configured = os.getenv("VIRUSTOTAL_API_KEY")
    if configured:
        return configured

    env_file = Path(__file__).resolve().parent.parent / ".env"
    try:
        with env_file.open(encoding="utf-8") as stream:
            for line in stream:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, value = line.split("=", 1)
                if name.strip() == "VIRUSTOTAL_API_KEY":
                    return value.strip().strip("\"'")
    except OSError:
        return None
    return None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def user_summary(data: dict) -> str:
    assessment = data["assessment"]
    lines = [
        f"BookSafe - resultado de análisis",
        f"Archivo: {data['filename']}",
        f"SHA-256: {data['sha256']}",
        f"Riesgo estimado: {assessment['level']}",
        f"Indicadores: {len(data['findings'])}",
        "",
        assessment["message"],
    ]
    if data["findings"]:
        lines.extend(["", "Hallazgos:"])
        for finding in data["findings"]:
            evidence = f" ({finding['evidence']})" if finding.get("evidence") else ""
            lines.append(
                f"- [{finding['severity'].upper()}] {finding['message']}{evidence}"
            )
    lines.extend([
        "",
        "Nota: análisis estático; no confirma ni descarta malware por sí solo.",
    ])
    return "\n".join(lines)


def virustotal_url(file_hash: str) -> str:
    return f"https://www.virustotal.com/gui/file/{file_hash}/detection"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts if count
    )


def extract_urls(data: bytes) -> list[str]:
    urls = []
    for match in URL_PATTERN.findall(data):
        url = match.rstrip(b".,;:)]}").decode("utf-8", errors="replace")
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc and url not in urls:
            urls.append(url)
    return urls[:100]


def add_url_findings(findings: list[dict], urls: list[str]) -> None:
    for url in urls:
        hostname = urlparse(url).hostname or ""
        severity = "medium" if urlparse(url).scheme == "http" else "low"
        findings.append({
            "severity": severity,
            "category": "external_url",
            "message": f"Se detectó una URL externa: {hostname}",
            "evidence": url,
        })


def detect_type(filename: str, data: bytes) -> dict:
    suffix = Path(filename).suffix.lower()
    if data.startswith(b"%PDF-"):
        real_type = "PDF"
    elif data[:2] == b"PK":
        real_type = "ZIP/EPUB candidate"
    else:
        real_type = "Unknown"

    extension_type = suffix.lstrip(".").upper() or "NONE"
    return {
        "extension": suffix or None,
        "extension_type": extension_type,
        "detected_type": real_type,
        "extension_matches": (
            (suffix == ".pdf" and real_type == "PDF")
            or (suffix == ".epub" and real_type == "ZIP/EPUB candidate")
        ),
    }


async def read_upload(file: UploadFile) -> bytes:
    chunks = []
    total_size = 0

    while chunk := await file.read(1024 * 1024):
        total_size += len(chunk)
        if total_size > MAX_UPLOAD_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"El archivo supera el límite de {MAX_UPLOAD_SIZE // (1024 * 1024)} MiB.",
            )
        chunks.append(chunk)

    return b"".join(chunks)


class WorkerOutputLimitError(Exception):
    pass


async def _read_worker_stream(stream: asyncio.StreamReader, limit: int) -> bytes | None:
    output = bytearray()
    while chunk := await stream.read(64 * 1024):
        output.extend(chunk)
        if len(output) > limit:
            return None
    return bytes(output)


async def _write_worker_input(
    process: asyncio.subprocess.Process,
    data: bytes,
) -> None:
    if process.stdin is None:
        raise RuntimeError("El worker no tiene un canal de entrada.")

    try:
        process.stdin.write(data)
        await process.stdin.drain()
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        process.stdin.close()


async def _collect_worker_output(
    process: asyncio.subprocess.Process,
    data: bytes,
) -> tuple[int, bytes, bytes]:
    if process.stdout is None or process.stderr is None:
        raise RuntimeError("El worker no tiene canales de salida.")

    input_task = asyncio.create_task(_write_worker_input(process, data))
    stdout_task = asyncio.create_task(
        _read_worker_stream(process.stdout, WORKER_STDOUT_LIMIT)
    )
    stderr_task = asyncio.create_task(
        _read_worker_stream(process.stderr, WORKER_STDERR_LIMIT)
    )
    wait_task = asyncio.create_task(process.wait())
    tasks = (input_task, stdout_task, stderr_task, wait_task)

    try:
        while not wait_task.done():
            pending = tuple(
                task for task in (stdout_task, stderr_task, wait_task)
                if not task.done()
            )
            done, _ = await asyncio.wait(
                pending,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if (
                stdout_task in done and stdout_task.result() is None
                or stderr_task in done and stderr_task.result() is None
            ):
                raise WorkerOutputLimitError

        stdout, stderr = await asyncio.gather(stdout_task, stderr_task)
        await input_task
        if stdout is None or stderr is None:
            raise WorkerOutputLimitError
        return process.returncode or 0, stdout, stderr
    finally:
        if not wait_task.done():
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await wait_task
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def _stop_worker_container(cid_path: Path) -> None:
    try:
        container_id = cid_path.read_text(encoding="ascii").strip()
    except OSError as exc:
        logger.error("No se pudo leer el ID del contenedor para limpiarlo.")
        raise HTTPException(
            status_code=502,
            detail="No se pudo confirmar la limpieza del contenedor de análisis.",
        ) from exc
    if not re.fullmatch(r"[a-fA-F0-9]{64}", container_id):
        logger.error("Docker no registró un ID de contenedor válido.")
        raise HTTPException(
            status_code=502,
            detail="No se pudo confirmar la limpieza del contenedor de análisis.",
        )

    try:
        stop_process = await asyncio.create_subprocess_exec(
            "docker",
            "stop",
            "--time",
            "1",
            container_id,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError as exc:
        logger.error("No se pudo iniciar la limpieza del worker Docker.")
        raise HTTPException(
            status_code=502,
            detail="No se pudo detener el contenedor de análisis.",
        ) from exc

    try:
        await asyncio.wait_for(stop_process.wait(), timeout=5)
    except asyncio.TimeoutError as exc:
        stop_process.kill()
        await stop_process.wait()
        logger.error("La limpieza del contenedor Docker agotó el tiempo.")
        raise HTTPException(
            status_code=502,
            detail="No se pudo detener el contenedor de análisis.",
        ) from exc
    if stop_process.returncode != 0:
        logger.error("Docker devolvió un error al detener el worker.")
        raise HTTPException(
            status_code=502,
            detail="No se pudo detener el contenedor de análisis.",
        )


def _valid_worker_result(kind: str, result: object) -> bool:
    if not isinstance(result, dict):
        return False
    findings = result.get("findings")
    if not isinstance(findings, list) or any(
        not isinstance(finding, dict)
        or not isinstance(finding.get("severity"), str)
        or finding["severity"] not in {"low", "medium", "high", "critical"}
        or not isinstance(finding.get("category"), str)
        or not isinstance(finding.get("message"), str)
        for finding in findings
    ):
        return False

    def valid_entropy(value: object) -> bool:
        return (
            type(value) is int and 0 <= value <= 8
            or type(value) is float
            and math.isfinite(value)
            and 0 <= value <= 8
        )

    if kind == "pdf":
        return (
            type(result.get("parser_valid")) is bool
            and (
                result.get("pages") is None
                or type(result.get("pages")) is int and result["pages"] >= 0
            )
            and isinstance(result.get("urls"), list)
            and all(isinstance(url, str) for url in result["urls"])
            and valid_entropy(result.get("entropy"))
        )

    return (
        all(
            type(result.get(key)) is bool
            for key in (
                "valid_zip",
                "has_mimetype",
                "mimetype_correct",
                "container_valid",
                "inspection_complete",
                "encrypted",
            )
        )
        and type(result.get("file_count")) is int
        and result["file_count"] >= 0
        and all(
            isinstance(result.get(key), list)
            and all(isinstance(value, str) for value in result[key])
            for key in ("path_anomalies", "urls", "suspicious_extensions")
        )
        and (
            result.get("max_entropy") is None
            or valid_entropy(result.get("max_entropy"))
        )
    )


async def run_isolated_analysis(kind: str, data: bytes) -> dict:
    if kind not in {"pdf", "epub"}:
        raise ValueError("Tipo de análisis no soportado.")

    with tempfile.TemporaryDirectory(prefix="booksafe-worker-") as temp_dir:
        cid_path = Path(temp_dir) / "container-id"
        command = [
            "docker", "run",
            "--rm",
            "--interactive",
            "--cidfile", str(cid_path),
            "--network", "none",
            "--memory", "256m",
            "--memory-swap", "256m",
            "--cpus", "1.0",
            "--pids-limit", "64",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", "10001:10001",
            "--ulimit", "nofile=64:64",
            "--ulimit", "cpu=45:45",
            WORKER_IMAGE,
            kind,
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            logger.error("No se pudo iniciar Docker para el análisis.")
            raise HTTPException(
                status_code=503,
                detail="El servicio de análisis aislado no está disponible.",
            ) from exc

        completed = False
        try:
            try:
                return_code, stdout, _ = await asyncio.wait_for(
                    _collect_worker_output(process, data),
                    timeout=WORKER_TIMEOUT_SECONDS,
                )
                completed = True
            except asyncio.TimeoutError as exc:
                logger.warning("El worker de análisis excedió el tiempo límite.")
                raise HTTPException(
                    status_code=504,
                    detail="El análisis excedió el tiempo límite.",
                ) from exc
            except WorkerOutputLimitError as exc:
                logger.warning("El worker de análisis excedió el límite de salida.")
                raise HTTPException(
                    status_code=502,
                    detail="El worker produjo una respuesta demasiado grande.",
                ) from exc

            if return_code == 125:
                logger.error("Docker no pudo crear el contenedor de análisis.")
                raise HTTPException(
                    status_code=503,
                    detail="No se pudo iniciar el contenedor de análisis.",
                )
            if return_code != 0:
                logger.error("El worker de análisis terminó con error (%d).", return_code)
                raise HTTPException(
                    status_code=502,
                    detail="El worker no pudo completar el análisis.",
                )

            try:
                result = json.loads(stdout)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                logger.error("El worker devolvió una respuesta JSON inválida.")
                raise HTTPException(
                    status_code=502,
                    detail="El worker devolvió una respuesta inválida.",
                ) from exc
            if not _valid_worker_result(kind, result):
                raise HTTPException(
                    status_code=502,
                    detail="El worker devolvió una respuesta inválida.",
                )
            return result
        finally:
            if not completed and process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                await process.wait()
            if not completed:
                await _stop_worker_container(cid_path)


def analyze_epub(data: bytes) -> dict:
    findings = []
    files_found = []
    valid_zip = False
    has_mimetype = False
    mimetype_correct = False
    container_valid = False
    inspection_complete = True
    urls = []
    encrypted = False
    path_anomalies = []
    max_entropy = None

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
            files_found = [info.filename for info in infos]
            duplicate_names = {
                name for name in files_found if files_found.count(name) > 1
            }
            path_anomalies = [
                name for name in files_found
                if Path(name).is_absolute()
                or ".." in Path(name).parts
                or "\\" in name
            ]
            encrypted = any(info.flag_bits & 0x1 for info in infos)
            if duplicate_names:
                findings.append({
                    "severity": "high",
                    "category": "archive_anomaly",
                    "message": "El EPUB contiene nombres de archivo duplicados.",
                    "evidence": sorted(duplicate_names)[:20],
                })
            if path_anomalies:
                findings.append({
                    "severity": "high",
                    "category": "path_traversal",
                    "message": "El EPUB contiene rutas absolutas o con segmentos inseguros.",
                    "evidence": path_anomalies[:20],
                })
            if encrypted:
                findings.append({
                    "severity": "high",
                    "category": "encrypted_content",
                    "message": "El EPUB contiene entradas cifradas que no pueden inspeccionarse.",
                })
            if len(infos) > MAX_ZIP_ENTRIES:
                findings.append({
                    "severity": "critical",
                    "category": "resource_limit",
                    "message": "El EPUB contiene demasiadas entradas para analizarlo de forma segura.",
                })
                inspection_complete = False
            else:
                total_uncompressed = sum(info.file_size for info in infos)
                oversized = next(
                    (info.filename for info in infos if info.file_size > MAX_ZIP_MEMBER_SIZE),
                    None,
                )
                if oversized or total_uncompressed > MAX_ZIP_TOTAL_SIZE:
                    findings.append({
                        "severity": "critical",
                        "category": "resource_limit",
                        "message": "El EPUB supera los límites de tamaño descomprimido.",
                        "evidence": oversized or f"{total_uncompressed} bytes",
                    })
                    inspection_complete = False

            if inspection_complete:
                bad_member = z.testzip()
                valid_zip = bad_member is None
                if bad_member:
                    findings.append({
                        "severity": "critical",
                        "category": "integrity",
                        "message": "Una entrada del EPUB no supera la comprobación de integridad ZIP.",
                        "evidence": bad_member,
                    })

            if "mimetype" in files_found:
                has_mimetype = True
                if inspection_complete:
                    try:
                        mimetype = z.read("mimetype").decode("utf-8").strip()
                        mimetype_correct = mimetype == "application/epub+zip"
                        if not mimetype_correct:
                            findings.append({
                                "severity": "medium",
                                "category": "structure",
                                "message": "El archivo mimetype del EPUB no contiene el MIME esperado."
                            })
                    except (KeyError, RuntimeError, UnicodeDecodeError, zipfile.BadZipFile):
                        findings.append({
                            "severity": "high",
                            "category": "structure",
                            "message": "No se pudo leer el archivo mimetype."
                        })
            else:
                findings.append({
                    "severity": "high",
                    "category": "structure",
                    "message": "El EPUB no contiene el archivo mimetype obligatorio.",
                })

            if "META-INF/container.xml" not in files_found:
                findings.append({
                    "severity": "high",
                    "category": "structure",
                    "message": "El EPUB no contiene META-INF/container.xml.",
                })
            elif inspection_complete:
                try:
                    container = ET.fromstring(z.read("META-INF/container.xml"))
                    rootfiles = [
                        element for element in container.iter()
                        if element.tag.rsplit("}", 1)[-1] == "rootfile"
                    ]
                    container_valid = bool(rootfiles and all(
                        element.attrib.get("full-path") for element in rootfiles
                    ))
                    if not container_valid:
                        findings.append({
                            "severity": "high",
                            "category": "structure",
                            "message": "META-INF/container.xml no contiene un rootfile válido.",
                        })
                except (ET.ParseError, UnicodeDecodeError, KeyError):
                    findings.append({
                        "severity": "high",
                        "category": "structure",
                        "message": "No se pudo interpretar META-INF/container.xml.",
                    })

            for name in files_found if inspection_complete else []:
                ext = Path(name).suffix.lower()
                if ext in SUSPICIOUS_EXTENSIONS:
                    findings.append({
                        "severity": "high",
                        "category": "embedded_file",
                        "message": f"Se encontró un archivo potencialmente ejecutable: {name}",
                        "evidence": name,
                    })

            script_like = [
                name for name in files_found
                if Path(name).suffix.lower() in {".js", ".vbs", ".ps1", ".bat", ".cmd", ".sh"}
            ]
            for name in script_like:
                findings.append({
                    "severity": "medium",
                    "category": "script",
                    "message": f"Se encontró un script dentro del EPUB: {name}",
                    "evidence": name,
                })

            html_like = [
                name for name in files_found
                if Path(name).suffix.lower() in {
                    ".html", ".xhtml", ".htm", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".sh"
                }
            ]
            for name in html_like:
                try:
                    content = z.read(name)
                    lower = content.lower()
                    urls.extend(extract_urls(content))
                    if b"<script" in lower or b"javascript:" in lower:
                        findings.append({
                            "severity": "medium",
                            "category": "javascript",
                            "message": f"Se detectó JavaScript en contenido EPUB: {name}",
                            "evidence": name,
                        })
                except (KeyError, RuntimeError, UnicodeDecodeError):
                    inspection_complete = False
                    findings.append({
                        "severity": "medium",
                        "category": "inspection_error",
                        "message": f"No se pudo inspeccionar el contenido de {name}.",
                        "evidence": name,
                    })
                    continue
                for marker in SUSPICIOUS_SCRIPT_MARKERS:
                    if marker in lower:
                        findings.append({
                            "severity": "high",
                            "category": "script_indicator",
                            "message": f"Se detectó un indicador de ejecución o código dinámico en {name}.",
                            "evidence": marker.decode("ascii"),
                        })
                        break
            if inspection_complete:
                max_entropy = max(
                    (shannon_entropy(z.read(name)) for name in files_found if name != "mimetype"),
                    default=0.0,
                )
            if inspection_complete:
                add_url_findings(findings, sorted(set(urls)))

    except zipfile.BadZipFile:
        findings.append({
            "severity": "critical",
            "category": "structure",
            "message": "El archivo no es un ZIP/EPUB válido."
        })
    except (OSError, RuntimeError) as exc:
        findings.append({
            "severity": "critical",
            "category": "inspection_error",
            "message": "No se pudo completar la inspección del EPUB.",
            "evidence": type(exc).__name__,
        })

    return {
        "valid_zip": valid_zip,
        "has_mimetype": has_mimetype,
        "mimetype_correct": mimetype_correct,
        "container_valid": container_valid,
        "inspection_complete": inspection_complete,
        "file_count": len(files_found),
        "encrypted": encrypted,
        "path_anomalies": path_anomalies,
        "urls": sorted(set(urls))[:100],
        "max_entropy": round(max_entropy, 3) if max_entropy is not None else None,
        "suspicious_extensions": [
            f for f in files_found if Path(f).suffix.lower() in SUSPICIOUS_EXTENSIONS
        ],
        "findings": findings,
    }

def analyze_pdf(data: bytes) -> dict:
    findings = []

    indicators = [
        (b"/JavaScript", "javascript", "El PDF contiene /JavaScript.", "high"),
        (b"/JS", "javascript", "El PDF contiene /JS.", "high"),
        (b"/OpenAction", "automatic_action", "El PDF contiene /OpenAction.", "medium"),
        (b"/AA", "automatic_action", "El PDF contiene /AA (Additional Actions).", "medium"),
        *[
            (marker, category, message, severity)
            for marker, (category, message, severity) in SUSPICIOUS_PDF_MARKERS.items()
        ],
    ]

    for evidence, category, message, severity in indicators:
        if evidence in data:
            findings.append({
                "severity": severity,
                "category": category,
                "message": message,
                "evidence": evidence.decode("ascii"),
            })

    parser_valid = False
    pages = None
    urls = extract_urls(data)
    add_url_findings(findings, urls)
    entropy = shannon_entropy(data)

    if entropy >= 7.5:
        findings.append({
            "severity": "medium",
            "category": "high_entropy",
            "message": "El archivo tiene entropía alta, compatible con contenido comprimido, cifrado u ofuscado.",
            "evidence": round(entropy, 3),
        })
    if b"%%EOF" in data and data[data.rfind(b"%%EOF") + 5:].strip():
        findings.append({
            "severity": "medium",
            "category": "polyglot",
            "message": "Se detectaron datos después del marcador final %%EOF.",
        })
    for marker in SUSPICIOUS_SCRIPT_MARKERS:
        if marker in data.lower():
            findings.append({
                "severity": "high",
                "category": "script_indicator",
                "message": "Se detectó un indicador de ejecución u ofuscación en el PDF.",
                "evidence": marker.decode("ascii"),
            })

    try:
        from pypdf import PdfReader
        from pypdf.errors import PdfReadError

        reader = PdfReader(io.BytesIO(data))
        pages = len(reader.pages)
        parser_valid = True
    except (OSError, ValueError, KeyError, IndexError, PdfReadError) as exc:
        findings.append({
            "severity": "medium",
            "category": "parser_error",
            "message": "El PDF no pudo ser procesado completamente por el parser.",
            "evidence": type(exc).__name__,
        })

    return {
        "parser_valid": parser_valid,
        "pages": pages,
        "urls": urls,
        "entropy": round(entropy, 3),
        "findings": findings,
    }

def assess(findings: list[dict]) -> dict:
    rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    highest = max((rank.get(f["severity"], 0) for f in findings), default=0)
    level = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "CRITICAL"}[highest]

    return {
        "level": level,
        "confidence": "limited",
        "message": {
            "LOW": "No se encontraron señales sospechosas durante este análisis.",
            "MEDIUM": "Se encontraron elementos que merecen revisión.",
            "HIGH": "Se encontraron elementos potencialmente peligrosos.",
            "CRITICAL": "El archivo presenta problemas graves de estructura o indicadores de alto riesgo.",
        }[level],
    }

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!doctype html>
    <html lang="es">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>BookSafe | Análisis seguro de documentos</title>
      <style>
        :root {
          color-scheme: light;
          --ink: #201735;
          --muted: #706782;
          --purple-950: #29134f;
          --purple-800: #4c238c;
          --purple-700: #6135ad;
          --purple-500: #8057c7;
          --purple-100: #eee9f8;
          --purple-50: #faf9fc;
          --border: #e4ddec;
          --surface: #ffffff;
          --shadow: 0 8px 26px rgba(65, 35, 116, .08);
        }
        * { box-sizing: border-box; }
        body {
          min-height: 100vh;
          margin: 0;
          color: var(--ink);
          font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: #f7f5fa;
        }
        .shell { width: min(900px, calc(100% - 36px)); margin: 0 auto; padding: 30px 0 48px; }
        .topbar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 45px; padding-bottom: 17px; border-bottom: 1px solid var(--border); }
        .brand { display: flex; align-items: center; gap: 12px; font-weight: 750; letter-spacing: -.02em; }
        .brand-mark {
          display: grid; place-items: center; width: 32px; height: 32px; border-radius: 7px;
          color: white; background: var(--purple-800); font-size: 15px;
        }
        .brand-name { font-size: 17px; }
        .version {
          color: var(--muted); font-size: 12px; font-weight: 600;
        }
        .hero { max-width: 640px; margin-bottom: 26px; }
        .eyebrow { margin: 0 0 9px; color: var(--purple-700); font-size: 12px; font-weight: 700; }
        h1 { margin: 0 0 9px; color: var(--purple-950); font-size: clamp(29px, 5vw, 40px); line-height: 1.12; letter-spacing: -.035em; }
        .intro { max-width: 580px; margin: 0; color: var(--muted); font-size: 15px; line-height: 1.55; }
        .card { border: 1px solid var(--border); border-radius: 12px; background: var(--surface); box-shadow: var(--shadow); }
        .upload-card { padding: 8px; }
        .dropzone {
          display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 205px;
          padding: 24px; border: 1px dashed #c9b8ec; border-radius: 8px; background: var(--purple-50);
          text-align: center; transition: .2s ease;
        }
        .dropzone.dragging, .dropzone:hover { border-color: var(--purple-500); background: #f5f1fb; }
        .upload-icon { display: grid; place-items: center; width: 42px; height: 42px; margin-bottom: 13px; border: 1px solid #dcd1ed; border-radius: 9px; color: var(--purple-700); background: var(--purple-100); font-size: 21px; }
        .drop-title { margin: 0 0 6px; font-size: 17px; font-weight: 700; }
        .drop-help { margin: 0 0 16px; color: var(--muted); font-size: 13px; }
        input[type="file"] { display: none; }
        .choose { display: inline-flex; align-items: center; justify-content: center; padding: 10px 16px; border-radius: 7px; color: white; background: var(--purple-700); cursor: pointer; font-size: 13px; font-weight: 700; transition: .2s ease; }
        .choose:hover { background: var(--purple-800); }
        .selected { min-height: 19px; margin: 12px 0 0; color: var(--purple-800); font-size: 12px; font-weight: 600; }
        .actions { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 16px 6px 5px; }
        .hint { margin: 0; color: var(--muted); font-size: 12px; }
        button { border: 0; border-radius: 7px; padding: 11px 18px; color: white; background: var(--purple-800); cursor: pointer; font: inherit; font-size: 13px; font-weight: 700; transition: .2s ease; }
        button:hover:not(:disabled) { background: var(--purple-950); }
        button:disabled { opacity: .5; cursor: not-allowed; }
        .result-card { display: none; margin-top: 22px; padding: 22px; }
        .result-card.visible { display: block; }
        .result-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; margin-bottom: 19px; }
        .result-label { margin: 0 0 5px; color: var(--muted); font-size: 12px; font-weight: 750; letter-spacing: .08em; text-transform: uppercase; }
        #status { margin: 0; color: var(--purple-950); font-size: 27px; letter-spacing: -.03em; }
        .risk { padding: 8px 11px; border-radius: 5px; font-size: 11px; font-weight: 800; letter-spacing: .05em; }
        .risk.low { color: #166534; background: #dcfce7; }
        .risk.medium { color: #92400e; background: #fef3c7; }
        .risk.high, .risk.critical { color: #991b1b; background: #fee2e2; }
        .result-meta { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 22px; }
        .meta { padding: 12px 13px; border: 1px solid var(--border); border-radius: 7px; background: #fcfbff; }
        .meta span { display: block; color: var(--muted); font-size: 11px; }
        .meta strong { display: block; overflow: hidden; margin-top: 4px; text-overflow: ellipsis; white-space: nowrap; font-size: 14px; }
        .hash-box { margin: 0 0 18px; padding: 12px 13px; border: 1px solid var(--border); border-radius: 7px; background: #fcfbff; }
        .hash-label { display: block; margin-bottom: 7px; color: var(--muted); font-size: 11px; }
        .hash-row { display: flex; align-items: center; gap: 10px; }
        .hash-value { min-width: 0; overflow-wrap: anywhere; color: var(--purple-950); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; line-height: 1.5; }
        .copy-hash { flex: 0 0 auto; padding: 7px 10px; font-size: 11px; }
        .disclaimer { margin: 0; color: var(--muted); font-size: 12px; line-height: 1.5; }
        .summary { margin: 18px 0; padding: 16px; border: 1px solid var(--border); border-radius: 7px; background: #fcfbff; }
        .summary-title { margin: 0 0 10px; font-size: 14px; }
        .finding { display: flex; gap: 9px; align-items: flex-start; padding: 9px 0; border-top: 1px solid var(--border); font-size: 13px; line-height: 1.45; }
        .finding-level { min-width: 58px; padding: 3px 5px; border-radius: 4px; font-size: 10px; font-weight: 800; text-align: center; }
        .finding-level.high, .finding-level.critical { color: #991b1b; background: #fee2e2; }
        .finding-level.medium { color: #92400e; background: #fef3c7; }
        .finding-level.low { color: #166534; background: #dcfce7; }
        .result-actions { display: flex; flex-wrap: wrap; gap: 9px; margin-top: 16px; }
        .secondary { border: 1px solid #d8cbea; color: var(--purple-800); background: white; }
        .secondary:hover:not(:disabled) { color: white; background: var(--purple-800); }
        .vt-status { margin: 12px 0 0; color: var(--muted); font-size: 12px; line-height: 1.5; }
        .vt-result { display: none; margin-top: 12px; padding: 13px; border-left: 3px solid var(--purple-500); background: var(--purple-50); font-size: 13px; line-height: 1.5; }
        .vt-result.visible { display: block; }
        .vt-stats { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 9px; }
        .vt-stat { padding: 4px 8px; border-radius: 4px; background: white; font-size: 11px; font-weight: 700; }
        pre { max-height: 280px; margin: 18px 0 0; padding: 16px; overflow: auto; border-radius: 7px; color: #e9ddff; background: #201735; font-size: 12px; line-height: 1.55; }
        .footer { margin-top: 23px; color: var(--muted); font-size: 12px; }
        @media (max-width: 620px) {
          .shell { width: min(100% - 24px, 960px); padding-top: 24px; }
          .topbar { margin-bottom: 27px; }
          .actions, .result-head { align-items: stretch; flex-direction: column; }
          button { width: 100%; }
          .result-meta { grid-template-columns: 1fr; }
        }
      </style>
    </head>
    <body>
      <main class="shell">
        <header class="topbar">
          <div class="brand"><span class="brand-mark">B</span><span class="brand-name">BookSafe</span></div>
          <span class="version">Analizador de documentos · v0.1</span>
        </header>
        <section class="hero">
          <p class="eyebrow">Análisis de archivos</p>
          <h1>Revisa un documento antes de abrirlo</h1>
          <p class="intro">Selecciona un PDF o EPUB para comprobar su estructura e identificar indicadores que requieran revisión.</p>
        </section>
        <section class="card upload-card">
          <div class="dropzone" id="dropzone">
            <div class="upload-icon">↑</div>
            <p class="drop-title">Selecciona un archivo</p>
            <p class="drop-help">Arrástralo aquí o utiliza el botón · PDF o EPUB</p>
            <label class="choose" for="file">Elegir archivo</label>
            <input id="file" type="file" accept=".pdf,.epub">
            <p class="selected" id="selected">Ningún archivo seleccionado</p>
          </div>
          <div class="actions">
            <p class="hint">Análisis estático · límite de 50 MiB</p>
            <button id="scan-button" onclick="scan()" disabled>Iniciar análisis</button>
          </div>
        </section>
        <section class="card result-card" id="result-card">
          <div class="result-head">
            <div><p class="result-label">Resultado del análisis</p><h2 id="status">Preparando...</h2></div>
            <span class="risk" id="risk"></span>
          </div>
          <div class="result-meta">
            <div class="meta"><span>Archivo</span><strong id="result-file">—</strong></div>
            <div class="meta"><span>Tamaño</span><strong id="result-size">—</strong></div>
            <div class="meta"><span>Indicadores</span><strong id="result-findings">—</strong></div>
          </div>
          <div class="hash-box">
            <span class="hash-label">SHA-256 completo</span>
            <div class="hash-row">
              <code class="hash-value" id="result-hash">—</code>
              <button class="secondary copy-hash" id="copy-hash-button" onclick="copyHash()">Copiar hash</button>
            </div>
          </div>
          <div class="summary">
            <h3 class="summary-title">Qué se encontró</h3>
            <div id="findings-list"><p class="disclaimer">Sin hallazgos registrados.</p></div>
          </div>
          <div class="result-actions">
            <button class="secondary" id="copy-button" onclick="copySummary()">Copiar resumen</button>
            <a class="choose secondary" id="vt-link" href="#" target="_blank" rel="noopener">Abrir en VirusTotal</a>
          </div>
          <p class="vt-status" id="vt-status">VirusTotal: se consultará únicamente el SHA-256; BookSafe no sube el archivo.</p>
          <div class="vt-result" id="vt-result"></div>
          <p class="disclaimer">Revisa los hallazgos antes de abrir el archivo. BookSafe es una herramienta de triaje, no un antivirus.</p>
          <pre id="result" aria-label="Detalles técnicos del análisis"></pre>
        </section>
        <p class="footer">BookSafe · análisis local de documentos</p>
      </main>
      <script>
        const fileInput = document.getElementById("file");
        const dropzone = document.getElementById("dropzone");
        const selected = document.getElementById("selected");
        const scanButton = document.getElementById("scan-button");
        const resultCard = document.getElementById("result-card");
        let currentSummary = "";
        let currentHash = "";

        function setFile(file) {
          if (!file) return;
          fileInput.files = (() => {
            const transfer = new DataTransfer();
            transfer.items.add(file);
            return transfer.files;
          })();
          selected.textContent = file.name;
          scanButton.disabled = false;
        }

        fileInput.addEventListener("change", () => setFile(fileInput.files[0]));
        ["dragenter", "dragover"].forEach(eventName => dropzone.addEventListener(eventName, event => {
          event.preventDefault();
          dropzone.classList.add("dragging");
        }));
        ["dragleave", "drop"].forEach(eventName => dropzone.addEventListener(eventName, event => {
          event.preventDefault();
          dropzone.classList.remove("dragging");
        }));
        dropzone.addEventListener("drop", event => setFile(event.dataTransfer.files[0]));

        function formatBytes(bytes) {
          if (bytes < 1024) return bytes + " B";
          if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
          return (bytes / (1024 * 1024)).toFixed(1) + " MB";
        }

        function escapeHtml(value) {
          return String(value).replace(/[&<>"']/g, character => ({
            "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
          }[character]));
        }

        async function scan() {
          const file = fileInput.files[0];
          if (!file) return;
          const fd = new FormData();
          fd.append("file", file);
          scanButton.disabled = true;
          scanButton.textContent = "Analizando...";
          resultCard.classList.add("visible");
          document.getElementById("status").textContent = "Analizando archivo...";
          try {
            const r = await fetch("/scan", {method:"POST", body:fd});
            const data = await r.json();
            if (!r.ok) throw new Error(data.detail || "No se pudo completar el análisis.");
            const assessment = data.assessment;
            const level = assessment.level.toLowerCase();
            document.getElementById("status").textContent = assessment.message;
            const risk = document.getElementById("risk");
            risk.textContent = assessment.level;
            risk.className = "risk " + level;
            document.getElementById("result-file").textContent = data.filename;
            document.getElementById("result-size").textContent = formatBytes(data.size_bytes);
            currentHash = data.sha256;
            document.getElementById("result-hash").textContent = data.sha256;
            document.getElementById("result-findings").textContent =
              data.security_summary.finding_count + " (" + data.security_summary.high_or_critical_count + " altos)";
            currentSummary = data.user_summary;
            const findingsList = document.getElementById("findings-list");
            findingsList.innerHTML = data.findings.length ? data.findings.map(finding =>
              '<div class="finding"><span class="finding-level ' + escapeHtml(finding.severity) + '">' +
              escapeHtml(finding.severity.toUpperCase()) + '</span><span>' + escapeHtml(finding.message) + '</span></div>'
            ).join("") : '<p class="disclaimer">No se encontraron indicadores en este análisis.</p>';
            document.getElementById("vt-link").href = data.virustotal.url;
            lookupVirusTotal(data.sha256);
            document.getElementById("result").textContent = JSON.stringify(data, null, 2);
          } catch (error) {
            document.getElementById("status").textContent = "No se pudo analizar";
            document.getElementById("risk").textContent = "ERROR";
            document.getElementById("risk").className = "risk critical";
            document.getElementById("result").textContent = error.message;
          } finally {
            scanButton.disabled = false;
            scanButton.textContent = "Iniciar análisis";
          }

          async function copySummary() {
            if (!currentSummary) return;
            await navigator.clipboard.writeText(currentSummary);
            const button = document.getElementById("copy-button");
            button.textContent = "Resumen copiado";
            setTimeout(() => button.textContent = "Copiar resumen", 1800);
          }

          async function copyHash() {
            if (!currentHash) return;
            await navigator.clipboard.writeText(currentHash);
            const button = document.getElementById("copy-hash-button");
            button.textContent = "Copiado";
            setTimeout(() => button.textContent = "Copiar hash", 1800);
          }

          async function lookupVirusTotal(hash) {
            const status = document.getElementById("vt-status");
            const result = document.getElementById("vt-result");
            result.classList.remove("visible");
            try {
              const response = await fetch("/virustotal/" + hash);
              const data = await response.json();
              if (!response.ok) throw new Error(data.detail || "Consulta no disponible.");
              if (!data.available) {
                status.textContent = "VirusTotal: abre el enlace para consultar manualmente el SHA-256.";
              } else if (!data.found) {
                status.textContent = "VirusTotal: no hay un análisis previo para este SHA-256.";
                result.textContent = "VirusTotal no tiene un registro previo para este archivo. Puedes abrir el enlace para revisarlo directamente.";
                result.classList.add("visible");
              } else {
                const stats = data.stats || {};
                const total = Object.values(stats).reduce((total, value) => total + value, 0);
                status.textContent = "VirusTotal consultado";
                result.innerHTML = "<strong>" + (stats.malicious || 0) +
                  " detecciones maliciosas de " + total + " motores</strong>" +
                  '<div class="vt-stats">' +
                  Object.entries(stats).map(([name, value]) =>
                    '<span class="vt-stat">' + escapeHtml(name) + ": " + escapeHtml(value) + "</span>"
                  ).join("") + "</div>";
                result.classList.add("visible");
              }
            } catch (error) {
              status.textContent = "VirusTotal: no se pudo completar la consulta.";
              result.textContent = "Revisa el enlace manual o verifica la configuración de la API.";
              result.classList.add("visible");
            }
          }
        }
      </script>
    </body>
    </html>
    """

@app.post("/scan")
async def scan(file: UploadFile = File(...)):
    suffix = Path(file.filename or "").suffix.lower()

    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Solo se permiten archivos .pdf y .epub en esta versión."
        )

    data = await read_upload(file)

    if not data:
        raise HTTPException(status_code=400, detail="El archivo está vacío.")

    detected = detect_type(file.filename, data)
    findings = []

    if not detected["extension_matches"]:
        findings.append({
            "severity": "high",
            "category": "type_mismatch",
            "message": "La extensión no coincide con el tipo detectado.",
        })

    analysis = {}
    if suffix == ".epub" and detected["detected_type"] == "ZIP/EPUB candidate":
        analysis = {"epub": await run_isolated_analysis("epub", data)}
        findings.extend(analysis["epub"]["findings"])
    elif suffix == ".pdf" and detected["detected_type"] == "PDF":
        analysis = {"pdf": await run_isolated_analysis("pdf", data)}
        findings.extend(analysis["pdf"]["findings"])

    return {
        "filename": file.filename,
        "size_bytes": len(data),
        "sha256": sha256_bytes(data),
        "file": detected,
        "analysis": analysis,
        "findings": findings,
        "assessment": assess(findings),
        "security_summary": {
            "finding_count": len(findings),
            "high_or_critical_count": sum(
                finding["severity"] in {"high", "critical"} for finding in findings
            ),
            "note": "La detección es estática; confirma los indicadores con un antivirus, sandbox o servicio de reputación antes de abrir el archivo.",
        },
        "user_summary": user_summary({
            "filename": file.filename,
            "sha256": sha256_bytes(data),
            "assessment": assess(findings),
            "findings": findings,
        }),
        "virustotal": {
            "url": virustotal_url(sha256_bytes(data)),
            "lookup_available": bool(virustotal_api_key()),
        },
        "disclaimer": "Este análisis no garantiza que el archivo sea completamente seguro.",
    }


@app.get("/virustotal/{file_hash}")
async def virustotal_lookup(file_hash: str):
    if not re.fullmatch(r"[a-fA-F0-9]{64}", file_hash):
        raise HTTPException(status_code=400, detail="El SHA-256 no es válido.")

    url = virustotal_url(file_hash.lower())
    api_key = virustotal_api_key()
    if not api_key:
        return {
            "available": False,
            "url": url,
            "message": "Configura VIRUSTOTAL_API_KEY para consultar resultados desde BookSafe.",
        }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash.lower()}",
                headers={"x-apikey": api_key},
            )
        if response.status_code == 404:
            return {
                "available": True,
                "found": False,
                "url": url,
                "message": "VirusTotal no tiene un análisis previo para este hash.",
            }
        if response.status_code in {401, 403}:
            raise HTTPException(status_code=502, detail="La API key de VirusTotal no es válida o no tiene permisos.")
        response.raise_for_status()
        attributes = response.json()["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})
        return {
            "available": True,
            "found": True,
            "url": url,
            "stats": stats,
            "reputation": attributes.get("reputation"),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="VirusTotal no respondió a tiempo.") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="No se pudo consultar VirusTotal.") from exc
