import json
import sys

from app.main import MAX_UPLOAD_SIZE, analyze_epub, analyze_pdf


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"pdf", "epub"}:
        print("Tipo de análisis no soportado.", file=sys.stderr)
        return 2

    data = sys.stdin.buffer.read(MAX_UPLOAD_SIZE + 1)
    if len(data) > MAX_UPLOAD_SIZE:
        print("El archivo supera el límite permitido.", file=sys.stderr)
        return 2

    analysis = analyze_pdf(data) if sys.argv[1] == "pdf" else analyze_epub(data)
    sys.stdout.write(json.dumps(analysis, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
