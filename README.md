# BookSafe

MVP educativo para análisis estático de archivos PDF y EPUB antes de abrirlos.

## Qué hace

- Recibe PDF/EPUB.
- Comprueba extensión vs. magic bytes.
- Calcula SHA-256.
- Inspecciona la estructura ZIP de EPUB.
- Busca archivos ejecutables/scripts dentro de EPUB.
- Busca JavaScript y acciones automáticas en PDF.
- Extrae URLs externas, detecta contenido cifrado/ofuscado y anomalías de archivos ZIP.
- Identifica indicadores de ejecución, formularios remotos, archivos embebidos y PDFs poliglotas.
- Genera un nivel de riesgo: LOW / MEDIUM / HIGH / CRITICAL.
- Genera un resumen legible y copiable para compartirlo con otros servicios.
- Permite consultar el SHA-256 en VirusTotal sin subir el archivo.
- Expone una API FastAPI y una interfaz web mínima.
- Limita las cargas a 50 MiB y la inspección EPUB a límites de entradas y descompresión.
- Ejecuta cada análisis PDF/EPUB en un contenedor Docker temporal, sin red, con
  límites de memoria, CPU, procesos y permisos.

## Importante

Esto NO es un antivirus y NO garantiza que un archivo sea seguro.

## Ejecutar

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
docker build -f Dockerfile.worker -t booksafe-worker .
uvicorn app.main:app --reload
```

La API requiere Docker disponible para el usuario que ejecuta Uvicorn. Cada
llamada a `/scan` crea un worker con `--rm`, `--network none`, 256 MiB de RAM,
un CPU, 64 procesos, sistema de archivos raíz de solo lectura, sin capacidades
Linux, perfil seccomp predeterminado de Docker y usuario no privilegiado. Los
datos viajan por stdin; no se monta ningún directorio del host. El worker tiene
hasta 45 segundos y su salida está limitada.

`POST /scan` recibe el archivo como multipart (`file`) y conserva una respuesta
JSON completa con `filename`, `size_bytes`, `sha256`, `file`, `analysis`,
`findings`, `assessment`, `security_summary`, `user_summary`, `virustotal` y
`disclaimer`.

Para usar otra imagen, define `BOOKSAFE_WORKER_IMAGE` al iniciar la API. El
acceso del servicio web al daemon Docker debe protegerse como una capacidad
privilegiada del host; el aislamiento del contenedor de análisis no elimina ese
riesgo operativo.

Abre:

http://127.0.0.1:8000

API interactiva:

http://127.0.0.1:8000/docs

## Tests

```bash
pytest
```

## Próximos pasos

1. ClamAV.
2. YARA.
3. Extracción de URLs/IOCs.
4. Mejor análisis PDF.
5. Reporte para usuario no técnico.
6. Sandbox dinámico posteriormente.

El límite actual de subida es de 50 MiB. Para EPUB se rechazan análisis que
superen 10.000 entradas, 10 MiB por entrada o 100 MiB descomprimidos.

## Alcance de seguridad

BookSafe realiza triaje estático en un worker aislado: inspecciona estructura,
metadatos, acciones PDF, scripts, URLs, archivos embebidos, rutas anómalas,
cifrado y entropía.
Los hallazgos son indicadores, no una confirmación de malware. Para decidir si
abrir un archivo no confiable, hay que combinar este resultado con un antivirus,
un sandbox y/o un servicio de reputación de hashes. El analizador no ejecuta el
contenido ni consulta servicios externos.

## VirusTotal

Por defecto, BookSafe genera un enlace de consulta por SHA-256. Esto no sube
el documento y permite abrir el resultado manualmente en VirusTotal. Para mostrar desde BookSafe el número de detecciones de un hash ya conocido,
crea el archivo `.env` en la raíz del proyecto, al mismo nivel que
`requirements.txt`, y agrega:

```env
VIRUSTOTAL_API_KEY=tu_clave_real
```

`.env` está excluido por `.gitignore` y no debe subirse al repositorio.
Restringe además sus permisos en Linux/macOS:

```bash
chmod 600 .env
```

La clave también puede proporcionarse mediante la variable de entorno
`VIRUSTOTAL_API_KEY`, que tiene prioridad sobre `.env`. La integración solo
consulta `GET /api/v3/files/{sha256}`; nunca envía el contenido del archivo.
