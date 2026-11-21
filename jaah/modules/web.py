"""[6] Enumeración de páginas web: headers, robots.txt, whatweb y fuzzing de rutas.

Nota: las máquinas de HTB/THM casi siempre usan certificados HTTPS
autofirmados. Si se verificara el certificado como hace Python por defecto,
TODA petición HTTPS fallaría en silencio. Por eso este módulo usa un
contexto SSL que no valida el certificado — aceptable aquí porque el
objetivo ya está autorizado y es tuyo (nunca uses esto contra un target
que no controles)."""
import re
import shutil
import ssl
import urllib.request
import urllib.error
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..core import C, run, ask, print_status, exportar_json

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

WORDLIST_FALLBACK = [
    "admin", "administrator", "login", "wp-admin", "phpmyadmin", "backup",
    ".git", ".env", "config", "api", "uploads", "images", "assets", "test",
    "dev", "robots.txt", "sitemap.xml", ".well-known", "server-status",
    "console", "manager", "index.php", "readme.md", ".htaccess", "upload",
    "files", "data", "tmp", "old", "static",
]
WORDLISTS_SISTEMA = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
]


def _hosts_web(ctx) -> list:
    objetivos = []
    for ip, puertos in ctx.hosts_puertos.items():
        for p, esquema in (("80", "http"), ("8080", "http"), ("443", "https"), ("8443", "https")):
            if p in puertos:
                objetivos.append((ip, p, esquema))
    return objetivos


def _fuzz_directorios(ctx, url: str) -> list:
    encontrados = []
    if shutil.which("gobuster"):
        wordlist = next((w for w in WORDLISTS_SISTEMA if Path(w).exists()), None)
        if wordlist:
            # -k desactiva la verificación TLS (certificados autofirmados de HTB/THM).
            # Sin --no-error: ese flag no existe en todas las versiones de gobuster
            # y, si falla, deja la enumeración sin resultados sin avisar.
            out = run(["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "-t", "20", "-k"],
                      ctx=ctx, timeout=300)
            if out:
                for line in out.splitlines():
                    m = re.match(r"^(/\S+)\s+\(Status:\s*(\d+)\)", line)
                    if m:
                        encontrados.append({"ruta": m.group(1), "status": int(m.group(2))})
                if encontrados:
                    return encontrados
            # gobuster puede devolver vacío si detecta una respuesta "comodín"
            # (el servidor responde 200 a CUALQUIER ruta, típico de routers/portales
            # cautivos) y aborta por seguridad. En ese caso usamos el fallback propio.
            print_status("gobuster no devolvió resultados (puede haber detectado una "
                          "respuesta comodín). Probando con wordlist mínima de respaldo.", "warning")
    for path in WORDLIST_FALLBACK:
        full_url = url.rstrip("/") + "/" + path
        try:
            req = urllib.request.Request(full_url, method="GET",
                                          headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=4, context=_SSL_CTX) as resp:
                encontrados.append({"ruta": "/" + path, "status": resp.status})
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 401, 403):
                encontrados.append({"ruta": "/" + path, "status": e.code})
        except Exception:
            continue

    # Si TODAS las rutas probadas devolvieron el mismo status (normalmente 200),
    # el servidor probablemente responde igual sin importar la ruta (wildcard /
    # router / captive portal): avisamos para que no se interprete como hallazgos reales.
    if len(encontrados) == len(WORDLIST_FALLBACK) and len({e["status"] for e in encontrados}) == 1:
        print_status(f"{url} respondió el mismo status a TODAS las rutas probadas: "
                      "probablemente es una página comodín (router/portal cautivo), "
                      "no una fuga real de directorios.", "warning")

    return encontrados


def _analizar_host_web(ctx, ip, puerto, esquema):
    """Se ejecuta en un hilo. Devuelve (url, info)."""
    url = f"{esquema}://{ip}:{puerto}"
    info = {"headers": {}, "titulo": "", "robots": "", "rutas_encontradas": []}

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=6, context=_SSL_CTX) as resp:
            body = resp.read(20000).decode("utf-8", errors="ignore")
            info["headers"] = dict(resp.headers.items())
            m_title = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
            if m_title:
                info["titulo"] = m_title.group(1).strip()[:200]
    except urllib.error.HTTPError as e:
        # El servidor SÍ respondió (403, 401, 500...); no es un fallo de conexión.
        # Seguimos con robots.txt/whatweb/fuzzing en vez de abortar todo el host.
        info["headers"] = dict(e.headers.items()) if e.headers else {}
        info["titulo"] = f"(HTTP {e.code} en la raíz)"
        try:
            body = e.read(20000).decode("utf-8", errors="ignore")
            m_title = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
            if m_title:
                info["titulo"] = m_title.group(1).strip()[:200]
        except Exception:
            pass
    except Exception as e:
        # Esto sí es un fallo real de conexión: host caído, timeout, DNS, etc.
        info["error"] = str(e)
        return url, info

    try:
        with urllib.request.urlopen(url.rstrip("/") + "/robots.txt", timeout=4, context=_SSL_CTX) as r:
            info["robots"] = r.read(2000).decode("utf-8", errors="ignore")
    except Exception:
        pass

    if shutil.which("whatweb"):
        info["whatweb"] = (run(["whatweb", "--no-errors", url], ctx=ctx, timeout=60) or "").strip()

    info["rutas_encontradas"] = _fuzz_directorios(ctx, url)
    return url, info


def enumerar_web(ctx):
    print(f"\n{C.HEADER}=== [6] Enumeración de Páginas Web ==={C.RESET}")
    objetivos = _hosts_web(ctx)
    if not objetivos:
        manual = ask("No se detectó HTTP/S en [1]. ¿IP:puerto a revisar manualmente? (vacío = omitir)", "")
        if not manual:
            print_status("Ejecuta [1] primero o indica un objetivo manual.", "warning"); return
        ip, _, puerto = manual.partition(":")
        objetivos = [(ip, puerto or "80", "https" if puerto == "443" else "http")]

    ctx.resultados["web"] = {}
    with ThreadPoolExecutor(max_workers=min(ctx.max_threads, len(objetivos))) as executor:
        futuros = {executor.submit(_analizar_host_web, ctx, ip, puerto, esquema): (ip, puerto)
                   for ip, puerto, esquema in objetivos}
        for futuro in as_completed(futuros):
            url, info = futuro.result()
            ctx.resultados["web"][url] = info
            if "error" in info:
                print_status(f"No se pudo conectar a {url}: {info['error']}", "warning")
                continue
            server = info["headers"].get("Server", "N/A")
            print(f"  {C.CYAN}{url}{C.RESET} | Server: {C.YELLOW}{server}{C.RESET} | "
                  f"Título: {info['titulo'][:60]!r} | Rutas encontradas: {len(info['rutas_encontradas'])}")
            for ruta in info["rutas_encontradas"][:10]:
                print(f"      -> {ruta['ruta']} ({ruta['status']})")

    exportar_json(ctx)
