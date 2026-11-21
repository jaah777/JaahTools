"""[7] Enumeración de aplicaciones: versiones (nmap -sV) + exploits (searchsploit)."""
import re
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..core import C, run, print_status, exportar_json


def _analizar_host_apps(ctx, ip, puertos, tiene_searchsploit):
    """Se ejecuta en un hilo. Devuelve (ip, lista_apps)."""
    puertos_csv = ",".join(puertos)
    out = run(["nmap", "-n", "-sV", "-p", puertos_csv, "--version-intensity", "5", ip],
              ctx=ctx, timeout=300) or ""
    apps = []
    for line in out.splitlines():
        m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s+(.*)$", line.strip())
        if m:
            puerto, servicio, version = m.groups()
            entrada = {"puerto": puerto, "servicio": servicio, "version": version.strip(), "exploits": []}
            if tiene_searchsploit and version.strip():
                sx = run(["searchsploit", version.strip()], ctx=ctx, timeout=30) or ""
                for sline in sx.splitlines():
                    if "|" in sline and "Exploit Title" not in sline and "---" not in sline:
                        titulo = sline.split("|")[0].strip()
                        if titulo:
                            entrada["exploits"].append(titulo)
            apps.append(entrada)
    return ip, apps


def enumerar_aplicaciones(ctx):
    print(f"\n{C.HEADER}=== [7] Enumeración de Aplicaciones ==={C.RESET}")
    if not ctx.hosts_puertos:
        print_status("Ejecuta [1] primero.", "warning"); return

    ctx.resultados["aplicaciones"] = {}
    tiene_searchsploit = shutil.which("searchsploit") is not None
    if not tiene_searchsploit:
        print_status("searchsploit no está instalado: solo se detectarán versiones, sin exploits.", "warning")

    items = list(ctx.hosts_puertos.items())
    with ThreadPoolExecutor(max_workers=min(ctx.max_threads, len(items))) as executor:
        futuros = {executor.submit(_analizar_host_apps, ctx, ip, puertos, tiene_searchsploit): ip
                   for ip, puertos in items}
        for futuro in as_completed(futuros):
            ip, apps = futuro.result()
            ctx.resultados["aplicaciones"][ip] = apps
            for a in apps:
                marca = f" | {len(a['exploits'])} exploit(s)" if a["exploits"] else ""
                print(f"  {C.CYAN}{ip}:{a['puerto']}{C.RESET} {a['servicio']} "
                      f"{C.YELLOW}{a['version']}{C.RESET}{marca}")

    exportar_json(ctx)
