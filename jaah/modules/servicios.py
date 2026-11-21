"""[8] Enumeración de servicios: scripts por defecto de nmap + banner grabbing manual."""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..core import C, run, print_status, exportar_json


def _banner_grab(ip: str, puerto: str, timeout=4) -> str:
    try:
        with socket.create_connection((ip, int(puerto)), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                return s.recv(256).decode("utf-8", errors="ignore").strip()
            except socket.timeout:
                return ""
    except Exception:
        return ""


def _analizar_host_servicios(ctx, ip, puertos):
    """Se ejecuta en un hilo. Devuelve (ip, dict_resultado)."""
    puertos_csv = ",".join(puertos)
    out = run(["nmap", "-n", "-sC", "-sV", "-p", puertos_csv, ip], ctx=ctx, timeout=400) or ""
    banners = {}
    for p in puertos:
        b = _banner_grab(ip, p)
        if b:
            banners[p] = b[:200]
    return ip, {"nmap_scripts": out[:8000], "banners": banners}


def enumerar_servicios(ctx):
    print(f"\n{C.HEADER}=== [8] Enumeración de Servicios ==={C.RESET}")
    if not ctx.hosts_puertos:
        print_status("Ejecuta [1] primero.", "warning"); return

    ctx.resultados["servicios"] = {}
    items = list(ctx.hosts_puertos.items())
    with ThreadPoolExecutor(max_workers=min(ctx.max_threads, len(items))) as executor:
        futuros = {executor.submit(_analizar_host_servicios, ctx, ip, puertos): ip
                   for ip, puertos in items}
        for futuro in as_completed(futuros):
            ip, resultado = futuro.result()
            ctx.resultados["servicios"][ip] = resultado
            print(f"  {C.CYAN}{ip}{C.RESET}: scripts nmap ejecutados, "
                  f"{len(resultado['banners'])} banner(s) capturados.")
            for p, b in resultado["banners"].items():
                print(f"      {p}/tcp -> {b!r}")

    exportar_json(ctx)
