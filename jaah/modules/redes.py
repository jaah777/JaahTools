"""[2] Enumeración de redes: mapeo de subredes activas, con escaneo en paralelo."""
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..core import (C, run, ask, ask_yes_no, print_status, _parse_nmap_grepable_hosts,
                     PUERTOS_RECON, PROBE_FLAGS, exportar_json)


def _escanear_bloque(ctx, bloque):
    """Se ejecuta en un hilo. Devuelve (bloque, dict_ip_puertos, ok)."""
    cmd = ["nmap", "-n", "-p", PUERTOS_RECON, "--open", "-T4", "--max-retries", "1"] \
          + PROBE_FLAGS + ["-oG", "-", str(bloque)]
    out = run(cmd, ctx=ctx, timeout=600)
    if out is None:
        return bloque, {}, False
    return bloque, _parse_nmap_grepable_hosts(out), True


def mapear_subredes(ctx):
    print(f"\n{C.HEADER}=== [2] Enumeración de Redes ==={C.RESET}")
    rutas = run(["ip", "-4", "route"], ctx=ctx)
    if not rutas:
        print_status("No se pudo leer la tabla de rutas (¿falta el paquete iproute2?).", "warning")
    else:
        print(f"{C.CYAN}{rutas.strip()}{C.RESET}")

    target = ask("Red grande a mapear (ej: 10.0.0.0/16)", ctx.subnet)
    try:
        red = ipaddress.ip_network(target, strict=False)
    except ValueError:
        print_status("CIDR inválido.", "error"); return

    if red.num_addresses > 65536:
        print_status(f"{target} tiene {red.num_addresses} direcciones. Limita a /16 o menor.", "error")
        return
    if not ask_yes_no(f"¿Escanear {target}? ({red.num_addresses} direcciones, "
                       f"hasta {ctx.max_threads} bloques en paralelo)"):
        return

    while True:
        try:
            cidr_agrupacion = int(ask("Tamaño de subred para agrupar (8-30)", "24"))
            if 8 <= cidr_agrupacion <= 30:
                break
            print_status("Valor fuera de rango (8-30).", "error")
        except ValueError:
            print_status("Valor inválido.", "error")

    bloques = [red] if red.prefixlen >= 24 else list(red.subnets(new_prefix=24))
    subredes = {}
    bloques_fallidos = []
    completados = 0

    with ThreadPoolExecutor(max_workers=ctx.max_threads) as executor:
        futuros = {executor.submit(_escanear_bloque, ctx, b): b for b in bloques}
        for futuro in as_completed(futuros):
            bloque, hosts_encontrados, ok = futuro.result()
            completados += 1
            print_status(f"[{completados}/{len(bloques)}] {bloque} -> {len(hosts_encontrados)} host(s)", "info")
            if not ok:
                bloques_fallidos.append(str(bloque)); continue
            for ip in hosts_encontrados:
                sub = str(ipaddress.ip_network(f"{ip}/{cidr_agrupacion}", strict=False))
                subredes.setdefault(sub, []).append(ip)

    if bloques_fallidos:
        print_status(f"{len(bloques_fallidos)} bloque(s) fallaron: {', '.join(bloques_fallidos)}", "warning")
    if not subredes:
        print_status("No se encontraron subredes activas.", "warning"); return

    print_status(f"¡{len(subredes)} subredes activas!", "success")
    opciones = []
    for i, (sub, ips) in enumerate(sorted(subredes.items())):
        print(f"  {C.CYAN}[{i+1}]{C.RESET} {sub.ljust(18)} | {C.YELLOW}{len(ips)} hosts{C.RESET}")
        opciones.append((sub, ips))

    ctx.resultados["subredes_activas"] = subredes
    exportar_json(ctx)

    seleccion = ask("\n¿Establecer alguna como objetivo principal? (0 omitir)", "0")
    try:
        idx = int(seleccion) - 1
        if 0 <= idx < len(opciones):
            ctx.subnet = opciones[idx][0]
            ctx.limpiar_datos_objetivo()
            ctx._guardar_meta()
            print_status(f"Objetivo: {ctx.subnet}. Datos previos limpiados.", "success")
    except ValueError:
        pass
