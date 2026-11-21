"""[1] Enumeración de hosts: descubrimiento de puertos + OS vía nxc."""
import re
from ..core import (C, run, print_status, _get_nxc_base, _parse_nmap_grepable_hosts,
                     PUERTOS_RECON, PROBE_FLAGS, get_nxc_bin, exportar_json)


def descubrir_puertos(ctx) -> list:
    print(f"\n{C.HEADER}=== [1] Enumeración de Hosts ==={C.RESET}")
    ctx.hosts_puertos.clear(); ctx.smb_hosts.clear(); ctx.resultados["hosts"].clear()

    cmd = ["nmap", "-n", "-p", PUERTOS_RECON, "-T4", "--open"] + PROBE_FLAGS + ["-oG", "-", ctx.subnet]
    out = run(cmd, ctx=ctx, timeout=900)
    if out is None:
        print_status("El escaneo falló o hizo timeout.", "error")
        return []

    ctx.hosts_puertos = _parse_nmap_grepable_hosts(out)
    for ip, puertos in ctx.hosts_puertos.items():
        ctx.resultados["hosts"][ip] = {"puertos": puertos, "os": "Pendiente", "hostname": ""}
        servicios = []
        if "445" in puertos or "139" in puertos: servicios.append("SMB")
        if "80" in puertos or "443" in puertos or "8080" in puertos or "8443" in puertos: servicios.append("HTTP/S")
        if "22" in puertos: servicios.append("SSH")
        if "88" in puertos or "389" in puertos or "636" in puertos: servicios.append("AD/Kerberos")
        if "3389" in puertos: servicios.append("RDP")
        if "21" in puertos: servicios.append("FTP")
        print(f"  {C.CYAN}{ip.ljust(15)}{C.RESET} | Puertos: {','.join(puertos).ljust(30)} | "
              f"Servicios: {C.YELLOW}{', '.join(servicios) if servicios else 'Otros'}{C.RESET}")

    if not ctx.hosts_puertos:
        print_status("No se encontraron puertos abiertos.", "warning")

    ctx.smb_hosts = [ip for ip, pts in ctx.hosts_puertos.items() if "445" in pts or "139" in pts]
    if ctx.smb_hosts:
        print_status(f"{len(ctx.smb_hosts)} host(s) con SMB activo.", "success")
        detectar_os_nxc(ctx)

    exportar_json(ctx)
    return list(ctx.hosts_puertos.keys())


def detectar_os_nxc(ctx):
    if not ctx.smb_hosts or not get_nxc_bin():
        return
    print_status("Obteniendo OS y dominio (sin autenticación)...")
    salida = run(_get_nxc_base(ctx, ctx.smb_hosts, for_os=True), ctx=ctx)
    if not salida:
        return
    for line in salida.splitlines():
        if "[*]" not in line:
            continue
        match = re.search(r"SMB\s+([\d.]+)\s+445\s+(\S+)\s+\[\*\]\s+(.*)", line)
        if match:
            ip, hostname, details = match.groups()
            os_info = details.split(" (name:")[0].strip()
            domain = re.search(r"\(domain:(.*?)\)", details)
            if ip in ctx.resultados["hosts"]:
                ctx.resultados["hosts"][ip].update({
                    "os": os_info, "hostname": hostname,
                    "domain": domain.group(1) if domain else "N/A"
                })
