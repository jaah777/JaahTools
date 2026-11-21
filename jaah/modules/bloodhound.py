"""Integración con BloodHound vía nxc ldap."""
from pathlib import Path
from ..core import C, run, ask, print_status, get_nxc_bin


def lanzar_bloodhound(ctx):
    print(f"\n{C.HEADER}=== BloodHound ==={C.RESET}")
    if not get_nxc_bin():
        print_status("nxc/netexec no está instalado.", "error"); return
    if not ctx.has_ad or not ctx.username or not ctx.dc_ip:
        print_status("BloodHound requiere AD, DC y credenciales.", "error"); return

    logs_dir = Path.home() / ".nxc" / "logs"
    zips_antes = set(logs_dir.rglob("*.zip")) if logs_dir.exists() else set()

    domain = ctx.detectar_dominio() or ask("Nombre del dominio (ej: HTB.LOCAL)", "")
    cmd = [get_nxc_bin(), "ldap", ctx.dc_ip, "-u", ctx.username, "-p", ctx.password,
           "--bloodhound", "--collection", "All", "--dns-server", ctx.dc_ip]
    if domain:
        cmd += ["-d", domain]

    run(cmd, ctx=ctx, timeout=900)
    nuevos_zips = (set(logs_dir.rglob("*.zip")) if logs_dir.exists() else set()) - zips_antes

    if nuevos_zips:
        print_status("¡Éxito! Archivos generados:", "success")
        for z in nuevos_zips:
            print(f"    {C.CYAN}{z}{C.RESET}")
    else:
        print_status("No se generaron nuevos .zip. Revisa raw/.", "warning")
