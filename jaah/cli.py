"""Punto de entrada: modo CLI (automatizable) y modo interactivo."""
import argparse
import os
import platform
import shutil
import sys

from .core import (C, Contexto, set_nxc_bin, print_status, ask_yes_no, ask_password,
                    validar_objetivo, exportar_json)
from .menu import BANNER, run_interactive
from .modules.hosts import descubrir_puertos
from .modules.smb import enumerar_usuarios, enumerar_grupos, enumerar_shares
from .modules.web import enumerar_web
from .modules.apps import enumerar_aplicaciones
from .modules.servicios import enumerar_servicios
from .modules.kerberos import enumerar_politica_passwords, asrep_roast, kerberoast
from .reporting import guardar_reporte

CTX = None


def _build_parser():
    parser = argparse.ArgumentParser(description="JAAH SECURY - CTF Recon Tool (Pro)")
    parser.add_argument("-t", "--target", help="Subred o IP")
    parser.add_argument("-u", "--user", default="", help="Usuario SMB")
    parser.add_argument("-p", "--password", default="",
                         help="Password SMB (INSEGURO en CLI: usa SMB_PASS).")
    parser.add_argument("--ad", action="store_true", help="Entorno con AD")
    parser.add_argument("--dc", help="IP del DC")
    parser.add_argument("--domain", default="", help="Nombre de dominio (ej: HTB.LOCAL)")
    parser.add_argument("-o", "--outdir", default="recon_output", help="Carpeta de resultados")
    parser.add_argument("--threads", type=int, default=8, help="Hilos en paralelo (1-32, def. 8)")
    parser.add_argument("--all", action="store_true", help="Flujo SMB completo (usuarios/grupos/shares)")
    parser.add_argument("--web", action="store_true", help="Incluir enumeración web")
    parser.add_argument("--apps", action="store_true", help="Incluir enumeración de aplicaciones")
    parser.add_argument("--services", action="store_true", help="Incluir enumeración de servicios")
    parser.add_argument("--kerberos", action="store_true",
                         help="Incluir política de contraseñas + AS-REP roasting + Kerberoasting")
    parser.add_argument("--report", action="store_true", help="Generar reporte Markdown al terminar")
    parser.add_argument("--yes", action="store_true", help="Saltar aviso legal")
    return parser


def main():
    global CTX
    parser = _build_parser()
    args = parser.parse_args()

    print(BANNER)

    if platform.system() != "Linux":
        print_status(
            "JAAH SECURY es solo para Linux (usa herramientas y rutas exclusivas de Linux: "
            "ip route, nmap -O, nxc, impacket, raw sockets de scapy). "
            "En Windows, ejecútalo dentro de WSL2 con una distro Linux.", "error")
        sys.exit(1)

    if not shutil.which("nmap"):
        print_status("Falta nmap. Instálalo primero.", "error"); sys.exit(1)

    nxc_bin = shutil.which("nxc") or shutil.which("netexec")
    set_nxc_bin(nxc_bin)
    if not nxc_bin:
        print_status("Falta nxc/netexec. Los módulos SMB/AD quedarán deshabilitados.", "warning")

    if args.target:
        try:
            validar_objetivo(args.target, args.dc, args.ad)
        except ValueError as e:
            parser.error(str(e))
        if args.password:
            print_status("Pasar la contraseña con -p la deja visible en `ps`. Usa SMB_PASS.", "warning")
        if args.user and not args.password:
            args.password = os.getenv("SMB_PASS", "") or ask_password("Password SMB")

    if not args.yes:
        print(f"{C.RED}{C.BOLD}[AVISO LEGAL]{C.RESET} Usa esta herramienta solo contra "
              f"objetivos autorizados (HTB, THM, tu propio lab o pentest con permiso).")
        if not ask_yes_no("¿Confirmas que tienes permiso para escanear este objetivo?"):
            sys.exit(0)

    CTX = Contexto()

    if args.target:
        CTX.configurar_cli(args)
        CTX.domain = args.domain

        descubrir_puertos(CTX)

        if args.all and CTX.smb_hosts:
            enumerar_usuarios(CTX); enumerar_grupos(CTX); enumerar_shares(CTX)

        if args.web:
            enumerar_web(CTX)
        if args.apps:
            enumerar_aplicaciones(CTX)
        if args.services:
            enumerar_servicios(CTX)

        if args.kerberos and args.ad:
            enumerar_politica_passwords(CTX)
            asrep_roast(CTX)
            if args.user and args.password:
                kerberoast(CTX)

        exportar_json(CTX)
        if args.report:
            guardar_reporte(CTX)
        sys.exit(0)

    # --- Modo interactivo ---
    run_interactive(CTX)


def entrypoint():
    global CTX
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.RED}[!] Interrumpido. Guardando datos...{C.RESET}")
        if CTX is not None and CTX.outdir.exists():
            exportar_json(CTX)
        sys.exit(130)
