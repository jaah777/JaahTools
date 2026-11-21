"""Menú interactivo: conecta la entrada del usuario con los módulos."""
from .core import C, ask, print_status, exportar_json
from .modules.hosts import descubrir_puertos
from .modules.redes import mapear_subredes
from .modules.smb import enumerar_usuarios, enumerar_grupos, enumerar_shares
from .modules.web import enumerar_web
from .modules.apps import enumerar_aplicaciones
from .modules.servicios import enumerar_servicios
from .modules.paquetes import elaborar_paquetes
from .modules.kerberos import enumerar_politica_passwords, asrep_roast, kerberoast
from .modules.bloodhound import lanzar_bloodhound
from .reporting import guardar_reporte

BANNER = f"""{C.CYAN}{C.BOLD}
     ██╗ █████╗  █████╗ ██╗  ██╗    ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗   ██╗
     ██║██╔══██╗██╔══██╗██║  ██║    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗╚██╗ ██╔╝
     ██║███████║███████║███████║    ███████╗█████╗  ██║     ██║   ██║██████╔╝ ╚████╔╝
██   ██║██╔══██║██╔══██║██╔══██║    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗  ╚██╔╝
╚█████╔╝██║  ██║██║  ██║██║  ██║    ███████║███████╗╚██████╗╚██████╔╝██║  ██║   ██║
 ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
{C.RESET}
{C.GREEN}       CTF Recon Tool Pro - JAAH SECURY{C.RESET}
"""

MENU = f"""
{C.YELLOW}Selecciona qué acción quieres realizar:{C.RESET}

  {C.CYAN}[1]{C.RESET}  Enumeración de hosts
  {C.CYAN}[2]{C.RESET}  Enumeración de redes (subredes activas)
  {C.CYAN}[3]{C.RESET}  Enumeración de usuarios (SMB/AD)
  {C.CYAN}[4]{C.RESET}  Enumeración de grupos (SMB/AD)
  {C.CYAN}[5]{C.RESET}  Enumeración de recursos compartidos (shares)
  {C.CYAN}[6]{C.RESET}  Enumeración de páginas web
  {C.CYAN}[7]{C.RESET}  Enumeración de aplicaciones (versiones + exploits)
  {C.CYAN}[8]{C.RESET}  Enumeración de servicios (banners + scripts nmap)
  {C.CYAN}[9]{C.RESET}  Elaboración de paquetes (scapy)
  {C.CYAN}[10]{C.RESET} Política de contraseñas (AD)
  {C.CYAN}[11]{C.RESET} AS-REP Roasting
  {C.CYAN}[12]{C.RESET} Kerberoasting
  {C.CYAN}[13]{C.RESET} Flujo SMB completo (3 -> 5)
  {C.CYAN}[14]{C.RESET} Lanzar BloodHound
  {C.CYAN}[15]{C.RESET} Generar reporte Markdown
  {C.CYAN}[0]{C.RESET}  Salir
"""


def run_interactive(ctx):
    ctx.pedir_datos_basicos()
    while True:
        print(MENU)
        opcion = ask("Opción", "0")
        if opcion == "1": descubrir_puertos(ctx)
        elif opcion == "2": mapear_subredes(ctx)
        elif opcion == "3": enumerar_usuarios(ctx); exportar_json(ctx)
        elif opcion == "4": enumerar_grupos(ctx); exportar_json(ctx)
        elif opcion == "5": enumerar_shares(ctx); exportar_json(ctx)
        elif opcion == "6": enumerar_web(ctx)
        elif opcion == "7": enumerar_aplicaciones(ctx)
        elif opcion == "8": enumerar_servicios(ctx)
        elif opcion == "9": elaborar_paquetes(ctx)
        elif opcion == "10": enumerar_politica_passwords(ctx)
        elif opcion == "11": asrep_roast(ctx)
        elif opcion == "12": kerberoast(ctx)
        elif opcion == "13":
            if ctx.smb_hosts:
                enumerar_usuarios(ctx); enumerar_grupos(ctx); enumerar_shares(ctx)
                exportar_json(ctx)
            else:
                print_status("Ejecuta [1] primero.", "warning")
        elif opcion == "14": lanzar_bloodhound(ctx)
        elif opcion == "15": guardar_reporte(ctx)
        elif opcion == "0":
            print_status("Saliendo... ¡Buena cacería!", "success"); break
        else:
            print_status("Opción inválida.", "error")
