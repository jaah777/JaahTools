#!/usr/bin/env python3
"""
smb_recon_menu.py
------------------
Herramienta de reconocimiento SMB/AD con menú interactivo, pensada para
laboratorios AUTORIZADOS (Hack The Box, TryHackMe, tu propio lab, etc.).

Funciones:
  1. Enumeración de hosts
  2. Enumeración de usuarios
  3. Enumeración de grupos (roles de autorización)
  4. Enumeración de recursos compartidos (shares) SMB
  5. Ejecutar todo el flujo completo

IMPORTANTE:
  Usa esto solo contra redes/objetivos para los que tengas autorización explícita.
"""

import re
import shutil
import subprocess
import sys
import getpass
import ipaddress
import logging
from pathlib import Path

# ---------- Configuración de colores (ANSI) ----------
class C:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# Banner actualizado a "Jaah Secury"
BANNER = f"""{C.CYAN}{C.BOLD}
     ██╗ █████╗  █████╗ ██╗  ██╗    ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗   ██╗
     ██║██╔══██╗██╔══██╗██║  ██║    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗╚██╗ ██╔╝
     ██║███████║███████║███████║    ███████╗█████╗  ██║     ██║   ██║██████╔╝ ╚████╔╝ 
██   ██║██╔══██║██╔══██║██╔══██║    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗  ╚██╔╝  
╚█████╔╝██║  ██║██║  ██║██║  ██║    ███████║███████╗╚██████╗╚██████╔╝██║  ██║   ██║   
 ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
{C.RESET}
{C.GREEN}       SMB / AD Recon Tool - Mente Intelectual{C.RESET}
"""

MENU = f"""
{C.YELLOW}Selecciona qué acción quieres realizar:{C.RESET}

  {C.CYAN}[1]{C.RESET} Enumeración de hosts
  {C.CYAN}[2]{C.RESET} Enumeración de usuarios
  {C.CYAN}[3]{C.RESET} Enumeración de grupos (roles de autorización)
  {C.CYAN}[4]{C.RESET} Enumeración de recursos compartidos SMB (shares)
  {C.CYAN}[5]{C.RESET} Ejecutar flujo completo (1 -> 4)
  {C.CYAN}[0]{C.RESET} Salir
"""

# ---------- Utilidades ----------

def setup_logging(outdir: Path):
    log_file = outdir / "session.log"
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console = logging.StreamHandler()
    console.setLevel(logging.WARNING)
    logging.getLogger('').addHandler(console)

def check_tool(name: str) -> bool:
    return shutil.which(name) is not None

def run(cmd: list, timeout: int = 600) -> str:
    cmd_str = ' '.join(cmd)
    safe_cmd = re.sub(r'-p\s+\S+', '-p ********', cmd_str)
    logging.info(f"Ejecutando: {safe_cmd}")
    print(f"{C.BLUE}[>] {safe_cmd}{C.RESET}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0 and result.stderr.strip():
            logging.warning(f"Error en comando: {result.stderr.strip()[:200]}")
        return result.stdout
    except subprocess.TimeoutExpired:
        msg = f"Timeout ejecutando: {safe_cmd}"
        logging.error(msg)
        print(f"{C.RED}[!] {msg}{C.RESET}")
        return ""
    except FileNotFoundError:
        msg = f"Herramienta no encontrada: {cmd[0]}"
        logging.error(msg)
        print(f"{C.RED}[!] {msg}{C.RESET}")
        return ""

def ask(prompt: str, default: str = "") -> str:
    suffix = f" {C.CYAN}[{default}]{C.RESET}" if default else ""
    val = input(f"{C.GREEN}?{C.RESET} {prompt}{suffix}: ").strip()
    return val or default

def ask_yes_no(prompt: str) -> bool:
    val = input(f"{C.GREEN}?{C.RESET} {prompt} {C.CYAN}(s/n){C.RESET}: ").strip().lower()
    return val.startswith("s")

def ask_password(prompt: str) -> str:
    return getpass.getpass(f"{C.GREEN}?{C.RESET} {prompt}: ")

def print_status(msg: str, level="info"):
    if level == "info":
        print(f"{C.CYAN}[*]{C.RESET} {msg}")
    elif level == "success":
        print(f"{C.GREEN}[+]{C.RESET} {msg}")
    elif level == "warning":
        print(f"{C.YELLOW}[!]{C.RESET} {msg}")
    elif level == "error":
        print(f"{C.RED}[-]{C.RESET} {msg}")

# ---------- Contexto de la sesión ----------

class Contexto:
    def __init__(self):
        self.subnet = ""
        self.username = ""
        self.password = ""
        self.has_ad = False
        self.dc_ip = ""
        self.outdir = Path("recon_output")
        self.smb_hosts = []

    def pedir_datos_basicos(self):
        print(f"\n{C.HEADER}=== Configuración de la Sesión ==={C.RESET}")
        
        while True:
            self.subnet = ask("Subred o IP objetivo (ej: 10.10.11.0/24)")
            try:
                ipaddress.ip_network(self.subnet, strict=False)
                break
            except ValueError:
                print_status("Formato de subred inválido. Intenta de nuevo.", "error")

        self.username = ask("Usuario SMB (dejar vacío = sesión anónima)", "")
        if self.username:
            self.password = ask_password("Password SMB")
        
        self.has_ad = ask_yes_no("¿El entorno tiene Active Directory?")
        if self.has_ad:
            while True:
                self.dc_ip = ask("IP del controlador de dominio (DC)")
                try:
                    ipaddress.ip_address(self.dc_ip)
                    break
                except ValueError:
                    print_status("IP del DC inválida. Intenta de nuevo.", "error")
        
        outdir_in = ask("Carpeta de resultados", "recon_output")
        self.outdir = Path(outdir_in).expanduser().resolve()
        self.outdir.mkdir(parents=True, exist_ok=True)
        setup_logging(self.outdir)
        print_status(f"Resultados se guardarán en: {self.outdir}", "success")

# ---------- Funciones de enumeración ----------

def enumerar_hosts(ctx: Contexto) -> list:
    print(f"\n{C.HEADER}=== Enumeración de hosts ==={C.RESET}")
    print_status("Escaneando red con nmap... (esto puede tomar unos minutos)")
    
    output = run(["nmap", "-sn", ctx.subnet], timeout=300)
    hosts = sorted(set(re.findall(r"Nmap scan report for \(?([\d.]+)\)?", output)))

    (ctx.outdir / "hosts.txt").write_text("\n".join(hosts) + ("\n" if hosts else ""))
    print_status(f"{len(hosts)} host(s) vivos encontrados.", "success")

    if not hosts:
        return []

    print_status("Filtrando hosts con SMB abierto (139/445)...")
    smb_hosts = []
    for h in hosts:
        out = run(["nmap", "-p", "139,445", "--open", "-oG", "-", h], timeout=120)
        if re.search(r"\b(139|445)/open/tcp//", out):
            smb_hosts.append(h)

    (ctx.outdir / "smb_hosts.txt").write_text("\n".join(smb_hosts) + ("\n" if smb_hosts else ""))
    print_status(f"{len(smb_hosts)} host(s) con SMB abierto.", "success")
    ctx.smb_hosts = smb_hosts
    return smb_hosts

def _get_nxc_base(ctx: Contexto, targets: list) -> list:
    cmd = ["nxc", "smb"] + targets
    if ctx.username:
        cmd += ["-u", ctx.username, "-p", ctx.password]
    else:
        cmd += ["-u", "", "-p", ""]
    
    if not ctx.has_ad:
        cmd.append("--local-auth")
    return cmd

def enumerar_usuarios(ctx: Contexto):
    print(f"\n{C.HEADER}=== Enumeración de usuarios ==={C.RESET}")
    if not ctx.smb_hosts:
        print_status("No hay hosts SMB cargados. Ejecuta primero la opción [1].", "warning")
        return
    if not check_tool("nxc"):
        print_status("NetExec (nxc) no está instalado. Omitiendo.", "error")
        return

    targets = [ctx.dc_ip] if ctx.has_ad and ctx.dc_ip else ctx.smb_hosts
    base_cmd = _get_nxc_base(ctx, targets)
    
    print_status("Consultando usuarios vía SMB...")
    salida = run(base_cmd + ["--users"])
    (ctx.outdir / "usuarios_raw.txt").write_text(salida)

    if ctx.has_ad and ctx.dc_ip:
        print_status("Entorno AD detectado: ejecutando RID cycling en el DC...")
        rid_out = run(_get_nxc_base(ctx, [ctx.dc_ip]) + ["--rid-brute"])
        (ctx.outdir / "rid_brute.txt").write_text(rid_out)
        salida += "\n" + rid_out
    else:
        print_status("Entorno sin AD: buscando usuarios locales con enum4linux-ng...")
        if check_tool("enum4linux-ng"):
            for h in targets:
                out = run(["enum4linux-ng", "-U", h], timeout=300)
                (ctx.outdir / f"usuarios_{h.replace('.', '_')}.txt").write_text(out)
                salida += "\n" + out
        else:
            print_status("enum4linux-ng no está instalado. Omitiendo.", "warning")

    usuarios = set()
    for patron in [r"(?:user:|Username:)\s*([A-Za-z0-9._\-\\$]+)", r"SidTypeUser\)\s*([A-Za-z0-9._\-$]+)"]:
        for match in re.findall(patron, salida):
            user = match.split('\\')[-1]
            if user.lower() not in ("guest", "krbtgt") and not user.endswith('$'):
                usuarios.add(user)

    if usuarios:
        (ctx.outdir / "usuarios.txt").write_text("\n".join(sorted(usuarios)) + "\n")
        print_status(f"{len(usuarios)} usuario(s) consolidados únicos encontrados.", "success")
    else:
        print_status("No se encontraron usuarios.", "warning")

def enumerar_grupos(ctx: Contexto):
    print(f"\n{C.HEADER}=== Enumeración de grupos (roles de autorización) ==={C.RESET}")
    if not ctx.smb_hosts:
        print_status("No hay hosts SMB cargados. Ejecuta primero la opción [1].", "warning")
        return
    if not check_tool("nxc"):
        print_status("NetExec (nxc) no está instalado. Omitiendo.", "error")
        return

    targets = [ctx.dc_ip] if ctx.has_ad and ctx.dc_ip else ctx.smb_hosts
    base_cmd = _get_nxc_base(ctx, targets)
    
    print_status("Consultando grupos vía SMB...")
    salida = run(base_cmd + ["--groups"])
    (ctx.outdir / "grupos_raw.txt").write_text(salida)

    if ctx.has_ad and ctx.dc_ip:
        print_status("Priorizando grupos de dominio con privilegios...")
        privilegiados = ["Domain Admins", "Enterprise Admins", "Administrators",
                         "Backup Operators", "Account Operators", "Schema Admins"]
    else:
        print_status("Priorizando grupos locales con privilegios...")
        privilegiados = ["Administrators", "Remote Desktop Users", "Power Users", "Backup Operators"]

    encontrados = [g for g in privilegiados if g.lower() in salida.lower()]

    reporte = ctx.outdir / "grupos_roles.txt"
    with reporte.open("w") as f:
        f.write("=== Grupos detectados (salida cruda) ===\n")
        f.write(salida + "\n\n")
        f.write("=== Grupos de interés para roles de autorización ===\n")
        if encontrados:
            for g in encontrados:
                f.write(f"- {g}\n")
        else:
            f.write("No se detectaron coincidencias con la lista de grupos privilegiados conocidos.\n")

    if encontrados:
        print_status(f"¡Grupos privilegiados detectados! -> {', '.join(encontrados)}", "warning")
    else:
        print_status("No se detectaron grupos privilegiados obvios.", "info")
    print_status(f"Reporte guardado en: {reporte}", "success")

def enumerar_shares(ctx: Contexto):
    print(f"\n{C.HEADER}=== Enumeración de recursos compartidos SMB (shares) ==={C.RESET}")
    if not ctx.smb_hosts:
        print_status("No hay hosts SMB cargados. Ejecuta primero la opción [1].", "warning")
        return
    if not check_tool("nxc"):
        print_status("NetExec (nxc) no está instalado. Omitiendo.", "error")
        return

    print_status("Buscando shares accesibles de forma anónima...")
    anon_cmd = ["nxc", "smb"] + ctx.smb_hosts + ["-u", "", "-p", ""]
    if not ctx.has_ad:
        anon_cmd.append("--local-auth")
    anon_out = run(anon_cmd + ["--shares"])
    
    auth_out = ""
    if ctx.username:
        print_status("Buscando shares con las credenciales proporcionadas...")
        auth_cmd = ["nxc", "smb"] + ctx.smb_hosts + ["-u", ctx.username, "-p", ctx.password]
        if not ctx.has_ad:
            auth_cmd.append("--local-auth")
        auth_out = run(auth_cmd + ["--shares"])

    salida_total = "=== ANÓNIMO ===\n" + anon_out + "\n\n=== AUTENTICADO ===\n" + auth_out
    (ctx.outdir / "shares.txt").write_text(salida_total)
    print_status("Shares guardados.", "success")

    if check_tool("enum4linux-ng"):
        print_status("Complementando con enum4linux-ng (-S) por host...")
        for h in ctx.smb_hosts:
            out = run(["enum4linux-ng", "-S", h], timeout=300)
            (ctx.outdir / f"shares_{h.replace('.', '_')}.txt").write_text(out)

def resumen_final(ctx: Contexto):
    print(f"\n{C.HEADER}{'='*40}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}           RESUMEN DE LA SESIÓN{C.RESET}")
    print(f"{C.HEADER}{'='*40}{C.RESET}")
    
    if ctx.smb_hosts:
        print(f" Hosts SMB encontrados : {C.GREEN}{len(ctx.smb_hosts)}{C.RESET}")
    else:
        print(f" Hosts SMB encontrados : {C.RED}0{C.RESET}")

    archivos = ["usuarios.txt", "grupos_roles.txt", "shares.txt"]
    print(f"\n {C.BOLD}Archivos generados en {ctx.outdir}:{C.RESET}")
    for f in archivos:
        p = ctx.outdir / f
        if p.exists():
            size = p.stat().st_size
            print(f"  - {f.ljust(20)} ({size} bytes)")
        else:
            print(f"  - {f.ljust(20)} (No generado)")
    print(f"{C.HEADER}{'='*40}{C.RESET}\n")

# ---------- Menú principal ----------

def main():
    print(BANNER)

    required = ["nmap"]
    faltantes = [t for t in required if not check_tool(t)]
    if faltantes:
        print_status(f"Faltan herramientas obligatorias: {', '.join(faltantes)}", "error")
        sys.exit(1)
    
    if not check_tool("nxc"): print_status("NetExec (nxc) no encontrado. Las opciones 2, 3 y 4 fallarán.", "warning")
    if not check_tool("enum4linux-ng"): print_status("enum4linux-ng no encontrado. La enumeración será menos profunda.", "warning")

    ctx = Contexto()
    ctx.pedir_datos_basicos()

    while True:
        print(MENU)
        opcion = ask("Opción", "0")

        if opcion == "1":
            enumerar_hosts(ctx)
        elif opcion == "2":
            enumerar_usuarios(ctx)
        elif opcion == "3":
            enumerar_grupos(ctx)
        elif opcion == "4":
            enumerar_shares(ctx)
        elif opcion == "5":
            print_status("Iniciando flujo completo. Esto puede tardar bastante...", "info")
            if enumerar_hosts(ctx):
                enumerar_usuarios(ctx)
                enumerar_grupos(ctx)
                enumerar_shares(ctx)
                resumen_final(ctx)
            else:
                print_status("Flujo detenido: no se encontraron hosts vivos.", "error")
        elif opcion == "0":
            print_status("Saliendo... ¡Buena cacería!", "success")
            break
        else:
            print_status("Opción inválida. Intenta de nuevo.", "error")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.RED}[!] Interrumpido por el usuario. Saliendo de forma segura...{C.RESET}")
        sys.exit(130)