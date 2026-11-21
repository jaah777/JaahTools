"""
jaah.core
---------
Utilidades compartidas por todos los módulos: colores, ejecución segura de
comandos, logging, y el Contexto de sesión (thread-safe).
"""
import re
import shutil
import socket
import subprocess
import sys
import getpass
import ipaddress
import logging
import json
import time
import os
import threading
from pathlib import Path


class C:
    HEADER = '\033[95m'; BLUE = '\033[94m'; CYAN = '\033[96m'
    GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    RESET = '\033[0m'; BOLD = '\033[1m'


# Puertos de reconocimiento y sondas de descubrimiento (compartidos por hosts/redes)
PUERTOS_RECON = "21,22,53,80,88,135,139,389,443,445,464,636,1433,3306,3389,5985,8080,8443"
PROBE_FLAGS = ["-PE", "-PS21,22,80,135,139,443,445,3389"]

GRUPOS_PRIV_AD = ["Domain Admins", "Enterprise Admins", "Administrators", "Backup Operators"]
GRUPOS_PRIV_LOCAL = ["Administrators", "Remote Desktop Users"]

# Binario de NetExec, resuelto una vez al arrancar (ver cli.set_nxc_bin)
NXC_BIN = None


def set_nxc_bin(path):
    global NXC_BIN
    NXC_BIN = path


def get_nxc_bin():
    return NXC_BIN


def _find_tool(names):
    """Devuelve la ruta del primer binario que exista de una lista de alias."""
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


# ---------- Seguridad en la ejecución de comandos ----------

def mask_command(cmd: list) -> str:
    masked = []
    skip_next = False
    is_nxc = "nxc" in cmd[0] or "netexec" in cmd[0]
    for i, arg in enumerate(cmd):
        if skip_next:
            masked.append("********")
            skip_next = False
            continue
        if is_nxc and arg in ("-p", "--password") and i > 0:
            masked.append(arg)
            skip_next = True
        else:
            masked.append(arg)
    return ' '.join(masked)


def _secure_write(path: Path, content: str):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)


_raw_lock = threading.Lock()  # evita condiciones de carrera al crear raw_dir en paralelo


def _mask_password_in_text(text: str, password: str) -> str:
    """Enmascara la contraseña en una salida de comando.

    Con contraseñas de 4+ caracteres se reemplaza cualquier aparición: es
    agresivo pero seguro, porque es poco probable que una cadena así de
    larga aparezca por casualidad en la salida de nmap/nxc/impacket.
    Con contraseñas más cortas (ej. "a1", "123") un reemplazo global
    destrozaría evidencia legítima (podría coincidir con fragmentos de IPs,
    hashes, etc.), así que solo se enmascara cuando aparece justo después
    de un separador típico de credencial (':' o '-p ')."""
    if not password:
        return text
    if len(password) >= 4:
        return text.replace(password, "********")
    patron = re.compile(r"(:|-p\s+)" + re.escape(password) + r"\b")
    return patron.sub(r"\1********", text)


def run(cmd: list, ctx: 'Contexto' = None, timeout: int = 600):
    """Ejecuta un comando. Devuelve stdout (str) en éxito, o None si falló
    (timeout, binario ausente). Seguro para llamar desde varios hilos."""
    safe_cmd = mask_command(cmd)
    try:
        usuario_local = os.getlogin()
        safe_cmd_log = safe_cmd.replace(f"/home/{usuario_local}", "/home/[REDACTED]")
    except Exception:
        safe_cmd_log = safe_cmd

    logging.info(f"Ejecutando: {safe_cmd_log}")
    print(f"{C.BLUE}[>] {safe_cmd_log}{C.RESET}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        stdout, stderr = result.stdout, result.stderr

        if ctx and ctx.password:
            stdout = _mask_password_in_text(stdout, ctx.password)
            stderr = _mask_password_in_text(stderr, ctx.password)

        if ctx and ctx.outdir:
            with _raw_lock:
                raw_dir = ctx.outdir / "raw"
                raw_dir.mkdir(exist_ok=True, mode=0o700)
                os.chmod(raw_dir, 0o700)
            filepath = raw_dir / f"{time.time_ns()}_{cmd[0].split('/')[-1]}.txt"
            _secure_write(filepath, f"CMD: {safe_cmd_log}\n\nSTDOUT:\n{stdout}\n\nSTDERR:\n{stderr}")

        if result.returncode != 0 and stderr.strip():
            logging.warning(f"Error (code {result.returncode}): {stderr.strip()[:200]}")
        return stdout
    except subprocess.TimeoutExpired:
        print(f"{C.RED}[!] Timeout ejecutando: {safe_cmd_log}{C.RESET}")
        logging.error(f"Timeout: {safe_cmd_log}")
        return None
    except FileNotFoundError:
        print(f"{C.RED}[!] Herramienta no encontrada: {cmd[0]}{C.RESET}")
        return None


def _get_nxc_base(ctx: 'Contexto', targets: list, for_os=False) -> list:
    cmd = [NXC_BIN, "smb"] + targets
    if not for_os and ctx.username:
        cmd += ["-u", ctx.username, "-p", ctx.password]
    else:
        cmd += ["-u", "", "-p", ""]
    if not ctx.has_ad:
        cmd.append("--local-auth")
    return cmd


# ---------- Entrada de usuario ----------

def ask(prompt: str, default: str = "") -> str:
    suffix = f" {C.CYAN}[{default}]{C.RESET}" if default else ""
    val = input(f"{C.GREEN}?{C.RESET} {prompt}{suffix}: ").strip()
    return val or default


def ask_yes_no(prompt: str) -> bool:
    val = input(f"{C.GREEN}?{C.RESET} {prompt} {C.CYAN}(s/n){C.RESET}: ").strip().lower()
    return val.startswith("s") or val.startswith("y")


def ask_password(prompt: str) -> str:
    return getpass.getpass(f"{C.GREEN}?{C.RESET} {prompt}: ")


def print_status(msg: str, level="info"):
    if level == "info": print(f"{C.CYAN}[*]{C.RESET} {msg}")
    elif level == "success": print(f"{C.GREEN}[+]{C.RESET} {msg}")
    elif level == "warning": print(f"{C.YELLOW}[!]{C.RESET} {msg}")
    elif level == "error": print(f"{C.RED}[-]{C.RESET} {msg}")


def setup_logging(outdir: Path):
    log_file = outdir / "session.log"
    if not log_file.exists():
        _secure_write(log_file, "")
    os.chmod(log_file, 0o600)
    logging.basicConfig(filename=log_file, level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    console = logging.StreamHandler()
    console.setLevel(logging.WARNING)
    logging.getLogger('').addHandler(console)


def es_ip_o_red_valida(valor: str) -> bool:
    try:
        ipaddress.ip_network(valor, strict=False)
        return True
    except ValueError:
        return False


def es_host_resoluble(host: str) -> bool:
    """True si `host` es un nombre de dominio que resuelve a una IP.
    nmap acepta nombres de host de forma nativa, así que no hace falta
    convertirlo: solo confirmamos aquí que DNS lo resuelve, para dar un
    error claro antes de lanzar el escaneo en vez de que nmap falle después."""
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False


def validar_objetivo(subnet: str, dc_ip: str = "", has_ad: bool = False):
    if not es_ip_o_red_valida(subnet) and not es_host_resoluble(subnet):
        raise ValueError(f"'{subnet}' no es una IP/CIDR válida ni un nombre de host que se pueda resolver.")
    if has_ad and not dc_ip:
        raise ValueError("--dc es obligatorio cuando el entorno tiene AD.")
    if dc_ip and not es_ip_o_red_valida(dc_ip) and not es_host_resoluble(dc_ip):
        raise ValueError(f"'{dc_ip}' no es una IP válida ni un nombre de host que se pueda resolver.")


def _parse_nmap_grepable_hosts(out: str) -> dict:
    hosts = {}
    for line in out.splitlines():
        if "Ports:" not in line:
            continue
        m_ip = re.search(r"Host:\s+([\d.]+)", line)
        if not m_ip:
            continue
        ip = m_ip.group(1)
        m_ports = re.search(r"Ports:\s+(.*?)(?:\t|$)", line)
        if not m_ports:
            continue
        puertos = re.findall(r"(\d+)/open", m_ports.group(1))
        if puertos:
            hosts[ip] = puertos
    return hosts


# ---------- Contexto de sesión (thread-safe) ----------

class Contexto:
    def __init__(self):
        self.subnet = ""; self.username = ""; self.password = ""
        self.has_ad = False; self.dc_ip = ""; self.domain = ""
        self.outdir = Path("recon_output")
        self.max_threads = 8
        self.hosts_puertos = {}; self.smb_hosts = []
        self.lock = threading.Lock()
        self.resultados = {
            "meta": {}, "hosts": {}, "usuarios": [], "grupos_privilegiados": {},
            "shares": {}, "subredes_activas": {}, "web": {}, "aplicaciones": {},
            "servicios": {}, "paquetes_enviados": [],
            "politica_contrasenas": {}, "kerberoast": {}, "asrep_roast": {},
        }

    # --- escritura thread-safe de resultados ---
    def safe_set(self, top_key, sub_key, value):
        with self.lock:
            self.resultados[top_key][sub_key] = value

    def safe_append(self, top_key, value):
        with self.lock:
            self.resultados[top_key].append(value)

    def safe_update_dict(self, top_key, sub_key, patch: dict):
        with self.lock:
            self.resultados[top_key].setdefault(sub_key, {}).update(patch)

    # --- preparación de entorno ---
    def preparar_outdir(self):
        self.outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.outdir, 0o700)
        setup_logging(self.outdir)
        self._guardar_meta()

    def configurar_cli(self, args):
        self.subnet = args.target
        self.username = args.user
        self.password = args.password
        self.has_ad = args.ad
        self.dc_ip = args.dc or ""
        self.outdir = Path(args.outdir).resolve()
        self.max_threads = max(1, min(args.threads, 32))
        self.preparar_outdir()

    def pedir_datos_basicos(self):
        print(f"\n{C.HEADER}=== Configuración de la Sesión ==={C.RESET}")
        while True:
            self.subnet = ask("Subred, IP o nombre de host objetivo (ej: 10.10.11.0/24, scanme.nmap.org)")
            if es_ip_o_red_valida(self.subnet) or es_host_resoluble(self.subnet):
                break
            print_status("No es una IP/CIDR válida ni un host que se pueda resolver.", "error")

        self.username = ask("Usuario SMB (vacío = anónimo)", "")
        if self.username:
            self.password = os.getenv("SMB_PASS", "") or ask_password("Password SMB")

        self.has_ad = ask_yes_no("¿El entorno tiene Active Directory?")
        if self.has_ad:
            while True:
                self.dc_ip = ask("IP o nombre de host del controlador de dominio (DC)")
                if es_ip_o_red_valida(self.dc_ip) or es_host_resoluble(self.dc_ip):
                    break
                print_status("No es una IP válida ni un host que se pueda resolver.", "error")
            self.domain = ask("Nombre de dominio (ej: HTB.LOCAL, vacío = se intentará detectar)", "")

        hilos = ask("Hilos en paralelo para módulos pesados (1-32)", "8")
        try:
            self.max_threads = max(1, min(int(hilos), 32))
        except ValueError:
            self.max_threads = 8

        outdir_in = ask("Carpeta de resultados", "recon_output")
        self.outdir = Path(outdir_in).expanduser().resolve()
        self.preparar_outdir()
        print_status(f"Resultados en: {self.outdir}", "success")

    def _guardar_meta(self):
        self.resultados["meta"] = {
            "subred": self.subnet, "tiene_ad": self.has_ad,
            "dc_ip": self.dc_ip, "dominio": self.domain,
            "usuario": self.username if self.username else "Anónimo",
            "generado": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def limpiar_datos_objetivo(self):
        with self.lock:
            self.smb_hosts.clear()
            self.hosts_puertos.clear()
            for k in ("hosts", "usuarios", "shares", "grupos_privilegiados",
                      "web", "aplicaciones", "servicios", "politica_contrasenas",
                      "kerberoast", "asrep_roast"):
                if isinstance(self.resultados[k], dict):
                    self.resultados[k].clear()
                else:
                    self.resultados[k] = []

    def detectar_dominio(self):
        """Si no se indicó dominio a mano, lo toma del primer host con el campo detectado."""
        if self.domain:
            return self.domain
        for info in self.resultados["hosts"].values():
            d = info.get("domain")
            if d and d != "N/A":
                self.domain = d
                return d
        return ""


def exportar_json(ctx: Contexto):
    json_file = ctx.outdir / "recon_data.json"
    tmp_file = json_file.with_suffix(".tmp")
    with ctx.lock:
        contenido = json.dumps(ctx.resultados, indent=4, ensure_ascii=False)
    _secure_write(tmp_file, contenido)
    os.replace(tmp_file, json_file)
    print_status(f"JSON guardado en: {json_file}", "success")
