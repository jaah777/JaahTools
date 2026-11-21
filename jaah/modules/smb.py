"""[3][4][5] Enumeración SMB/AD: usuarios, grupos y shares."""
import re
from ..core import (C, run, print_status, _get_nxc_base, get_nxc_bin,
                     GRUPOS_PRIV_AD, GRUPOS_PRIV_LOCAL)


def enumerar_usuarios(ctx):
    print(f"\n{C.HEADER}=== [3] Enumeración de Usuarios ==={C.RESET}")
    if not get_nxc_bin():
        print_status("nxc/netexec no está instalado.", "error"); return
    if not ctx.smb_hosts:
        print_status("No hay hosts con SMB detectados. Ejecuta [1] primero.", "warning"); return

    targets = [ctx.dc_ip] if ctx.has_ad and ctx.dc_ip else ctx.smb_hosts
    salida = run(_get_nxc_base(ctx, targets) + ["--users"], ctx=ctx) or ""

    if ctx.has_ad and ctx.dc_ip:
        print_status("Ejecutando RID cycling...")
        rid_out = run(_get_nxc_base(ctx, [ctx.dc_ip]) + ["--rid-brute"], ctx=ctx) or ""
        salida += "\n" + rid_out

    usuarios = set()
    for line in salida.splitlines():
        m_rid = re.search(r"\d+:\s+[\w.-]+\\([^\s(]+)\s+\(SidTypeUser\)", line)
        if m_rid:
            usuarios.add(m_rid.group(1)); continue
        m_users = re.search(r"^SMB\s+\S+\s+445\s+\S+\s+(\S+)\s+(?:\d{4}-\d\d-\d\d|<never>)", line)
        if m_users:
            usuarios.add(m_users.group(1))

    usuarios = {u for u in usuarios if u.lower() not in ("guest", "krbtgt") and not u.endswith('$')}
    ctx.resultados["usuarios"] = sorted(usuarios)
    print_status(f"{len(usuarios)} usuario(s) consolidados.", "success")


def enumerar_grupos(ctx):
    print(f"\n{C.HEADER}=== [4] Enumeración de Grupos ==={C.RESET}")
    if not get_nxc_bin():
        print_status("nxc/netexec no está instalado.", "error"); return
    if not ctx.smb_hosts:
        print_status("No hay hosts con SMB detectados. Ejecuta [1] primero.", "warning"); return

    ctx.resultados["grupos_privilegiados"] = {}
    targets = [ctx.dc_ip] if ctx.has_ad and ctx.dc_ip else ctx.smb_hosts
    flag = "--groups" if ctx.has_ad else "--local-groups"
    lista_grupos = GRUPOS_PRIV_AD if ctx.has_ad else GRUPOS_PRIV_LOCAL

    salida_general = run(_get_nxc_base(ctx, targets) + [flag], ctx=ctx) or ""
    presentes = [g for g in lista_grupos if g.lower() in salida_general.lower()]

    detalle = {}
    for grupo in presentes:
        salida = run(_get_nxc_base(ctx, targets) + [flag, grupo], ctx=ctx) or ""
        miembros, capturando = [], False
        for line in salida.splitlines():
            if "enumerated members" in line.lower() or "membership" in line.lower():
                capturando = True; continue
            m = re.search(r"^SMB\s+\S+\s+445\s+\S+\s+(\S+)\s*$", line)
            if capturando and m and "[*]" not in line and "[-]" not in line:
                miembro = m.group(1).split("\\")[-1]
                if miembro and miembro != grupo:
                    miembros.append(miembro)
        detalle[grupo] = sorted(set(miembros))

    ctx.resultados["grupos_privilegiados"] = detalle
    if detalle:
        for g, miembros in detalle.items():
            etiqueta = ', '.join(miembros) if miembros else '(sin miembros detectados)'
            print_status(f"{g}: {etiqueta}", "warning")
    else:
        print_status("No se detectaron grupos privilegiados con miembros.", "info")


def enumerar_shares(ctx):
    print(f"\n{C.HEADER}=== [5] Enumeración de Shares ==={C.RESET}")
    if not get_nxc_bin():
        print_status("nxc/netexec no está instalado.", "error"); return
    if not ctx.smb_hosts:
        print_status("No hay hosts con SMB detectados. Ejecuta [1] primero.", "warning"); return

    ctx.resultados["shares"] = {}
    salida = run(_get_nxc_base(ctx, ctx.smb_hosts) + ["--shares"], ctx=ctx) or ""

    LINEAS_IGNORAR = {"Share", "-----", "Permissions", "Remark"}
    for line in salida.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[0] == "SMB" and parts[2] == "445":
            share = parts[4]
            if share.startswith("[") or share in LINEAS_IGNORAR:
                continue
            ip, perms = parts[1], " ".join(parts[5:])
            ctx.resultados["shares"].setdefault(ip, []).append({"share": share, "permisos": perms})

    print_status("Shares guardados.", "success")
