"""
jaah.reporting
--------------
Convierte ctx.resultados en un informe Markdown legible, ordenado por
severidad en una sección de "Hallazgos destacados" y con el detalle completo
debajo. Pensado para servir de borrador de writeup de CTF.
"""
from .core import _secure_write, print_status, C


def _tabla(headers, filas):
    if not filas:
        return "_Sin datos._\n"
    out = "| " + " | ".join(headers) + " |\n"
    out += "|" + "|".join(["---"] * len(headers)) + "|\n"
    for fila in filas:
        out += "| " + " | ".join(str(c) for c in fila) + " |\n"
    return out


def _hallazgos_destacados(r: dict) -> list:
    """Heurística simple de severidad para no tener que leer todo el JSON."""
    hallazgos = []

    for ip, shares in r.get("shares", {}).items():
        for s in shares:
            if "WRITE" in s.get("permisos", "").upper():
                hallazgos.append(("ALTA", f"Share con escritura: `{ip}` -> `{s['share']}` ({s['permisos']})"))

    for grupo, miembros in r.get("grupos_privilegiados", {}).items():
        if miembros:
            hallazgos.append(("ALTA", f"Grupo privilegiado con miembros: **{grupo}** -> {', '.join(miembros)}"))

    asrep = r.get("asrep_roast", {})
    if asrep.get("vulnerables"):
        hallazgos.append(("CRÍTICA", f"{asrep['vulnerables']} usuario(s) vulnerables a AS-REP Roasting "
                                      f"(`{asrep.get('archivo_hashes')}`)"))

    kerb = r.get("kerberoast", {})
    if kerb.get("hashes_obtenidos"):
        hallazgos.append(("CRÍTICA", f"{kerb['hashes_obtenidos']} hash(es) de Kerberoasting obtenidos "
                                      f"(`{kerb.get('archivo_hashes')}`)"))

    pol = r.get("politica_contrasenas", {})
    umbral = str(pol.get("umbral_bloqueo", "")).lower()
    if umbral and umbral not in ("none", "0"):
        hallazgos.append(("INFO", f"Umbral de bloqueo de cuentas: {pol['umbral_bloqueo']} "
                                   "(limita los intentos de password spraying)"))

    for ip, apps in r.get("aplicaciones", {}).items():
        for a in apps:
            if a.get("exploits"):
                hallazgos.append(("MEDIA", f"Exploit(s) públicos para `{ip}:{a['puerto']}` "
                                            f"({a['servicio']} {a['version']}): {a['exploits'][0]}"))

    for ip, host in r.get("hosts", {}).items():
        if ("445" in host.get("puertos", []) or "139" in host.get("puertos", [])) and not r.get("usuarios"):
            hallazgos.append(("INFO", f"`{ip}` tiene SMB abierto; revisa sesión nula si no hay usuarios listados."))

    orden = {"CRÍTICA": 0, "ALTA": 1, "MEDIA": 2, "INFO": 3}
    hallazgos.sort(key=lambda h: orden.get(h[0], 9))
    return hallazgos


def generar_reporte_markdown(ctx) -> str:
    r = ctx.resultados
    meta = r.get("meta", {})
    md = []

    md.append(f"# Reporte de Reconocimiento - {meta.get('subred', 'objetivo')}\n")
    md.append(f"- **Generado:** {meta.get('generado', 'N/A')}")
    md.append(f"- **Objetivo:** `{meta.get('subred', 'N/A')}`")
    md.append(f"- **Active Directory:** {'Sí' if meta.get('tiene_ad') else 'No'}")
    if meta.get("tiene_ad"):
        md.append(f"- **DC:** `{meta.get('dc_ip', 'N/A')}` | **Dominio:** `{meta.get('dominio', 'N/A')}`")
    md.append(f"- **Usuario de sesión:** {meta.get('usuario', 'Anónimo')}\n")

    # --- Hallazgos destacados ---
    md.append("## Hallazgos destacados\n")
    hallazgos = _hallazgos_destacados(r)
    if hallazgos:
        for severidad, texto in hallazgos:
            emoji = {"CRÍTICA": "🔴", "ALTA": "🟠", "MEDIA": "🟡", "INFO": "🔵"}.get(severidad, "⚪")
            md.append(f"- {emoji} **[{severidad}]** {texto}")
    else:
        md.append("_Sin hallazgos destacados todavía — ejecuta más módulos de enumeración._")
    md.append("")

    # --- Hosts ---
    md.append("## Hosts descubiertos\n")
    filas = []
    for ip, h in sorted(r.get("hosts", {}).items()):
        filas.append([ip, h.get("hostname", ""), h.get("os", ""), h.get("domain", ""),
                      ", ".join(h.get("puertos", []))])
    md.append(_tabla(["IP", "Hostname", "OS", "Dominio", "Puertos"], filas))

    # --- Usuarios ---
    md.append("## Usuarios enumerados\n")
    usuarios = r.get("usuarios", [])
    md.append(", ".join(f"`{u}`" for u in usuarios) if usuarios else "_Ninguno._")
    md.append("")

    # --- Grupos privilegiados ---
    md.append("## Grupos privilegiados\n")
    grupos = r.get("grupos_privilegiados", {})
    if grupos:
        for g, miembros in grupos.items():
            md.append(f"- **{g}**: {', '.join(miembros) if miembros else '_(sin miembros detectados)_'}")
    else:
        md.append("_Ninguno detectado._")
    md.append("")

    # --- Shares ---
    md.append("## Recursos compartidos (shares)\n")
    filas = []
    for ip, shares in r.get("shares", {}).items():
        for s in shares:
            filas.append([ip, s["share"], s["permisos"]])
    md.append(_tabla(["IP", "Share", "Permisos"], filas))

    # --- Web ---
    md.append("## Enumeración web\n")
    web = r.get("web", {})
    if web:
        for url, info in web.items():
            md.append(f"### {url}")
            if "error" in info:
                md.append(f"- Error de conexión: {info['error']}\n")
                continue
            md.append(f"- **Server:** {info.get('headers', {}).get('Server', 'N/A')}")
            md.append(f"- **Título:** {info.get('titulo', '')}")
            rutas = info.get("rutas_encontradas", [])
            if rutas:
                md.append(f"- **Rutas encontradas ({len(rutas)}):** " +
                           ", ".join(f"`{x['ruta']}` ({x['status']})" for x in rutas[:15]))
            md.append("")
    else:
        md.append("_Sin análisis web._\n")

    # --- Aplicaciones ---
    md.append("## Aplicaciones y exploits\n")
    apps = r.get("aplicaciones", {})
    filas = []
    for ip, lista in apps.items():
        for a in lista:
            filas.append([f"{ip}:{a['puerto']}", a["servicio"], a["version"],
                          a["exploits"][0] if a["exploits"] else ""])
    md.append(_tabla(["Host:Puerto", "Servicio", "Versión", "Exploit público (si existe)"], filas))

    # --- Kerberos ---
    md.append("## Kerberos (AS-REP Roasting / Kerberoasting)\n")
    asrep = r.get("asrep_roast", {})
    kerb = r.get("kerberoast", {})
    md.append(f"- **AS-REP Roasting:** {asrep.get('vulnerables', 0)} usuario(s) vulnerables "
              f"de {asrep.get('usuarios_probados', 0)} probados. "
              f"Archivo: `{asrep.get('archivo_hashes', 'N/A')}`")
    md.append(f"- **Kerberoasting:** {kerb.get('hashes_obtenidos', 0)} hash(es) obtenidos. "
              f"Archivo: `{kerb.get('archivo_hashes', 'N/A')}`")
    md.append("")

    # --- Política de contraseñas ---
    md.append("## Política de contraseñas\n")
    pol = r.get("politica_contrasenas", {})
    if pol:
        for k, v in pol.items():
            md.append(f"- **{k}**: {v}")
    else:
        md.append("_No consultada._")
    md.append("")

    # --- Subredes activas ---
    subredes = r.get("subredes_activas", {})
    if subredes:
        md.append("## Subredes activas\n")
        filas = [[sub, len(ips)] for sub, ips in subredes.items()]
        md.append(_tabla(["Subred", "Hosts activos"], filas))

    # --- Paquetes enviados ---
    paquetes = r.get("paquetes_enviados", [])
    if paquetes:
        md.append("## Paquetes crudos enviados (módulo scapy)\n")
        filas = [[p["destino"], p["tipo"], p["resultado"]] for p in paquetes]
        md.append(_tabla(["Destino", "Tipo", "Resultado"], filas))

    md.append("\n---\n_Generado automáticamente por JAAH SECURY. Revisa `raw/` para la evidencia "
               "completa de cada comando ejecutado._")

    return "\n".join(md)


def guardar_reporte(ctx):
    contenido = generar_reporte_markdown(ctx)
    ruta = ctx.outdir / "reporte.md"
    _secure_write(ruta, contenido)
    print_status(f"Reporte Markdown generado en: {ruta}", "success")
    return ruta
