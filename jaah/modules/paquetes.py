"""[9] Elaboración de paquetes crudos (scapy): TCP SYN, UDP, ICMP."""
import ipaddress
import json
import os
import time
from ..core import C, ask, ask_yes_no, print_status, _secure_write, exportar_json


def _requiere_scapy():
    try:
        from scapy.all import IP, TCP, UDP, ICMP, sr1, send  # noqa: F401
        return True
    except ImportError:
        return False


def elaborar_paquetes(ctx):
    print(f"\n{C.HEADER}=== [9] Elaboración de Paquetes ==={C.RESET}")
    print_status("Construye y envía paquetes crudos. Úsalo SOLO contra tu objetivo autorizado:"
                  " en cualquier otra red equivale a tráfico de ataque real.", "warning")

    if not _requiere_scapy():
        print_status("Falta la librería scapy (pip install scapy).", "error"); return
    if os.geteuid() != 0:
        print_status("Se necesitan privilegios de root para enviar paquetes crudos (sudo).", "error"); return

    from scapy.all import IP, TCP, UDP, ICMP, sr1

    sub_menu = f"""
  {C.CYAN}[1]{C.RESET} TCP SYN a un puerto
  {C.CYAN}[2]{C.RESET} Paquete UDP con payload
  {C.CYAN}[3]{C.RESET} ICMP echo (ping) con payload personalizado
  {C.CYAN}[0]{C.RESET} Volver
"""
    print(sub_menu)
    opcion = ask("Opción", "0")
    if opcion == "0":
        return

    destino = ask("IP destino")
    try:
        ipaddress.ip_address(destino)
    except ValueError:
        print_status("IP inválida.", "error"); return

    registro = {"destino": destino, "tipo": None, "resultado": None}

    if opcion == "1":
        puerto = ask("Puerto TCP destino", "80")
        if not ask_yes_no(f"¿Confirmas enviar un TCP SYN a {destino}:{puerto}?"):
            return
        pkt = IP(dst=destino) / TCP(dport=int(puerto), flags="S")
        resp = sr1(pkt, timeout=3, verbose=0)
        registro["tipo"] = f"TCP SYN -> {puerto}"
        if resp is None:
            print_status("Sin respuesta (filtrado o host caído).", "warning")
            registro["resultado"] = "sin respuesta"
        elif resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags
            estado = "abierto (SYN-ACK)" if flags == 0x12 else f"cerrado/filtrado (flags={flags})"
            print_status(f"Puerto {puerto}: {estado}", "success")
            registro["resultado"] = estado

    elif opcion == "2":
        puerto = ask("Puerto UDP destino", "53")
        payload = ask("Payload (texto plano)", "ping")
        if not ask_yes_no(f"¿Confirmas enviar UDP a {destino}:{puerto}?"):
            return
        pkt = IP(dst=destino) / UDP(dport=int(puerto)) / payload.encode()
        resp = sr1(pkt, timeout=3, verbose=0)
        registro["tipo"] = f"UDP -> {puerto}"
        if resp is None:
            print_status("Sin respuesta (normal en UDP si el puerto está abierto).", "warning")
            registro["resultado"] = "sin respuesta"
        else:
            print_status(f"Respuesta recibida: {resp.summary()}", "success")
            registro["resultado"] = resp.summary()

    elif opcion == "3":
        payload = ask("Payload del ICMP (texto)", "CTF-test")
        if not ask_yes_no(f"¿Confirmas enviar ICMP echo a {destino}?"):
            return
        pkt = IP(dst=destino) / ICMP() / payload.encode()
        resp = sr1(pkt, timeout=3, verbose=0)
        registro["tipo"] = "ICMP echo"
        if resp is None:
            print_status("Sin respuesta (host caído o ICMP bloqueado).", "warning")
            registro["resultado"] = "sin respuesta"
        else:
            print_status(f"Respuesta: {resp.summary()}", "success")
            registro["resultado"] = resp.summary()
    else:
        print_status("Opción inválida.", "error"); return

    ctx.resultados["paquetes_enviados"].append(registro)
    if ctx.outdir:
        _secure_write(ctx.outdir / "raw" / f"{time.time_ns()}_scapy.txt", json.dumps(registro, indent=2))
    exportar_json(ctx)
