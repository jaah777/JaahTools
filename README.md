# JAAH SECURY

Herramienta de reconocimiento todo-en-uno para CTF (Hack The Box, TryHackMe,
laboratorios propios): descubrimiento de hosts y redes, enumeración SMB/AD,
web, aplicaciones, servicios, ataques de Kerberos y elaboración de paquetes.

> ⚠️ **Solo Linux.** Depende de herramientas y rutas exclusivas de Linux
> (`ip route`, NetExec, Impacket, raw sockets de scapy). En Windows, usa
> **WSL2** con una distro Linux (Ubuntu/Kali/Parrot).

> 🔒 **Uso exclusivo en entornos autorizados.** Lee [`LEGAL.md`](LEGAL.md)
> antes de usarlo. Esta herramienta genera tráfico activo (escaneos,
> autenticaciones, paquetes crudos) indistinguible de un ataque real.

## ¿Qué hace?

| # | Módulo | Qué obtiene |
|---|--------|-------------|
| 1 | Hosts | Puertos abiertos, OS y dominio por host (nmap + NetExec) |
| 2 | Redes | Subredes activas dentro de un rango grande, en paralelo |
| 3 | Usuarios | Usuarios SMB/AD, incluyendo RID cycling |
| 4 | Grupos | Miembros de grupos privilegiados (Domain Admins, etc.) |
| 5 | Shares | Recursos compartidos SMB y sus permisos |
| 6 | Web | Headers, título, robots.txt, huella tecnológica, fuzzing de rutas |
| 7 | Aplicaciones | Versión de cada servicio + exploits públicos (searchsploit) |
| 8 | Servicios | Scripts por defecto de nmap + banner grabbing manual |
| 9 | Paquetes | TCP SYN / UDP / ICMP crudos con scapy, para pruebas puntuales |
| 10 | Política de contraseñas | Umbral de bloqueo, longitud mínima (para spraying seguro) |
| 11 | AS-REP Roasting | Usuarios sin preautenticación Kerberos |
| 12 | Kerberoasting | Hashes de tickets de servicio (SPN) |
| — | BloodHound | Recolección de datos para el grafo de ataque de AD |
| — | Reporte | `reporte.md` con hallazgos ordenados por severidad |

Todo queda en `recon_output/`: `recon_data.json` (datos consolidados),
`reporte.md` (informe legible), `raw/` (salida cruda de cada comando) y
`session.log`.

## Instalación

```bash
git clone https://github.com/<tu-usuario>/jaah-securey.git
cd jaah-securey

# Dependencias de sistema (Debian/Ubuntu/Kali)
sudo apt update
sudo apt install -y nmap gobuster whatweb exploitdb seclists python3-pip pipx

# Dependencias de Python
pip install -r requirements.txt --break-system-packages
pipx install git+https://github.com/Pennyw0rth/NetExec   # "netexec" NO existe en PyPI
pipx install impacket
```

Ver [`SYSTEM_REQUIREMENTS.md`](SYSTEM_REQUIREMENTS.md) para el detalle de
qué módulo necesita qué herramienta, y qué pasa si falta alguna (ningún
módulo debería crashear el programa completo: se omite con un aviso).

## Uso

```bash
# Interactivo
python3 jaah_cli.py

# CLI, flujo básico
python3 jaah_cli.py -t 10.10.11.0/24 --yes

# CLI, flujo SMB completo + web + apps + servicios + reporte
SMB_PASS="Password123" python3 jaah_cli.py -t 10.10.11.5 -u jdoe \
  --all --web --apps --services --report --yes

# CLI, entorno AD con Kerberos
SMB_PASS="Password123" python3 jaah_cli.py -t 10.10.11.0/24 -u jdoe \
  --ad --dc 10.10.11.5 --domain HTB.LOCAL --kerberos --report --yes
```

Todas las opciones: `python3 jaah_cli.py --help`.

## Estructura del proyecto

```
jaah_cli.py           Punto de entrada
jaah/
  core.py             Utilidades compartidas, Contexto thread-safe
  cli.py              Argumentos y orquestación en modo CLI
  menu.py             Menú interactivo
  reporting.py        Generador de reporte Markdown
  modules/
    hosts.py          [1]
    redes.py          [2]
    smb.py             [3][4][5]
    web.py             [6]
    apps.py            [7]
    servicios.py       [8]
    paquetes.py        [9]
    kerberos.py        [10][11][12]
    bloodhound.py       BloodHound
```

## Contribuir

Ver [`CONTRIBUTING.md`](CONTRIBUTING.md). Issues y PRs son bienvenidos,
especialmente los que corrijan parsing de salidas de NetExec/Impacket
contra versiones distintas a las que se probaron aquí.

## Seguridad y reporte de vulnerabilidades

Ver [`SECURITY.md`](SECURITY.md).

## Licencia

MIT. Ver [`LICENSE`](LICENSE) y, obligatoriamente, [`LEGAL.md`](LEGAL.md).
