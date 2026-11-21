# Requisitos del sistema

JAAH SECURY es **exclusivamente para Linux**. Depende de comandos (`ip
route`), bibliotecas (raw sockets vía scapy) y herramientas del ecosistema
ofensivo de Linux (NetExec, Impacket, gobuster, searchsploit) que no tienen
equivalente directo en Windows. Si solo tienes Windows, instala **WSL2**
con Ubuntu y trabaja desde ahí.

## Obligatorio

| Herramienta | Para qué | Instalación (Debian/Ubuntu/Kali) |
|---|---|---|
| Python ≥ 3.9 | Todo el programa | Preinstalado en casi toda distro |
| `nmap` | Módulos [1][2][7][8] | `sudo apt install nmap` |

Sin `nmap` el programa **se niega a arrancar** (lo comprueba al inicio).

## Opcional (cada módulo se degrada con un aviso si falta, nunca crashea)

| Herramienta | Para qué | Instalación |
|---|---|---|
| `netexec` (nxc) | [3][4][5][10], BloodHound | `pipx install git+https://github.com/Pennyw0rth/NetExec` (no existe en PyPI como `netexec`) |
| `impacket` (GetNPUsers.py, GetUserSPNs.py) | [11][12] | `pipx install impacket` |
| `scapy` (Python) | [9] | `pip install scapy --break-system-packages` |
| `gobuster` | [6] (fuzzing de directorios) | `sudo apt install gobuster` |
| SecLists o dirb | [6] (wordlists para gobuster) | `sudo apt install seclists` |
| `whatweb` | [6] (huella tecnológica) | `sudo apt install whatweb` |
| `searchsploit` (exploitdb) | [7] (búsqueda de exploits) | `sudo apt install exploitdb` |

Si falta `gobuster`/SecLists, el módulo [6] usa una wordlist mínima
integrada (~28 rutas) vía `urllib`, sin dependencias extra — más lento y
menos exhaustivo, pero funcional.

## Permisos

- El módulo [9] (elaboración de paquetes) necesita **root** (raw sockets).
  Ejecuta con `sudo` solo cuando vayas a usar ese módulo.
- El resto de módulos no necesita privilegios elevados.

## Variables de entorno

- `SMB_PASS`: contraseña SMB/AD, para no dejarla en el historial de bash
  ni visible en `ps aux` (a diferencia de pasarla con `-p`).

## Instalación en un solo bloque (Kali/Parrot/Ubuntu)

```bash
sudo apt update
sudo apt install -y nmap gobuster whatweb exploitdb seclists python3-pip pipx git
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
pipx install impacket
pip install -r requirements.txt --break-system-packages
```

Verifica que todo quedó disponible:

```bash
for t in nmap nxc GetNPUsers.py GetUserSPNs.py gobuster whatweb searchsploit; do
  command -v "$t" >/dev/null && echo "OK  $t" || echo "--  $t (no instalado, opcional)"
done
python3 -c "import scapy" 2>/dev/null && echo "OK  scapy" || echo "--  scapy (no instalado, opcional)"
```
