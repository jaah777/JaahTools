# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/).

## [2.0.2] - Robustez del módulo web

### Corregido
- Un error HTTP de la página raíz (403, 401, 500...) hacía que
  `enumerar_web` abandonara TODO el análisis de ese host, incluyendo
  `robots.txt`, whatweb y el fuzzing de rutas — aunque esos sí podrían
  funcionar con la raíz bloqueada. Ahora solo un fallo real de conexión
  (host caído, timeout, DNS) se trata como error; un HTTPError se registra
  y el análisis continúa.
- Si `gobuster` detecta una respuesta "comodín" (el servidor responde 200
  a cualquier ruta — típico de paneles de router/portales cautivos) y
  aborta por seguridad, el programa se quedaba sin resultados en silencio.
  Ahora cae automáticamente al fallback de wordlist propio.
- Se añadió detección de respuesta comodín también en el fallback: si
  todas las rutas probadas devuelven el mismo status, se avisa que
  probablemente no son hallazgos reales (router/portal cautivo) en vez de
  presentarlos como si fueran rutas encontradas de verdad.

## [2.0.1] - Soporte de nombres de host + corrección de instalación

### Corregido
- `-t`/`--dc` y los prompts interactivos solo aceptaban IP o CIDR
  (`ipaddress.ip_network` los rechazaba de entrada), así que algo tan común
  como `-t scanme.nmap.org` fallaba antes de intentar nada. Ahora se acepta
  cualquier nombre de host que resuelva por DNS, además de IP/CIDR.
- La documentación (README, SYSTEM_REQUIREMENTS, requirements.txt) decía
  instalar NetExec con `pipx install netexec` / `pip install netexec`.
  **Ese paquete no existe en PyPI.** La instalación oficial es directo
  desde el repositorio: `pipx install git+https://github.com/Pennyw0rth/NetExec`.

## [2.0.0] - Reestructuración en paquete

### Añadido
- Módulos [6][7][8]: enumeración web, de aplicaciones y de servicios.
- Módulo [9]: elaboración de paquetes crudos con scapy.
- Módulos [10][11][12]: política de contraseñas, AS-REP Roasting y
  Kerberoasting (vía Impacket).
- Threading configurable (`--threads`, 1-32) en los módulos de redes, web,
  aplicaciones y servicios.
- Generador de reporte en Markdown (`reporting.py`) con hallazgos
  ordenados por severidad.
- Reestructuración completa de un único script a un paquete Python
  (`jaah/core.py`, `jaah/modules/*`, `jaah/cli.py`, `jaah/menu.py`).
- Proyecto declarado explícitamente Linux-only, con comprobación de
  plataforma al arrancar.

### Corregido
- **Crítico:** las peticiones HTTPS fallaban en silencio contra
  certificados autofirmados (el caso normal en HTB/THM): el módulo web
  ahora usa un contexto SSL que no valida el certificado.
- Los archivos de hashes de Kerberos (`asrep_hashes.txt`,
  `kerberoast_hashes.txt`) y la lista de usuarios para AS-REP Roasting
  nacían con permisos por defecto del sistema; ahora se fuerzan a 600.
- El enmascarado de contraseñas en los logs ya no destroza texto legítimo
  cuando la contraseña es muy corta (< 4 caracteres): se enmascara solo en
  contexto de credencial (`:password`, `-p password`).
- `gobuster` se invoca con `-k` (ignora TLS) en vez de `--no-error`, que
  no existe en todas las versiones y dejaba la enumeración sin resultados
  sin avisar.

### Eliminado
- Toda rama de código condicional para Windows (`os.name == "nt"`).

## [1.x] - Versión de script único

- Script único `jaah_securey.py` con los módulos 1 a 5 (hosts, redes,
  usuarios, grupos, shares) y BloodHound.
- Correcciones sucesivas de parsing de shares/usuarios/grupos, manejo de
  timeouts, permisos de archivos y validación de CIDR.
