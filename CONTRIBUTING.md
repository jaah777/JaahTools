# Cómo contribuir

Gracias por el interés en mejorar JAAH SECURY. Esto es lo más útil que
puedes aportar, de mayor a menor impacto:

## 1. Reportar desajustes de parsing (lo más valioso)

El punto más frágil del proyecto es que varios módulos parsean la salida
de texto de herramientas externas (`nxc`, `GetNPUsers.py`, `gobuster`,
`nmap -oG`). Esa salida **cambia de formato entre versiones**. Si un
módulo te devuelve listas vacías cuando sabes que debería haber
resultados:

1. Ejecuta el comando a mano y guarda la salida real.
2. Abre un issue con: versión de la herramienta (`nxc --version`,
   `impacket` via `pip show impacket`, etc.), el comando exacto, y la
   salida completa (**redacta contraseñas e IPs reales si no quieres
   compartirlas**).
3. Si puedes, ajusta el regex correspondiente en `jaah/modules/*.py` y
   abre un PR.

## 2. Añadir soporte para una herramienta alternativa

Por ejemplo, soporte para `ffuf` además de `gobuster` en
`jaah/modules/web.py`, o para `crackmapexec` como alias legado de
`netexec`. Sigue el patrón ya usado: comprobar con `shutil.which()`,
degradar con un aviso si no está, nunca lanzar una excepción sin capturar.

## 3. Reglas del proyecto (léelas antes de un PR)

- **Nunca** rompas la compatibilidad "sin dependencias opcionales": todo
  módulo debe funcionar en modo degradado (con aviso) si falta una
  herramienta externa, salvo `nmap`, que es la única dependencia dura.
- **Nunca** reproduzcas contraseñas o hashes completos en los mensajes de
  consola o en el log; usa el enmascarado existente en
  `core._mask_password_in_text` y los permisos 600 ya aplicados a los
  archivos de salida sensibles.
- Todo archivo que contenga datos de la sesión (JSON, logs, hashes) debe
  escribirse con `core._secure_write` (permisos 600) o recibir un
  `os.chmod(..., 0o600)` explícito si lo genera una herramienta externa.
- El proyecto es **Linux-only** a propósito (ver discusión en el README).
  No se aceptan PRs que añadan rutas condicionales para Windows nativo;
  WSL2 ya cubre ese caso de uso sin duplicar código.
- Threading: si tu módulo lanza hilos, respeta `ctx.max_threads` y usa
  `ctx.safe_set` / `ctx.safe_append` si vas a escribir estructuras
  compartidas desde más de un hilo (ver `jaah/modules/redes.py` como
  referencia).

## 4. Estilo

- Español para mensajes de usuario y comentarios (consistencia con el
  resto del proyecto).
- Funciones pequeñas, un módulo por punto del menú.
- `python3 -m py_compile jaah/**/*.py` debe pasar sin errores antes de
  cualquier PR.

## 5. Pruebas

No hay suite de tests automatizada todavía (es una contribución muy
bienvenida). Mientras tanto, prueba manualmente contra:

- Una máquina Linux simple de HTB/THM (sin SMB), para los módulos 1, 2, 6,
  7, 8.
- Una máquina Windows/AD "fácil" de HTB (ej. estilo *Forest*, *Active*),
  para los módulos 3, 4, 5, 10, 11, 12 y BloodHound.
