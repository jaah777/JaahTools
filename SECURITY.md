# Política de seguridad

## Alcance

JAAH SECURY es una herramienta **ofensiva** pensada para entornos
autorizados (CTF, labs propios, pentests con permiso). "Vulnerabilidades"
en el sentido de un proyecto defensivo no aplican igual aquí, pero sí nos
importan estos dos tipos de problemas:

### A. Fugas de datos sensibles del propio operador

Ejemplos: una contraseña que se guarda en texto plano en algún archivo sin
los permisos 600, un hash de Kerberos que queda legible por otros
usuarios del sistema, credenciales que aparecen en `session.log` sin
enmascarar. **Esto sí es un bug de seguridad del proyecto** y agradecemos
mucho el reporte.

### B. Comportamiento que podría dañar un objetivo por error

Ejemplos: un módulo que podría bloquear cuentas de AD sin avisar antes de
revisar la política de contraseñas, un escaneo que no respeta los límites
de tamaño de red que documenta el README, o el módulo de paquetes crudos
enviando algo distinto a lo que el usuario confirmó.

## Qué NO es un issue de seguridad aquí

- Que la herramienta pueda usarse para atacar sistemas sin autorización:
  eso es responsabilidad de quien la ejecuta (ver `LEGAL.md`), no una
  vulnerabilidad del código.
- Falta de detección por antivirus/EDR: no es un objetivo del proyecto.

## Cómo reportar

Para el tipo A (fuga de datos del operador), abre un **issue privado** si
tu plataforma de Git lo permite, o contacta directamente a los
mantenedores antes de publicarlo en abierto, especialmente si el fallo es
explotable de forma automática (por ejemplo, un patrón de nombre de
archivo predecible con permisos abiertos).

Para el tipo B, un issue público normal está bien.

Incluye siempre:
- Versión del script / commit.
- Distro y versión de Python.
- Pasos para reproducir.
- Qué esperabas vs. qué ocurrió.

## Buenas prácticas para quien use esta herramienta

- Ejecuta siempre en una carpeta de salida (`-o`) dedicada por máquina de
  CTF, no reutilices `recon_output/` entre objetivos distintos.
- No subas `recon_output/` a repositorios públicos ni a servicios de
  sincronización compartidos (contiene usuarios, shares, y potencialmente
  hashes de Kerberos).
- Revisa el módulo [10] (política de contraseñas) antes de correr
  AS-REP Roasting o Kerberoasting contra muchos usuarios de golpe.
