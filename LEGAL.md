# Aviso legal y uso aceptable

JAAH SECURY es una herramienta de **reconocimiento ofensivo**: escanea
puertos, enumera usuarios y recursos de red, intenta autenticarse contra
servicios SMB/LDAP, solicita tickets Kerberos y puede construir y enviar
paquetes de red crudos.

## Úsala solo en:

- Máquinas de **Hack The Box**, **TryHackMe** u otras plataformas de CTF
  mientras tengas una sesión/acceso activo y autorizado a esa máquina.
- Infraestructura de **tu propiedad** (lab casero, homelab).
- Entornos de un **pentest o auditoría con autorización explícita y por
  escrito** del propietario del sistema.

## No la uses contra:

- Cualquier red, host o dominio para el que no tengas autorización
  explícita del propietario.
- Infraestructura de producción de terceros, aunque creas que tiene una
  vulnerabilidad "obvia".
- Objetivos donde el alcance autorizado no cubra expresamente escaneo de
  puertos, autenticación activa, Kerberoasting/AS-REP roasting o envío de
  paquetes crudos.

## Por qué importa específicamente en este proyecto

- El módulo de **elaboración de paquetes** (scapy) genera tráfico crudo
  indistinguible de un ataque real (SYN scanning, floods pequeños, ICMP
  con payload arbitrario).
- **Kerberoasting** y **AS-REP Roasting** generan intentos de
  autenticación contra el controlador de dominio. Mal usados, pueden
  **bloquear cuentas de usuarios reales** si no revisas antes la política
  de contraseñas (módulo 10).
- El **mapeo de subredes** puede escanear rangos grandes (hasta /16): en
  una red compartida esto es tráfico fácilmente detectable y puede
  activar alarmas de un SOC o IDS que no es tuyo.

## Responsabilidad

Esta herramienta se entrega "tal cual", sin garantías (ver `LICENSE`). El
autor y los colaboradores no se hacen responsables del uso que cada
persona le dé. **La responsabilidad legal y ética de cómo y contra quién
se usa esta herramienta es exclusivamente de quien la ejecuta.**

Si no tienes autorización explícita por escrito para escanear un objetivo,
no lo escanees.
