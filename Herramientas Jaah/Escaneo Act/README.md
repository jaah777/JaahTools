# 🛡️ JAAH EA - SMB / AD Recon Tool

Herramienta interactiva de reconocimiento SMB y Active Directory (AD) escrita en Python 3, diseñada para entornos de laboratorio (Hack The Box, TryHackMe, laboratorios propios). 

El script automatiza la enumeración de hosts, usuarios, grupos de autorización y recursos compartidos, adaptándose tanto a entornos con Active Directory como a grupos de trabajo (Workgroups).

## ✨ Características
- Menú interactivo con colores y validación de datos.
- Enumeración de hosts (Nmap).
- Enumeración de usuarios y grupos (NetExec + enum4linux-ng).
- Enumeración de recursos compartidos (Shares) en pasadas anónimas y autenticadas.
- Soporte inteligente para entornos con AD (Domain Controller) y sin AD (Workgroup).
- Validación estricta de IPs/Subredes.
- Ocultación de contraseñas en consola (`getpass`).
- Sistema de logs (`session.log`) para auditoría de comandos ejecutados.

## 📋 Requisitos
- Python 3.8+
- [Nmap](https://nmap.org/)
- [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec)
- [enum4linux-ng](https://github.com/cddmp/enum4linux-ng)

## 🚀 Instalación
1. Clona el repositorio:
   ```bash
   git clone https://github.com/jaah777/jaah-ea-smb-recon.git
   cd jaah-ea-smb-recon