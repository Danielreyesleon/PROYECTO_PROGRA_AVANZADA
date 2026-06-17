import os
import subprocess
import platform
import logging
from datetime import datetime

# Configuración del log
logging.basicConfig(
    filename='os_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def separador(titulo):
    print(f"\n{'='*50}")
    print(f"  {titulo}")
    print(f"{'='*50}")
    logging.info(f"--- {titulo} ---")

def info_sistema():
    separador("INFORMACIÓN DEL SISTEMA")
    datos = {
        "Sistema Operativo": platform.system(),
        "Versión": platform.version(),
        "Arquitectura": platform.machine(),
        "Hostname": platform.node(),
        "Python": platform.python_version()
    }
    for clave, valor in datos.items():
        print(f"  {clave}: {valor}")
        logging.info(f"{clave}: {valor}")

def listar_usuarios():
    separador("USUARIOS DEL SISTEMA")
    try:
        resultado = subprocess.run(['cat', '/etc/passwd'], capture_output=True, text=True)
        for linea in resultado.stdout.splitlines():
            partes = linea.split(':')
            if len(partes) > 0:
                usuario = partes[0]
                uid = partes[2] if len(partes) > 2 else '?'
                shell = partes[6] if len(partes) > 6 else '?'
                if int(uid) >= 1000 or usuario == 'root':
                    print(f"  Usuario: {usuario} | UID: {uid} | Shell: {shell}")
                    logging.info(f"Usuario: {usuario} | UID: {uid} | Shell: {shell}")
    except Exception as e:
        print(f"  Error: {e}")

def puertos_abiertos():
    separador("PUERTOS ABIERTOS")
    try:
        resultado = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
        print(resultado.stdout)
        logging.info(resultado.stdout)
    except Exception as e:
        print(f"  Error: {e}")

def servicios_activos():
    separador("SERVICIOS ACTIVOS")
    try:
        resultado = subprocess.run(
            ['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager'],
            capture_output=True, text=True
        )
        print(resultado.stdout)
        logging.info(resultado.stdout)
    except Exception as e:
        print(f"  Error: {e}")

def revisar_ssh():
    separador("CONFIGURACIÓN SSH")
    ruta = '/etc/ssh/sshd_config'
    claves = ['PermitRootLogin', 'PasswordAuthentication', 'Port', 'MaxAuthTries']
    try:
        with open(ruta, 'r') as f:
            for linea in f:
                for clave in claves:
                    if linea.startswith(clave):
                        print(f"  {linea.strip()}")
                        logging.info(linea.strip())
    except Exception as e:
        print(f"  Error leyendo SSH config: {e}")

def