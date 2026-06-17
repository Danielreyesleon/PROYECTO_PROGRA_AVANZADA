#!/bin/bash
# =============================================================================
# firewall_hardening.sh - Blue Team: Configuración Segura del Firewall
# =============================================================================
# Proyecto Final - Ciberseguridad: Red Team vs Blue Team en Azure
# Persona 2 - Desarrollo Defensivo
#
# Propósito:
#   Automatizar la aplicación de reglas de firewall con UFW e iptables
#   para proteger la VM de tráfico no deseado o sospechoso.
#
# Uso:
#   sudo bash firewall_hardening.sh
#   sudo bash firewall_hardening.sh --reset    # Para limpiar todas las reglas
#
# Requisitos:
#   - ufw instalado  (sudo apt install ufw)
#   - iptables       (generalmente ya incluido en Ubuntu/Debian)
#   - Ejecutar como root (sudo)
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────────
# Colores para la terminal
# ─────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # Sin color

# ─────────────────────────────────────────────
# Variables de configuración
# ─────────────────────────────────────────────
LOG_FILE="/var/log/firewall_hardening.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Puertos permitidos (modificar según necesidad del proyecto)
SSH_PORT=22          # Puerto SSH (cambiar si se usa puerto no estándar)
HTTP_PORT=80         # HTTP
HTTPS_PORT=443       # HTTPS

# Rate-limiting SSH: máximo N conexiones por intervalo
SSH_RATE_LIMIT=6     # intentos
SSH_RATE_WINDOW=30   # segundos

# ─────────────────────────────────────────────
# Funciones auxiliares
# ─────────────────────────────────────────────

log() {
    echo -e "${GREEN}[+]${NC} $1"
    echo "[$TIMESTAMP] [INFO]  $1" >> "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[$TIMESTAMP] [WARN]  $1" >> "$LOG_FILE"
}

error() {
    echo -e "${RED}[✗]${NC} $1"
    echo "[$TIMESTAMP] [ERROR] $1" >> "$LOG_FILE"
}

section() {
    echo ""
    echo -e "${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}════════════════════════════════════════${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Este script debe ejecutarse como root: sudo bash firewall_hardening.sh"
        exit 1
    fi
}

check_dependencies() {
    section "Verificando dependencias"
    for cmd in ufw iptables; do
        if command -v "$cmd" &>/dev/null; then
            log "$cmd encontrado: $(command -v $cmd)"
        else
            warn "$cmd no encontrado. Instalando..."
            apt-get install -y "$cmd" >> "$LOG_FILE" 2>&1 || {
                error "No se pudo instalar $cmd"
                exit 1
            }
        fi
    done
}

# ─────────────────────────────────────────────
# Modo reset (limpia todo)
# ─────────────────────────────────────────────

reset_firewall() {
    section "RESET: Limpiando todas las reglas del firewall"
    warn "Esto eliminará TODAS las reglas de UFW e iptables."
    read -r -p "¿Continuar? (s/N): " confirm
    if [[ "$confirm" != "s" && "$confirm" != "S" ]]; then
        echo "Operación cancelada."
        exit 0
    fi

    ufw --force reset
    iptables -F
    iptables -X
    iptables -Z
    iptables -t nat -F
    iptables -t mangle -F
    log "Firewall reseteado exitosamente."
    exit 0
}

# ─────────────────────────────────────────────
# 1. Configuración de UFW
# ─────────────────────────────────────────────

configure_ufw() {
    section "1. Configurando UFW (Uncomplicated Firewall)"

    # Deshabilitar UFW temporalmente para aplicar reglas sin interrupciones
    ufw --force disable >> "$LOG_FILE" 2>&1
    log "UFW deshabilitado temporalmente para configuración."

    # Limpiar reglas existentes
    ufw --force reset >> "$LOG_FILE" 2>&1
    log "Reglas previas de UFW eliminadas."

    # ── Políticas por defecto ──────────────────────────────────
    # Denegar TODO el tráfico entrante por defecto
    ufw default deny incoming
    log "Política predeterminada: DENEGAR entradas."

    # Permitir TODO el tráfico saliente
    ufw default allow outgoing
    log "Política predeterminada: PERMITIR salidas."

    # ── Puertos permitidos ──────────────────────────────────────

    # SSH con rate-limiting integrado de UFW (protección contra brute force)
    ufw limit "$SSH_PORT/tcp" comment "SSH con rate-limiting"
    log "SSH (puerto $SSH_PORT) habilitado con rate-limiting de UFW."

    # HTTP y HTTPS
    ufw allow "$HTTP_PORT/tcp" comment "HTTP"
    log "HTTP (puerto $HTTP_PORT) habilitado."

    ufw allow "$HTTPS_PORT/tcp" comment "HTTPS"
    log "HTTPS (puerto $HTTPS_PORT) habilitado."

    # ── Habilitar logging de UFW ────────────────────────────────
    ufw logging on
    log "Logging de UFW habilitado (ver: /var/log/ufw.log)."

    # Activar UFW
    ufw --force enable >> "$LOG_FILE" 2>&1
    log "UFW habilitado y activo."

    echo ""
    log "Estado actual de UFW:"
    ufw status verbose
}

# ─────────────────────────────────────────────
# 2. Reglas defensivas con iptables
# ─────────────────────────────────────────────

configure_iptables() {
    section "2. Aplicando reglas defensivas con iptables"

    # ── Limpiar reglas existentes ───────────────────────────────
    iptables -F INPUT
    iptables -F FORWARD
    log "Cadenas INPUT y FORWARD limpiadas."

    # ── Permitir loopback ───────────────────────────────────────
    iptables -A INPUT -i lo -j ACCEPT
    log "Tráfico loopback permitido."

    # ── Permitir conexiones establecidas/relacionadas ───────────
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    log "Conexiones ESTABLISHED/RELATED permitidas."

    # ── Protección contra escaneos de puertos conocidos ─────────

    # Descartar paquetes NULL (todos los flags apagados — stealth scan)
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    log "Paquetes NULL descartados (protección anti-stealth scan)."

    # Descartar paquetes XMAS (todos los flags activos — Xmas scan)
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    log "Paquetes XMAS descartados (protección anti-Xmas scan)."

    # Descartar FIN scan (solo FIN activo)
    iptables -A INPUT -p tcp --tcp-flags ALL FIN -j DROP
    log "Paquetes FIN-only descartados."

    # Descartar paquetes SYN/FIN inválidos
    iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    log "Paquetes SYN/FIN inválidos descartados."

    # ── Protección contra SYN Flood ─────────────────────────────
    iptables -A INPUT -p tcp --syn \
        -m limit --limit 10/s --limit-burst 20 \
        -j ACCEPT
    iptables -A INPUT -p tcp --syn -j DROP
    log "Protección anti-SYN Flood aplicada (10 SYN/s, burst 20)."

    # ── Rate-limiting SSH con iptables ──────────────────────────
    # Registrar intentos excesivos antes de bloquear
    iptables -A INPUT -p tcp --dport "$SSH_PORT" \
        -m state --state NEW \
        -m recent --set --name SSH_BRUTE
    iptables -A INPUT -p tcp --dport "$SSH_PORT" \
        -m state --state NEW \
        -m recent --update --seconds "$SSH_RATE_WINDOW" \
        --hitcount "$SSH_RATE_LIMIT" \
        --name SSH_BRUTE \
        -j LOG --log-prefix "[SSH-BRUTE-BLOCK] " --log-level 4
    iptables -A INPUT -p tcp --dport "$SSH_PORT" \
        -m state --state NEW \
        -m recent --update --seconds "$SSH_RATE_WINDOW" \
        --hitcount "$SSH_RATE_LIMIT" \
        --name SSH_BRUTE \
        -j DROP
    log "Rate-limiting SSH: máx $SSH_RATE_LIMIT intentos en ${SSH_RATE_WINDOW}s."

    # ── Protección contra ping flooding ────────────────────────
    iptables -A INPUT -p icmp --icmp-type echo-request \
        -m limit --limit 1/s --limit-burst 5 \
        -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
    log "Protección anti-ping flood aplicada."

    # ── Permitir puertos necesarios (TCP) ──────────────────────
    iptables -A INPUT -p tcp --dport "$SSH_PORT"   -j ACCEPT
    iptables -A INPUT -p tcp --dport "$HTTP_PORT"  -j ACCEPT
    iptables -A INPUT -p tcp --dport "$HTTPS_PORT" -j ACCEPT
    log "Puertos permitidos: $SSH_PORT (SSH), $HTTP_PORT (HTTP), $HTTPS_PORT (HTTPS)."

    # ── Registrar y descartar todo lo demás ────────────────────
    iptables -A INPUT -j LOG --log-prefix "[IPTABLES-DROP] " --log-level 4
    iptables -A INPUT -j DROP
    log "Todo el tráfico restante será registrado y descartado."

    log "Reglas iptables aplicadas exitosamente."
}

# ─────────────────────────────────────────────
# 3. Hardening adicional del sistema
# ─────────────────────────────────────────────

harden_ssh() {
    section "3. Hardening de configuración SSH"

    SSHD_CONFIG="/etc/ssh/sshd_config"
    BACKUP="${SSHD_CONFIG}.bak.$(date +%Y%m%d_%H%M%S)"

    # Backup antes de modificar
    cp "$SSHD_CONFIG" "$BACKUP"
    log "Backup de sshd_config guardado en: $BACKUP"

    # Función para aplicar o actualizar parámetros SSH
    apply_ssh_param() {
        local param="$1"
        local value="$2"
        if grep -qE "^#?${param}" "$SSHD_CONFIG"; then
            # El parámetro existe (comentado o no) → reemplazar
            sed -i "s|^#\?${param}.*|${param} ${value}|" "$SSHD_CONFIG"
        else
            # No existe → agregar al final
            echo "${param} ${value}" >> "$SSHD_CONFIG"
        fi
        log "SSH: ${param} = ${value}"
    }

    apply_ssh_param "PermitRootLogin"              "no"
    apply_ssh_param "PasswordAuthentication"       "no"
    apply_ssh_param "PubkeyAuthentication"         "yes"
    apply_ssh_param "MaxAuthTries"                 "3"
    apply_ssh_param "LoginGraceTime"               "30"
    apply_ssh_param "X11Forwarding"                "no"
    apply_ssh_param "AllowTcpForwarding"           "no"
    apply_ssh_param "ClientAliveInterval"          "300"
    apply_ssh_param "ClientAliveCountMax"          "2"
    apply_ssh_param "Banner"                       "/etc/issue.net"

    # Crear banner de advertencia legal
    cat > /etc/issue.net << 'EOF'
*******************************************************************
*   ACCESO RESTRINGIDO - SISTEMA MONITOREADO                      *
*   Toda actividad es registrada y auditada.                      *
*   El acceso no autorizado es ilegal y será reportado.           *
*******************************************************************
EOF
    log "Banner de advertencia creado en /etc/issue.net"

    # Validar configuración antes de reiniciar
    if sshd -t 2>>"$LOG_FILE"; then
        systemctl restart sshd
        log "Servicio SSH reiniciado exitosamente con nueva configuración."
    else
        error "Error en la configuración SSH. Restaurando backup..."
        cp "$BACKUP" "$SSHD_CONFIG"
        error "Backup restaurado. Verifica el archivo manualmente."
    fi
}

# ─────────────────────────────────────────────
# 4. Persistencia de reglas iptables
# ─────────────────────────────────────────────

save_iptables_rules() {
    section "4. Guardando reglas iptables para persistencia"

    if command -v iptables-save &>/dev/null; then
        RULES_FILE="/etc/iptables/rules.v4"
        mkdir -p /etc/iptables
        iptables-save > "$RULES_FILE"
        log "Reglas guardadas en: $RULES_FILE"

        # Instalar iptables-persistent si no existe
        if ! dpkg -l | grep -q iptables-persistent; then
            warn "iptables-persistent no encontrado. Instalando para persistencia en reinicios..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent >> "$LOG_FILE" 2>&1
            log "iptables-persistent instalado."
        fi
    else
        warn "iptables-save no disponible. Las reglas no persistirán tras reinicio."
    fi
}

# ─────────────────────────────────────────────
# 5. Verificación y resumen final
# ─────────────────────────────────────────────

show_summary() {
    section "5. Resumen de la Configuración Aplicada"

    echo ""
    echo -e "${GREEN}UFW STATUS:${NC}"
    ufw status numbered

    echo ""
    echo -e "${GREEN}IPTABLES (INPUT chain):${NC}"
    iptables -L INPUT -n -v --line-numbers

    echo ""
    echo -e "${GREEN}SSH Config (parámetros clave):${NC}"
    grep -E "^(PermitRootLogin|PasswordAuthentication|MaxAuthTries|PubkeyAuthentication)" \
        /etc/ssh/sshd_config 2>/dev/null || echo "  [No se pudo leer sshd_config]"

    echo ""
    log "══════════════════════════════════════════════════"
    log " Hardening completado: $(date '+%Y-%m-%d %H:%M:%S')"
    log " Log completo en: $LOG_FILE"
    log " Log UFW en:      /var/log/ufw.log"
    log " Log kernel en:   /var/log/kern.log (iptables drops)"
    log "══════════════════════════════════════════════════"
}

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

main() {
    # Iniciar log
    echo "" >> "$LOG_FILE"
    echo "[$TIMESTAMP] ════ Inicio de firewall_hardening.sh ════" >> "$LOG_FILE"

    echo -e "${BLUE}"
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║  BLUE TEAM - FIREWALL HARDENING          ║"
    echo "  ║  Proyecto Final de Ciberseguridad        ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo -e "${NC}"

    # Parsear argumentos
    if [[ "${1:-}" == "--reset" ]]; then
        reset_firewall
    fi

    check_root
    check_dependencies
    configure_ufw
    configure_iptables
    harden_ssh
    save_iptables_rules
    show_summary
}

main "$@"
