#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# start-dashboard.sh – ARTEX Monitor Dashboard starten
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_USER="${SUDO_USER:-$USER}"

# ── Ziel-Container bestimmen ───────────────────────────────────────────
# Default: artex-app (bisheriges Verhalten). --container <name> setzt ihn
# direkt, --manuell/--manual zeigt alle laufenden Container zur Auswahl,
# --all startet eine komplett eigene Dashboard-Instanz (eigener Port) für
# JEDEN laufenden Container gleichzeitig.
_usage() {
    cat <<'EOF'
Verwendung: bash start-dashboard.sh [OPTIONEN]

OPTIONEN
  (ohne Option)          Startet gegen den Default-Container 'artex-app'
                         (oder $ARTEX_CONTAINER, falls gesetzt).
  --container <name>     Startet gezielt gegen diesen einen Container.
  --manuell, --manual    Zeigt alle laufenden Container zur Auswahl an.
  --all                  Startet für JEDEN laufenden Container eine eigene
                         Dashboard-Instanz auf einem eigenen Port
                         (9999, 10000, 10001, ...). Strg+C beendet alle.
  -h, --help             Diese Hilfe anzeigen.

BEISPIELE
  bash start-dashboard.sh
  bash start-dashboard.sh --container mein-container
  bash start-dashboard.sh --manuell
  bash start-dashboard.sh --all
EOF
}

ARTEX_CONTAINER="${ARTEX_CONTAINER:-artex-app}"
ALL_MODE=0
_PASSTHROUGH_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            _usage
            exit 0
            ;;
        --all)
            ALL_MODE=1
            shift
            ;;
        --container)
            ARTEX_CONTAINER="${2:-}"
            if [[ -z "$ARTEX_CONTAINER" ]]; then
                echo "✗ --container benötigt einen Namen"; exit 1
            fi
            shift 2
            ;;
        --container=*)
            ARTEX_CONTAINER="${1#--container=}"
            shift
            ;;
        --manuell|--manual)
            mapfile -t _running < <(docker ps --format '{{.Names}}')
            if [[ ${#_running[@]} -eq 0 ]]; then
                echo "✗ Kein laufender Container gefunden."; exit 1
            fi
            echo "Laufende Container:"
            for i in "${!_running[@]}"; do
                printf '  [%d] %s\n' "$((i+1))" "${_running[$i]}"
            done
            read -rp "Container wählen [1-${#_running[@]}]: " _choice
            if ! [[ "$_choice" =~ ^[0-9]+$ ]] || (( _choice < 1 || _choice > ${#_running[@]} )); then
                echo "✗ Ungültige Auswahl."; exit 1
            fi
            ARTEX_CONTAINER="${_running[$((_choice-1))]}"
            shift
            ;;
        *)
            _PASSTHROUGH_ARGS+=("$1")
            shift
            ;;
    esac
done

if [[ "$ALL_MODE" -eq 1 ]]; then
    mapfile -t _ALL_CONTAINERS < <(docker ps --format '{{.Names}}')
    if [[ ${#_ALL_CONTAINERS[@]} -eq 0 ]]; then
        echo "✗ Kein laufender Container gefunden."; exit 1
    fi
    echo "[Setup] --all: ${#_ALL_CONTAINERS[@]} laufende Container → je eine eigene Dashboard-Instanz"
else
    export ARTEX_CONTAINER
    echo "[Setup] Ziel-Container: $ARTEX_CONTAINER"

    # ── Prüfen ob Container läuft ────────────────────────────────────
    if ! docker inspect "$ARTEX_CONTAINER" --format '{{.State.Status}}' 2>/dev/null | grep -q "running"; then
        echo "⚠  Container '$ARTEX_CONTAINER' läuft nicht."
        echo "   Starte zuerst: bash start-intern.sh oder bash start-extern.sh"
        echo "   (oder wähle einen anderen Container mit --container <name> / --manuell)"
        exit 1
    fi
fi

# ── Container-Setup (als root, ggf. mit sudo) ────────────────────────
# Alles was im Container benötigt wird, einmalig sicherstellen.

_docker_setup() {
    local _target="${1:-$ARTEX_CONTAINER}"
    echo "[Setup] Überprüfe Container-Abhängigkeiten ($_target)..."

    # Alle Checks/Installs laufen als root (-u 0) und --privileged im Container:
    # das Skript läuft ohnehin nur über den Host, daher keine künstliche
    # Rechte-Beschränkung hier – sonst schlagen apt-get/iptables-Installs auf
    # Containern mit Non-Root-Default-User oder fehlendem NET_ADMIN leise fehl,
    # und das spätere Monitoring/Blocking funktioniert dann nicht.
    _dexec() { docker exec -u 0 --privileged "$_target" "$@"; }

    # python3 muss vorhanden sein (Monitor-Skript)
    if ! _dexec python3 --version &>/dev/null; then
        echo "[Setup] python3 fehlt – installiere..."
        _dexec sh -c 'apt-get update -qq && apt-get install -y -q python3' \
            || _dexec sh -c 'apk add -q python3' \
            || { echo "✗ python3 konnte nicht installiert werden"; exit 1; }
    fi

    # iptables für IP/Port-Sperren
    if ! _dexec which iptables &>/dev/null; then
        echo "[Setup] iptables fehlt – installiere..."
        _dexec sh -c \
            'apt-get update -qq 2>/dev/null && apt-get install -y -q iptables 2>/dev/null' \
            || _dexec sh -c 'apk add -q iptables 2>/dev/null' \
            || { echo "✗ iptables konnte nicht installiert werden"; exit 1; }
    fi
    # Funktionstest unabhängig davon ob gerade erst installiert
    if _dexec iptables -L OUTPUT -n &>/dev/null; then
        echo "[Setup] ✓ iptables funktionsfähig (IP/Port-Sperren verfügbar)"
    else
        echo "✗ iptables nicht funktionsfähig (NET_ADMIN fehlt?) – Sperren/Isolieren werden nicht funktionieren"
    fi

    # iproute2 für ss/ip (Netzwerk-Diagnose im Monitor, Isolations-Info)
    if ! _dexec which ss &>/dev/null; then
        echo "[Setup] iproute2 fehlt – installiere..."
        _dexec sh -c \
            'apt-get update -qq 2>/dev/null && apt-get install -y -q iproute2 2>/dev/null' \
            || _dexec sh -c 'apk add -q iproute2 2>/dev/null' \
            || true
    fi

    # conntrack (best effort) – räumt beim Sperren/Isolieren bereits etablierte
    # Verbindungen aus der Kernel-Conntrack-Tabelle, sonst bleibt eine laufende
    # Reverse Shell trotz DROP-Regel bis zum Timeout bestehen.
    if ! _dexec which conntrack &>/dev/null; then
        echo "[Setup] conntrack fehlt – installiere (optional)..."
        _dexec sh -c \
            'apt-get update -qq 2>/dev/null && apt-get install -y -q conntrack 2>/dev/null' \
            || _dexec sh -c 'apk add -q conntrack-tools 2>/dev/null' \
            || true
    fi

    # Raw-Socket-Fähigkeit (CAP_NET_RAW) – ohne die läuft der Sniffer-Thread
    # des Monitors nicht (DNS-Tunnel-/Paketinhalt-Erkennung fehlt dann).
    if _dexec python3 -c \
        'import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3).close()' \
        &>/dev/null; then
        echo "[Setup] ✓ Raw-Socket-Zugriff verfügbar (voller Monitor-Funktionsumfang)"
    else
        echo "⚠  Raw-Socket-Zugriff NICHT verfügbar – Monitor läuft im eingeschränkten Modus"
        echo "   (kein Packet-Sniffing: DNS-Tunnel-Inhalt/Beaconing-Details fehlen)"
    fi

    echo "[Setup] ✓ Container-Abhängigkeiten geprüft"
}

# Root-Prüfung: Setup-Schritte brauchen ggf. root (docker group oder root)
_run_setup() {
    if [[ "$ALL_MODE" -eq 1 ]]; then
        for _c in "${_ALL_CONTAINERS[@]}"; do _docker_setup "$_c"; done
    else
        _docker_setup
    fi
}
if [[ $EUID -ne 0 ]]; then
    # Wenn docker ohne sudo erreichbar ist, direkt ausführen
    if docker info &>/dev/null 2>&1; then
        _run_setup
    elif command -v sudo &>/dev/null; then
        echo "[Setup] Docker nicht ohne root erreichbar – re-starte mit sudo..."
        exec sudo -E bash "$0" "$@"
    else
        echo "✗ Kein Zugriff auf Docker. Als root starten oder zur docker-Gruppe hinzufügen."
        exit 1
    fi
else
    _run_setup
fi

# ── Bestehende Instanzen beenden ─────────────────────────────────────
echo "[Dashboard] Beende alte Instanzen..."

pkill -f "artex-monitor-dashboard.py" 2>/dev/null || true

if [[ "$ALL_MODE" -eq 1 ]]; then
    _PORTS=()
    for i in "${!_ALL_CONTAINERS[@]}"; do _PORTS+=($((9999 + i))); done
else
    _PORTS=(9999)
fi

for _p in "${_PORTS[@]}"; do
    if command -v fuser &>/dev/null; then
        fuser -k "${_p}/tcp" 2>/dev/null || true
    elif command -v lsof &>/dev/null; then
        lsof -ti:"${_p}" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    fi
done

if [[ "$ALL_MODE" -eq 1 ]]; then
    for _c in "${_ALL_CONTAINERS[@]}"; do
        docker exec "$_c" pkill -f "/tmp/artex-monitor.py" 2>/dev/null || true
    done
else
    docker exec "$ARTEX_CONTAINER" pkill -f "/tmp/artex-monitor.py" 2>/dev/null || true
fi

for _p in "${_PORTS[@]}"; do
    for i in 1 2 3 4 5; do
        if ! ss -tlnp 2>/dev/null | grep -q ":${_p} "; then break; fi
        sleep 1
    done
done

# ── Monitor-Skript in Container(n) kopieren ──────────────────────────
_copy_monitor_script() {
    local _target="$1"
    if [[ -f "$SCRIPT_DIR/artex-monitor.py" ]]; then
        docker cp "$SCRIPT_DIR/artex-monitor.py" "$_target:/tmp/artex-monitor.py" 2>/dev/null \
            && echo "[Dashboard] Monitor-Script aktualisiert ($_target)"
    fi
}

if [[ "$ALL_MODE" -eq 1 ]]; then
    for _c in "${_ALL_CONTAINERS[@]}"; do _copy_monitor_script "$_c"; done
else
    _copy_monitor_script "$ARTEX_CONTAINER"
fi

echo ""

# ── Dashboard(s) als normaler User starten (nicht als root) ─────────
# ARTEX_CONTAINER/ARTEX_PORT explizit mitgeben: sudo -u gibt ohne -E
# keine Env-Vars weiter.
_launch() {
    local _target="$1" _port="$2"
    if [[ $EUID -eq 0 && "$REAL_USER" != "root" ]]; then
        sudo -u "$REAL_USER" ARTEX_CONTAINER="$_target" ARTEX_PORT="$_port" \
            python3 "$SCRIPT_DIR/artex-monitor-dashboard.py" "${_PASSTHROUGH_ARGS[@]}" &
    else
        ARTEX_CONTAINER="$_target" ARTEX_PORT="$_port" \
            python3 "$SCRIPT_DIR/artex-monitor-dashboard.py" "${_PASSTHROUGH_ARGS[@]}" &
    fi
}

if [[ "$ALL_MODE" -eq 1 ]]; then
    _CHILD_PIDS=()
    for i in "${!_ALL_CONTAINERS[@]}"; do
        _c="${_ALL_CONTAINERS[$i]}"
        _p=$((9999 + i))
        echo "[Dashboard] $_c  →  http://localhost:$_p"
        _launch "$_c" "$_p"
        _CHILD_PIDS+=($!)
    done
    echo ""
    echo "[Dashboard] ${#_ALL_CONTAINERS[@]} Instanzen laufen. Strg+C beendet alle."
    echo ""
    trap 'echo; echo "[Dashboard] Beende alle Instanzen..."; kill "${_CHILD_PIDS[@]}" 2>/dev/null || true' EXIT INT TERM
    wait
else
    echo "[Dashboard] Dashboard startet auf http://localhost:9999"
    echo "[Dashboard] Strg+C zum Beenden"
    echo ""
    _launch "$ARTEX_CONTAINER" 9999
    _SINGLE_PID=$!
    trap 'kill "$_SINGLE_PID" 2>/dev/null || true' EXIT INT TERM
    wait "$_SINGLE_PID"
fi
