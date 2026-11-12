#!/usr/bin/env python3
"""
artex-monitor-dashboard.py  –  ARTEX Container Security Monitor Dashboard
=========================================================================
Startet den Monitor als Docker-Subprocess und streamt alle Events live
in ein Browser-Dashboard mit Tab-System.

Start:  python3 artex-monitor-dashboard.py
Browser: http://localhost:9999
"""

import subprocess, threading, json, re, time, os, copy, logging, logging.handlers
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from datetime import datetime
from collections import deque
import queue as _queue
import urllib.parse

# ── Konfiguration ──────────────────────────────────────────────────────
PORT           = int(os.environ.get('ARTEX_PORT', '9999'))
BIND_HOST      = '127.0.0.1'          # Nur lokal; für Netzwerk auf '0.0.0.0' ändern
CONTAINER      = os.environ.get('ARTEX_CONTAINER', 'artex-app')
MONITOR_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'artex-monitor.py')
MONITOR_DST    = '/tmp/artex-monitor.py'
MAX_HISTORY    = 500
MAX_SESSION_CMDS = 2000
RESTART_BACKOFF_MAX = 60   # Max Sekunden zwischen Neustartversuchen
LOG_FILE       = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'artex-monitor.log')

# ── File-Logging ────────────────────────────────────────────────────────
_log = logging.getLogger('artex')
_log.setLevel(logging.DEBUG)
_fh  = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=4, encoding='utf-8')
_fh.setFormatter(logging.Formatter('%(asctime)s  %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
_log.addHandler(_fh)
_log.propagate = False

def _logev(tag: str, data) -> None:
    try:
        # HTTP-Rauschen und Stats-Updates nicht im Log (zu viel Volumen)
        if tag == 'BROADCAST':
            t = data.get('type', '') if isinstance(data, dict) else ''
            sev = data.get('severity', '') if isinstance(data, dict) else ''
            if t == 'stats':
                return
            if sev == 'HTTP':
                return
        _log.info(f"{tag}  {json.dumps(data, ensure_ascii=False) if not isinstance(data, str) else data}")
    except Exception:
        pass

# ── ANSI-Strip ─────────────────────────────────────────────────────────
# Erfasst SGR (Farben), Cursor-Bewegungen, Zeilen-Löschungen
ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b[()][AB012]|\x1b[MABC]')

def strip_ansi(s: str) -> str:
    return ANSI_RE.sub('', s)

# ── Event-Parsing ──────────────────────────────────────────────────────
ALERT_RE       = re.compile(r'\[(\d{2}:\d{2}:\d{2})\]\s+\[(\w+)\s*\]\s+(.*)')
DETAIL_RE      = re.compile(r'^\s+[↳→←]\s*(.*)')
SESSION_CMD_RE = re.compile(
    r'\[(\d{2}:\d{2}:\d{2})\]\s+\[SESSION\]\s+(?:PID=(\d+|\?)\s+)?(.+?)\s+([\d.]+:\d+)\s+(.*)')
BANNER_RE      = re.compile(r'^[║╔╠╚╗╝═─\s⚠⚡📡⚙]+$')
REMOTE_RE      = re.compile(r'Remote\s*:\s*([\d.]+:\d+)')
LOGFILE_RE     = re.compile(r'tail\s+-f\s+(\S+)')
SESSION_END_RE = re.compile(r'TUNNEL SESSION BEENDET.*?←\s*([\d.]+:\d+)')

def parse_line(line: str) -> dict | None:
    line = strip_ansi(line).rstrip()
    if not line or BANNER_RE.match(line):
        return None

    m = SESSION_CMD_RE.match(line)
    if m:
        return {'type': 'session_cmd', 'ts': m.group(1),
                'pid': None if m.group(2) in (None, '?') else m.group(2),
                'direction': m.group(3).strip(),
                'remote': m.group(4), 'data': m.group(5).strip()}

    m = ALERT_RE.match(line)
    if m:
        return {'type': 'alert', 'ts': m.group(1),
                'severity': m.group(2).strip(), 'message': m.group(3).strip(), 'detail': ''}

    m = DETAIL_RE.match(line)
    if m:
        return {'type': 'detail', 'detail': m.group(1).strip()}

    m = REMOTE_RE.search(line)
    if m:
        return {'type': 'session_open_banner', 'remote': m.group(1)}

    m = LOGFILE_RE.search(line)
    if m:
        return {'type': 'session_logfile_banner', 'logfile': m.group(1)}

    m = SESSION_END_RE.search(line)
    if m:
        return {'type': 'session_end', 'remote': m.group(1)}

    return None

# ── Globaler State (alle Zugriffe unter _state_lock) ───────────────────
_state_lock  = threading.Lock()
event_history: deque = deque(maxlen=MAX_HISTORY)
sse_clients: list    = []
stats        = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0, 'SESSION': 0, 'HTTP': 0}
sessions     = {}   # remote → {started, ended, cmds, logfile}
monitor_status = {'running': False, 'started': None, 'privileged': False}
autokill_enabled = False   # Autokill: alle erkannten Reverse-Shell-PIDs sofort beenden
auto_neutralize  = False   # Auto-Neutralize: Rootkits automatisch entfernen
_rootkit_correlations: dict = {}  # rk_id → [session remotes]
_pending_implant_pids: set  = set()  # implant PIDs ohne Session – warten auf NEUE VERBINDUNG
_pending_implant_names: set = set()  # getarnte Prozessnamen (z.B. sd-pam) – deckt den Fall ab
                                      # dass der Implant-Alert eine ANDERE PID meldet als die,
                                      # die den eigentlichen TCP-Socket hält (Loader/Watchdog-Paar)
_event_id    = 0
_active_blocks: dict = {}  # key: 'ip:1.2.3.4' oder 'port:53' → True
_blocks_lock = threading.Lock()
_network_isolated: bool = False   # True solange iptables OUTPUT-Policy auf DROP steht

def _next_id() -> int:
    global _event_id
    _event_id += 1
    return _event_id

# ── Broadcast (MUSS außerhalb von _state_lock aufgerufen werden) ────────
def _container_ts() -> str:
    """Gibt die aktuelle Uhrzeit aus dem Container zurück (vermeidet UTC/Host-Versatz)."""
    try:
        r = subprocess.run(
            ['docker', 'exec', CONTAINER, 'date', '+%H:%M:%S'],
            capture_output=True, text=True, timeout=3
        )
        ts = r.stdout.strip()
        if re.match(r'^\d{2}:\d{2}:\d{2}$', ts):
            return ts
    except Exception:
        pass
    return datetime.now().strftime('%H:%M:%S')  # Fallback auf Host-Zeit


def _socket_pid_map() -> dict:
    """Liefert ESTABLISHED Remote-Endpunkte und ihre aktuellen Besitzer-PIDs."""
    probe = r'''
import json, os, re, socket
inode_remote = {}
with open('/proc/net/tcp') as f:
    for line in list(f)[1:]:
        p = line.split()
        if len(p) < 10 or p[3] != '01':
            continue
        rh, rp = p[2].split(':')
        remote = socket.inet_ntoa(bytes.fromhex(rh)[::-1]) + ':' + str(int(rp, 16))
        inode_remote[p[9]] = remote
out = {}
for pid in os.listdir('/proc'):
    if not pid.isdigit():
        continue
    try:
        for fd in os.listdir('/proc/' + pid + '/fd'):
            link = os.readlink('/proc/' + pid + '/fd/' + fd)
            m = re.fullmatch(r'socket:\[(\d+)\]', link)
            if m and m.group(1) in inode_remote:
                out.setdefault(inode_remote[m.group(1)], set()).add(int(pid))
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
print(json.dumps({remote: sorted(pids) for remote, pids in out.items()}))
'''
    r = subprocess.run(
        ['docker', 'exec', CONTAINER, 'python3', '-c', probe],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or 'Socket/PID-Prüfung fehlgeschlagen')
    raw = json.loads(r.stdout or '{}')
    return {remote: [str(pid) for pid in pids] for remote, pids in raw.items()}


def _implant_pid_remote(pid: str) -> str | None:
    """Findet den ESTABLISHED TCP-Remote-Endpunkt für eine gegebene PID
    oder deren direkte Kindprozesse (Watchdog → Worker / Loader → Shell)."""
    probe = r'''
import json, os, re, socket, sys
target_pid = sys.argv[1]
inode_remote = {}
for path in ('/proc/net/tcp', '/proc/net/tcp6'):
    try:
        with open(path) as f:
            for line in list(f)[1:]:
                p = line.split()
                if len(p) < 10 or p[3] != '01':
                    continue
                rh, rp = p[2].split(':')
                try:
                    if len(rh) == 8:
                        remote = socket.inet_ntoa(bytes.fromhex(rh)[::-1]) + ':' + str(int(rp, 16))
                        inode_remote[p[9]] = remote
                except Exception:
                    pass
    except FileNotFoundError:
        pass

def pid_remote(p):
    try:
        for fd in os.listdir('/proc/' + p + '/fd'):
            try:
                link = os.readlink('/proc/' + p + '/fd/' + fd)
                m = re.fullmatch(r'socket:\[(\d+)\]', link)
                if m and m.group(1) in inode_remote:
                    return inode_remote[m.group(1)]
            except (FileNotFoundError, PermissionError, OSError):
                pass
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return None

result = pid_remote(target_pid)
if not result:
    # Kindprozesse prüfen (Loader → bash -i, Watchdog → Worker)
    try:
        for child in os.listdir('/proc'):
            if not child.isdigit():
                continue
            try:
                with open('/proc/' + child + '/status') as f:
                    for line in f:
                        if line.startswith('PPid:') and line.split()[1] == target_pid:
                            result = pid_remote(child)
                            break
            except (FileNotFoundError, OSError):
                pass
            if result:
                break
    except (FileNotFoundError, OSError):
        pass
print(json.dumps(result))
'''
    try:
        r = subprocess.run(
            ['docker', 'exec', CONTAINER, 'python3', '-c', probe, str(pid)],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0 and r.stdout.strip():
            return json.loads(r.stdout.strip()) or None
    except Exception:
        pass
    return None


def _udp_local_owners(local_port: int | str) -> list[str]:
    """Liefert nur Prozesse, die aktuell den angegebenen UDP-Port besitzen."""
    probe = r'''
import json, os, re, sys
port = int(sys.argv[1])
inodes = set()
with open('/proc/net/udp') as f:
    for line in list(f)[1:]:
        p = line.split()
        if len(p) < 10:
            continue
        _ip, lp = p[1].split(':')
        if int(lp, 16) == port:
            inodes.add(p[9])
owners = set()
for pid in os.listdir('/proc'):
    if not pid.isdigit():
        continue
    try:
        for fd in os.listdir('/proc/' + pid + '/fd'):
            m = re.fullmatch(r'socket:\[(\d+)\]', os.readlink('/proc/' + pid + '/fd/' + fd))
            if m and m.group(1) in inodes:
                owners.add(int(pid))
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
print(json.dumps(sorted(owners)))
'''
    r = subprocess.run(
        ['docker', 'exec', CONTAINER, 'python3', '-c', probe, str(local_port)],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or 'UDP-PID-Prüfung fehlgeschlagen')
    return [str(pid) for pid in json.loads(r.stdout or '[]')]


def _udp_remote_owners(remote_ip: str, remote_port: int | str) -> list[str]:
    """Findet Prozesse mit connected UDP-Socket zur angegebenen Remote-IP:Port.
    Fallback für DNS-Shells die keinen dauerhaften local-Port haben."""
    probe = r'''
import json, os, re, socket, sys
rip, rport = sys.argv[1], int(sys.argv[2])
try:
    rem_hex = socket.inet_aton(rip).hex().upper()
    # little-endian: bytes umkehren
    rem_hex = ''.join(reversed([rem_hex[i:i+2] for i in range(0,8,2)]))
    rport_hex = format(rport, '04X')
except Exception:
    print('[]'); sys.exit(0)
inodes = set()
for f in ('/proc/net/udp', '/proc/net/udp6'):
    try:
        with open(f) as fh:
            for line in list(fh)[1:]:
                p = line.split()
                if len(p) < 10: continue
                rem = p[2]  # format: XXXXXXXX:PPPP
                if rem == rem_hex + ':' + rport_hex:
                    inodes.add(p[9])
    except FileNotFoundError:
        pass
owners = set()
for pid in os.listdir('/proc'):
    if not pid.isdigit(): continue
    try:
        for fd in os.listdir('/proc/' + pid + '/fd'):
            m = re.fullmatch(r'socket:\[(\d+)\]', os.readlink('/proc/' + pid + '/fd/' + fd))
            if m and m.group(1) in inodes:
                owners.add(int(pid))
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
print(json.dumps(sorted(owners)))
'''
    r = subprocess.run(
        ['docker', 'exec', CONTAINER, 'python3', '-c', probe,
         str(remote_ip), str(remote_port)],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or 'UDP-Remote-PID-Prüfung fehlgeschlagen')
    return [str(pid) for pid in json.loads(r.stdout or '[]')]


def _udp_cmdline_scan() -> list[str]:
    """Sucht Prozesse deren Cmdline auf DNS-Tunnel-Tools hindeutet.
    Letzter Ausweg wenn kein Socket-Lookup greift."""
    probe = r'''
import json, os, re
shell_re = re.compile(
    r'\b(?:dnscat|iodine|dns2tcp|dns[-_]?shell|heyoka|dnsx|chisel|sliver|mettle)\b|'
    r'(?:^|/)(?:ba)?sh\s+-i\b|'
    r'^\[(?:kworker|ksoftirqd|migration|rcu)[^]]*\]',
    re.I)
hits = []
for pid in os.listdir('/proc'):
    if not pid.isdigit(): continue
    try:
        with open('/proc/' + pid + '/cmdline', 'rb') as f:
            cmd = f.read().replace(b'\x00', b' ').decode(errors='replace').strip()
        if shell_re.search(cmd):
            hits.append(int(pid))
    except Exception:
        pass
print(json.dumps(sorted(hits)))
'''
    r = subprocess.run(
        ['docker', 'exec', CONTAINER, 'python3', '-c', probe],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or 'Cmdline-Scan fehlgeschlagen')
    return [str(pid) for pid in json.loads(r.stdout or '[]')]


def _do_kill(remote: str, pid: str | None = None,
             udp_local_port: int | str | None = None) -> dict:
    """Beendet nur PIDs, die den Remote-Socket aktuell wirklich besitzen.
    Für UDP/DNS-Sessions ohne dauerhaften Socket: Kill direkt per gespeicherter PID."""
    try:
        if udp_local_port:
            owners = _udp_local_owners(udp_local_port)
            if not owners:
                # Ephemerer local-Port weg → per Remote-IP suchen
                parts = remote.rsplit(':', 1)
                if len(parts) == 2:
                    try:
                        owners = _udp_remote_owners(parts[0], parts[1])
                    except Exception:
                        pass
            # Letzter Ausweg: gespeicherte PID direkt nutzen (DNS-Shells ohne Persistent-Socket)
            if not owners and pid and pid != '?':
                owners = [pid]
        else:
            owners = _socket_pid_map().get(remote, [])
            # Fallback: gespeicherte PID nutzen wenn kein aktiver Socket
            # (C2-Beacons nutzen kurzlebige Verbindungen — Socket oft schon zu)
            if not owners and pid and pid != '?':
                owners = [pid]
        if not owners:
            return {'ok': True, 'pid': str(pid or '?'), 'pids': [], 'results': [],
                    'outcome': 'already_closed', 'msg': 'Verbindung bereits beendet'}

        results = []
        for owner in owners:
            # Erst Process Group killen (tötet auch Kind-Prozesse wie spawnte Bash-Shells)
            subprocess.run(
                ['docker', 'exec', CONTAINER, 'sh', '-c',
                 f'kill -9 -{owner} 2>/dev/null; kill -9 {owner} 2>/dev/null'],
                capture_output=True, text=True, timeout=5
            )
            results.append({'pid': owner, 'ok': True, 'msg': ''})

        # Bestätigung: für UDP/DNS prüfen ob PID noch existiert (kein persistenter Socket)
        time.sleep(0.1)
        remaining = []
        for attempt in range(5):
            if udp_local_port:
                # UDP: prüfen ob einer der gek. PIDs noch lebt
                still_alive = []
                for owner in owners:
                    r2 = subprocess.run(
                        ['docker', 'exec', CONTAINER, 'kill', '-0', owner],
                        capture_output=True, text=True, timeout=3
                    )
                    if r2.returncode == 0:
                        still_alive.append(owner)
                remaining = still_alive
            else:
                remaining = _socket_pid_map().get(remote, [])
            if not remaining:
                break
            if attempt < 4:
                time.sleep(0.05)
        ok = not remaining
        return {
            'ok': ok,
            'pid': str(pid or owners[-1]),
            'pids': owners,
            'remaining': remaining,
            'results': results,
            'outcome': 'killed' if ok else 'still_active',
            'msg': '' if ok else f'Verbindung weiterhin aktiv (PID {", ".join(remaining)})',
        }
    except Exception as e:
        return {'ok': False, 'pid': str(pid or '?'), 'pids': [], 'results': [],
                'outcome': 'probe_failed', 'msg': str(e)}


_IP_RE   = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
_PORT_RE = re.compile(r'^\d{1,5}$')

def _validate_block_input(btype: str, value: str) -> str | None:
    """Gibt Fehlermeldung zurück oder None wenn OK."""
    if btype == 'ip':
        if not _IP_RE.match(value):
            return 'Ungültige IP-Adresse'
        parts = value.split('.')
        if not all(0 <= int(p) <= 255 for p in parts):
            return 'IP-Oktett außerhalb 0–255'
    elif btype == 'port':
        if not _PORT_RE.match(value) or not (1 <= int(value) <= 65535):
            return 'Ungültiger Port (1–65535)'
    else:
        return 'Unbekannter Block-Typ (nur ip oder port erlaubt)'
    return None


def _run_iptables(args: list[str]) -> bool:
    """Führt iptables mit --privileged im Container aus. Gibt True bei Erfolg."""
    r = subprocess.run(
        ['docker', 'exec', '--privileged', CONTAINER, 'iptables'] + args,
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0:
        print(f'[Block] iptables Fehler: {r.stderr.strip()}', flush=True)
    return r.returncode == 0


def _block_rules(btype: str, value: str) -> list[tuple[str, list[str]]]:
    """Liefert (Kette, Match-Argumente)-Paare für eine Sperre.

    BEIDE Richtungen sind nötig: OUTPUT allein kappt nur die Antworten des
    Containers – die eingehenden Befehle des Angreifers passieren weiter die
    INPUT-Kette und werden von der Shell ausgeführt (nur die Ausgabe fehlt).
    Erst INPUT-DROP stoppt die Befehlsausführung tatsächlich.
    'value' ist beim Port der Remote-Port des Angreifers: ausgehend --dport,
    eingehend --sport.
    """
    if btype == 'ip':
        return [
            ('OUTPUT', ['-d', value]),   # Antworten an den Angreifer
            ('INPUT',  ['-s', value]),   # Befehle vom Angreifer
        ]
    # port
    return [
        ('OUTPUT', ['-p', 'tcp', '--dport', value]),
        ('OUTPUT', ['-p', 'udp', '--dport', value]),
        ('INPUT',  ['-p', 'tcp', '--sport', value]),
        ('INPUT',  ['-p', 'udp', '--sport', value]),
    ]


def _apply_block(btype: str, value: str) -> dict:
    """Setzt iptables DROP-Regeln (INPUT + OUTPUT) im Container.
    Blockiert damit eingehende Befehle UND ausgehende Antworten."""
    err = _validate_block_input(btype, value)
    if err:
        return {'ok': False, 'msg': err}
    try:
        ok = True
        for chain, match in _block_rules(btype, value):
            ok &= _run_iptables(['-I', chain, '1'] + match + ['-j', 'DROP'])
        if not ok:
            return {'ok': False, 'msg': 'iptables fehlgeschlagen – iptables im Container installiert?'}
        # Bestehende TCP-Verbindung aus der Conntrack-Tabelle werfen, damit die
        # bereits offene Shell-Verbindung sofort stirbt statt in Timeout zu laufen.
        _drop_conntrack(btype, value)
        with _blocks_lock:
            _active_blocks[f'{btype}:{value}'] = True
        broadcast({'type': 'block_state', 'blocks': dict(_active_blocks)})
        return {'ok': True}
    except Exception as e:
        return {'ok': False, 'msg': str(e)}


def _apply_unblock(btype: str, value: str) -> dict:
    """Entfernt die INPUT- und OUTPUT-DROP-Regeln wieder."""
    err = _validate_block_input(btype, value)
    if err:
        return {'ok': False, 'msg': err}
    try:
        for chain, match in _block_rules(btype, value):
            _run_iptables(['-D', chain] + match + ['-j', 'DROP'])
        with _blocks_lock:
            _active_blocks.pop(f'{btype}:{value}', None)
        broadcast({'type': 'block_state', 'blocks': dict(_active_blocks)})
        return {'ok': True}
    except Exception as e:
        return {'ok': False, 'msg': str(e)}


def _drop_conntrack(btype: str, value: str) -> None:
    """Löscht passende Einträge aus der Conntrack-Tabelle (best effort).
    Ohne das bleibt eine bereits etablierte TCP-Session im Kernel bestehen,
    bis sie in Timeout läuft. conntrack fehlt evtl. – dann einfach überspringen."""
    try:
        if btype == 'ip':
            _exec_in_container(f'conntrack -D -d {value} 2>/dev/null; '
                               f'conntrack -D -s {value} 2>/dev/null; true')
        else:
            _exec_in_container(f'conntrack -D -p tcp --dport {value} 2>/dev/null; '
                               f'conntrack -D -p tcp --sport {value} 2>/dev/null; true')
    except Exception:
        pass


def _exec_in_container(cmd: str) -> tuple[bool, str]:
    """Fuehrt einen Shell-Befehl im Container mit root aus."""
    r = subprocess.run(
        ['docker', 'exec', '--privileged', CONTAINER, 'sh', '-c', cmd],
        capture_output=True, text=True, timeout=10
    )
    out = (r.stdout + r.stderr).strip()
    return r.returncode == 0, out


# Bei der Isolierung ausgenommenes Netz (Docker-intern: DB, Proxy) + Loopback.
ISOLATION_ALLOW_NET = '172.16.0.0/12'


def _isolation_info() -> dict:
    """Liefert Container-Adresse, das ausgenommene Netz und den aktuellen Isolierungs-Zustand."""
    ok, out = _exec_in_container(
        "ip -4 -o addr show scope global 2>/dev/null "
        "| awk '{print $2\" \"$4}' | head -3")
    return {
        'allow':    ISOLATION_ALLOW_NET,
        'blocked':  f'alle Ziele ausser {ISOLATION_ALLOW_NET} und lo',
        'ifaces':   out if ok and out else '',
        'isolated': _network_isolated,
    }


def _apply_countermeasure(action: str, param: str = '') -> dict:
    """Fuehrt eine Rootkit-Gegenmassnahme im Container aus."""
    global _network_isolated
    param = param.strip()
    if action == 'clear_ldpreload':
        ok, out = _exec_in_container('cat /etc/ld.so.preload; echo "" > /etc/ld.so.preload')
        broadcast({'type': 'countermeasure', 'action': action, 'ok': ok, 'detail': out})
        return {'ok': ok, 'msg': f'ld.so.preload geleert. War: {out[:200]}' if ok else out}

    elif action == 'clean_tmp_so':
        ok, out = _exec_in_container(
            'find /tmp /dev/shm -maxdepth 1 \\( -name "*.so" -o -name "*.ko" \\) '
            '-exec ls -la {} \\; -exec rm -f {} \\; 2>&1 | head -40'
        )
        broadcast({'type': 'countermeasure', 'action': action, 'ok': ok, 'detail': out})
        return {'ok': ok, 'msg': out or 'Keine .so/.ko Dateien gefunden' if ok else out}

    elif action == 'kill_pid':
        if not param.isdigit():
            return {'ok': False, 'msg': 'Ungueltige PID'}
        ok, out = _exec_in_container(f'kill -9 {param} 2>&1; echo "Exit: $?"')
        broadcast({'type': 'countermeasure', 'action': action, 'ok': ok,
                   'param': param, 'detail': f'PID {param}: {out}'})
        if ok:
            # Implant-Banner fuer diese PID bei ALLEN verbundenen Clients
            # entfernen (nicht nur beim Client der den Kill ausgelöst hat).
            broadcast({'type': 'implant_cleared', 'pid': param})
        return {'ok': ok, 'msg': f'PID {param}: {out}'}

    elif action == 'rmmod':
        # Nur einfache Modulnamen zulassen (kein Pfad, kein Sonderzeichen)
        if not re.match(r'^[a-zA-Z0-9_-]{1,64}$', param):
            return {'ok': False, 'msg': 'Ungültiger Modulname'}
        ok, out = _exec_in_container(f'rmmod {param} 2>&1')
        broadcast({'type': 'countermeasure', 'action': action, 'ok': ok,
                   'param': param, 'detail': out})
        return {'ok': ok, 'msg': out or 'Modul entfernt'}

    elif action == 'remove_rootkit':
        # 1. Was ist in ld.so.preload?
        _, preload = _exec_in_container('cat /etc/ld.so.preload 2>/dev/null')
        ref_file = param.strip() if param else preload.strip().splitlines()[0] if preload.strip() else ''
        # 2. ld.so.preload leeren
        _exec_in_container('echo "" > /etc/ld.so.preload')
        # 3. Spezifische Datei löschen wenn angegeben und sicher (kein Path-Traversal)
        if ref_file and re.match(r'^[/a-zA-Z0-9_.@-]+$', ref_file):
            _exec_in_container(f'rm -f "{ref_file}" 2>/dev/null')
        # 4. Alle .so/.ko aus /tmp und /dev/shm löschen
        _, cleaned = _exec_in_container(
            'find /tmp /dev/shm -maxdepth 1 \\( -name "*.so" -o -name "*.ko" \\) '
            '-exec rm -f {} \\; 2>&1 | head -20')
        fname = ref_file.split('/')[-1] if ref_file else '?'
        broadcast({'type': 'rootkit_cleared', 'file': fname})
        return {'ok': True, 'msg': f'Rootkit {fname} entfernt. ld.so.preload geleert. Cleaned: {cleaned or "–"}'}

    elif action == 'isolate_network':
        cmds = (
            f'iptables -P OUTPUT DROP; '
            f'iptables -A OUTPUT -d {ISOLATION_ALLOW_NET} -j ACCEPT; '
            f'iptables -A OUTPUT -o lo -j ACCEPT'
        )
        ok, out = _exec_in_container(cmds)
        if ok:
            _network_isolated = True
        ni = _isolation_info()
        broadcast({'type': 'countermeasure', 'action': action, 'ok': ok,
                   'param': '', 'detail': out,
                   'isolated': _network_isolated, 'network': ni})
        return {'ok': ok, 'msg': 'Container netzwerk-isoliert' if ok else out,
                'network': ni}

    elif action == 'restore_network':
        ok, out = _exec_in_container('iptables -P OUTPUT ACCEPT; iptables -F OUTPUT')
        if ok:
            _network_isolated = False
        ni = _isolation_info()
        broadcast({'type': 'countermeasure', 'action': action, 'ok': ok,
                   'param': '', 'detail': out,
                   'isolated': _network_isolated, 'network': ni})
        return {'ok': ok, 'msg': 'Netzwerk-Regeln zurueckgesetzt' if ok else out,
                'network': ni}

    elif action == 'remove_file':
        # Persistence-Datei entfernen – nur einfache Pfade ohne Traversal erlaubt
        if not param or not re.match(r'^[/a-zA-Z0-9_.@\-]+$', param):
            return {'ok': False, 'msg': 'Ungültiger Pfad'}
        # Nur in bekannten Persistence-Verzeichnissen erlaubt
        allowed_prefixes = (
            '/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.hourly/',
            '/etc/cron.weekly/', '/etc/cron.monthly/',
            '/var/spool/cron/crontabs/',
            '/etc/systemd/system/', '/etc/init.d/', '/etc/profile.d/',
        )
        if not any(param.startswith(p) for p in allowed_prefixes):
            return {'ok': False, 'msg': 'Pfad nicht in erlaubten Persistence-Verzeichnissen'}
        ok, out = _exec_in_container(f'rm -f {param} 2>&1; echo "Exit: $?"')
        broadcast({'type': 'countermeasure', 'action': action, 'ok': ok,
                   'param': param, 'detail': f'{param}: {out}'})
        return {'ok': ok, 'msg': f'{param} entfernt' if ok else out}

    elif action == 'remove_suid':
        # SUID-Bit von einer Binary entfernen
        if not param or not re.match(r'^[/a-zA-Z0-9_.@\-]+$', param):
            return {'ok': False, 'msg': 'Ungültiger Pfad'}
        ok, out = _exec_in_container(f'chmod u-s {param} 2>&1; ls -la {param} 2>&1')
        broadcast({'type': 'countermeasure', 'action': action, 'ok': ok,
                   'param': param, 'detail': f'{param}: {out}'})
        return {'ok': ok, 'msg': f'SUID-Bit entfernt: {out[:100]}' if ok else out}

    elif action == 'show_file':
        # Inhalt einer Datei zur Inspektion anzeigen – schreibgeschützt
        if not param or not re.match(r'^[/a-zA-Z0-9_.@\-]+$', param):
            return {'ok': False, 'msg': 'Ungültiger Pfad'}
        ok, out = _exec_in_container(f'head -50 {param} 2>&1')
        return {'ok': ok, 'msg': out[:500] if ok else out}

    return {'ok': False, 'msg': f'Unbekannte Aktion: {action}'}


# Event-Typen die nach F5 korrekt replayed werden müssen (UI-State-Events)
_HISTORY_REPLAY_TYPES = frozenset({
    'rootkit_cleared', 'auto_neutralize_applied', 'rootkit_correlation', 'countermeasure',
    'implant_correlation', 'implant_cleared'
})

def broadcast(payload: dict) -> None:
    """Sendet ein Event an alle verbundenen SSE-Clients."""
    _logev('BROADCAST', payload)
    # Bestimmte UI-State-Events in History speichern damit sie nach F5 replayed werden
    if payload.get('type') in _HISTORY_REPLAY_TYPES:
        with _state_lock:
            event_history.append(copy.copy(payload))
    msg = ('data: ' + json.dumps(payload, ensure_ascii=False) + '\n\n').encode()
    dead = []
    with _state_lock:
        clients = list(sse_clients)
    for q in clients:
        try:
            q.put_nowait(msg)
        except _queue.Full:
            dead.append(q)
        except Exception:
            dead.append(q)
    if dead:
        with _state_lock:
            for q in dead:
                if q in sse_clients:
                    sse_clients.remove(q)

# ── Event-Processing ────────────────────────────────────────────────────
def _build_implant_correlation(ev: dict, sessions: dict, anc_pids=None) -> dict | None:
    """Baut ein implant_correlation-Event aus einem IMPLANT-Alert.
    PID/Name/Rolle stammen primär aus der MELDUNG (race-sicher), das Detail
    dient nur als Rückfallebene. anc_pids ist die Prozess-Abstammung des
    Implants für die Session-Zuordnung. Muss unter _state_lock laufen."""
    msg = ev.get('message', '')
    detail_str = ev.get('detail', '') or ''
    pid_m  = re.search(r'PID=(\d+)', msg) or re.search(r'PID=(\d+)', detail_str)
    role_m = re.search(r'\[(WATCHDOG|WORKER|IMPLANT)\]', msg)
    # Name: in der Meldung steht er nach der PID (z.B. "PID=123 kworker/0:1H"),
    # im Detail als "name=...".
    name_m = re.search(r'PID=\d+\s+(\S+)', msg) or re.search(r'name=(\S+)', detail_str)
    impl_pid = pid_m.group(1) if pid_m else ''

    # Session-Zuordnung über die Prozess-Abstammung: Das Implant gehört zu der
    # Session, aus deren Shell es (direkt oder indirekt) gestartet wurde. 'anc'
    # ist pid + ppid-Kette des Implants; eine Session passt, wenn eine ihrer
    # Shell-PIDs darin vorkommt. Ohne Abstammungsinfo ODER ohne Treffer fällt
    # es konservativ auf alle Sessions zurück (Herkunft unbekannt → überall
    # warnen, damit ein aktives Implant nicht übersehen wird).
    anc = set(anc_pids or ())
    if impl_pid:
        anc.add(impl_pid)
    matched = []
    if anc:
        for r, s in sessions.items():
            spids = {str(p) for p in (s.get('pids') or []) if p}
            if s.get('pid'):
                spids.add(str(s.get('pid')))
            if spids & anc:
                matched.append((r, s))
    src = matched if matched else list(sessions.items())
    all_sess = [
        {'remote': r, 'started': s.get('started', ''), 'pid': s.get('pid'),
         'ended': s.get('ended')}
        for r, s in src
    ]
    return {
        'type': 'implant_correlation',
        'impl_id': ev.get('id'),
        'impl_msg': msg,
        'detail': detail_str,
        'pid': pid_m.group(1) if pid_m else '',
        'role': role_m.group(1) if role_m else 'IMPLANT',
        'name': name_m.group(1) if name_m else '',
        'sessions': all_sess,
        'ts': ev.get('ts', ''),
    }


def process_event(ev: dict) -> None:
    """State aktualisieren; alle Broadcasts AUSSERHALB des Locks."""
    if not ev:
        return

    to_broadcast = []
    _should_auto_neutralize = False
    _rk_param = ''
    _impl_kill_pid = ''
    _implant_no_session_pid = ''  # gesetzt wenn IMPLANT ohne passende aktive Session

    with _state_lock:
        t = ev['type']

        if t == 'alert':
            sev = ev.get('severity', 'INFO')
            msg = ev.get('message', '')

            # IMPLANT: Abstammungskette (anc=...) aus der Meldung lösen – sie
            # dient nur der Session-Zuordnung, nicht der Anzeige. Hier entfernen,
            # BEVOR die Meldung in History/Broadcast geht, damit der Titel sauber
            # bleibt.
            _impl_anc: set = set()
            if 'IMPLANT' in msg:
                _anc_m = re.search(r'\s+anc=([\d,]+)', msg)
                if _anc_m:
                    _impl_anc = {p for p in _anc_m.group(1).split(',') if p}
                    msg = msg[:_anc_m.start()] + msg[_anc_m.end():]
                    ev['message'] = msg

            # HTTP-Pentest-Traffic → eigene 'HTTP' Kategorie (nicht CRITICAL/HIGH)
            # Nur echte Security-Events bleiben auf ihrem ursprünglichen Severity
            _HTTP_PATTERNS = ('TUNNEL HTTP ', 'TUNNEL REQUEST ', 'TUNNEL INHALT ',
                              'TUNNEL INTERESSANT ')
            _KEEP_CRITICAL = ('TUNNEL SENSITIVE', 'TUNNEL SHELL', 'TUNNEL CMD-MARKER',
                              'TUNNEL VERDÄCHTIG')

            # Neue Verbindung / Beaconing zu Web-Ports → HTTP (normaler Pentest)
            _web_ports_re = re.compile(r'(?:→\s+|zu\s+)[\d.]+:(80|443|8080|8443|8000|8888|1992)[\s(]')
            if ('NEUE VERBINDUNG' in msg or 'BEACONING' in msg) and _web_ports_re.search(msg):
                sev = 'HTTP'
                ev['severity'] = 'HTTP'

            # TUNNEL CREDENTIALS: Port-basierte Unterscheidung
            # HTTP-Ports (Pentest-Traffic) → HTTP Kategorie
            # C2/Shell-Ports → bleibt CRITICAL
            if 'TUNNEL CREDENTIALS' in msg:
                _port_m = re.search(r'[\d.]+:(\d+)', msg)
                if _port_m:
                    _port = int(_port_m.group(1))
                    _web_ports = {80, 443, 8080, 8443, 8000, 8888, 8008, 3000, 4200, 5000, 1992}
                    _c2_ports  = {4444, 4445, 5555, 9001, 9002, 31337, 1337, 6666, 6667, 1234}
                    if _port in _web_ports and _port not in _c2_ports:
                        sev = 'HTTP'
                        ev['severity'] = 'HTTP'
                        ev['detail'] = (ev.get('detail') or '') + ' [Pentest HTTP-Auth]'
                    # else: unbekannter Port oder C2-Port → bleibt CRITICAL

            if any(p in msg for p in _HTTP_PATTERNS) and not any(k in msg for k in _KEEP_CRITICAL):
                sev = 'HTTP'
                ev['severity'] = 'HTTP'
            stats[sev] = stats.get(sev, 0) + 1
            ev['id'] = _next_id()
            event_history.append(ev)
            to_broadcast.append(copy.copy(ev))
            to_broadcast.append({'type': 'stats', 'stats': copy.copy(stats),
                                  'sessions': len(sessions)})

            # ROOTKIT-Alert → Korrelation mit aktiven Sessions erfassen
            if 'ROOTKIT' in msg:
                _active_sess = [
                    {'remote': r, 'started': s.get('started', ''), 'pid': s.get('pid')}
                    for r, s in sessions.items() if not s.get('ended')
                ]
                _rk_param = ev.get('detail', '') or ''
                _should_auto_neutralize = auto_neutralize
                if _active_sess:
                    _corr_ev = {
                        'type': 'rootkit_correlation', 'rk_id': ev.get('id'),
                        'rk_msg': msg, 'detail': ev.get('detail', '') or '',
                        'sessions': _active_sess, 'ts': ev.get('ts', '')
                    }
                    to_broadcast.append(_corr_ev)
                    _rootkit_correlations[ev.get('id', 0)] = [s['remote'] for s in _active_sess]

            # IMPLANT-Alert → Korrelation mit der ursächlichen Session (über die
            # Abstammung _impl_anc). PID/Name stehen in der Meldung, daher sofort
            # beim Alert korrelieren.
            if 'IMPLANT' in msg:
                _impl_ev = _build_implant_correlation(ev, sessions, _impl_anc)
                if _impl_ev:
                    to_broadcast.append(_impl_ev)
                # Auto-Entfernen deckt neben dem LD_PRELOAD-Rootkit auch die
                # dazugehörigen Implant-Prozesse ab (Fake-kworker, DNS-Tunnel-
                # Owner, laufende gelöschte Binaries) – sonst bleibt der
                # Watchdog/Worker nach dem Entfernen der Rootkit-Datei aktiv.
                if auto_neutralize and _impl_ev and _impl_ev.get('pid'):
                    _impl_kill_pid = _impl_ev['pid']
                # Wenn keine aktive Session bekannt ist (TUNNEL SESSION AKTIV
                # wurde verpasst oder nie gesendet), PID für Socket-Lookup merken.
                if _impl_ev and _impl_ev.get('pid'):
                    _active_in_ev = [s for s in _impl_ev.get('sessions', [])
                                     if not s.get('ended')]
                    if not _active_in_ev:
                        _implant_no_session_pid = _impl_ev['pid']

            # Session-Start direkt aus dem Alert extrahieren (kein Banner nötig)
            _SESS_START = ('TUNNEL SESSION AKTIV', 'REVERSE SHELL SESSION ERKANNT')
            _SESS_END   = ('TUNNEL SESSION BEENDET', 'SESSION BEENDET')
            _IP_RE      = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)')

            if any(k in msg for k in _SESS_START):
                m = _IP_RE.search(msg)
                if m:
                    remote = m.group(1)
                    if remote not in sessions:
                        sessions[remote] = {
                            'remote':  remote,
                            'started': ev.get('ts', datetime.now().strftime('%H:%M:%S')),
                            'ended':   None, 'cmds': [], 'logfile': '',
                            'pid': None, 'pids': [],
                        }
                        stats['SESSION'] = stats.get('SESSION', 0) + 1
                    elif sessions[remote].get('ended'):
                        # Reconnect: gleiche IP:Port, alte Session war beendet → State komplett reset
                        sessions[remote].update({
                            'started': ev.get('ts', datetime.now().strftime('%H:%M:%S')),
                            'ended':   None,
                            'pid':     None,
                            'pids':    [],   # ← alte tote PIDs löschen!
                            'ended_reason': None, 'ended_pid': None, 'ended_pids': [],
                        })
                        stats['SESSION'] = stats.get('SESSION', 0) + 1
                    # PID aus Detail extrahieren (z.B. "PID=34493 Shell: bash -i")
                    pid_m = re.search(r'PID=(\d+)', ev.get('detail', ''))
                    if pid_m:
                        sessions[remote]['pid'] = pid_m.group(1)
                        if pid_m.group(1) not in sessions[remote].setdefault('pids', []): sessions[remote]['pids'].append(pid_m.group(1))
                    to_broadcast.append({'type': 'session_open', 'remote': remote,
                                          'started': sessions[remote]['started'],
                                          'pid': sessions[remote].get('pid')})
                    to_broadcast.append({'type': 'stats', 'stats': copy.copy(stats),
                                          'sessions': len(sessions)})
                    # Echte Session erkannt → Implant-PID aus pending entfernen
                    pid_val = sessions[remote].get('pid')
                    if pid_val:
                        _pending_implant_pids.discard(pid_val)
            elif any(k in msg for k in _SESS_END):
                m = _IP_RE.search(msg)
                if m:
                    remote = m.group(1)
                    ended  = ev.get('ts', datetime.now().strftime('%H:%M:%S'))
                    already_ended = remote in sessions and sessions[remote].get('ended')
                    ended_pid = None
                    ended_pids = []
                    if remote in sessions:
                        sess = sessions[remote]
                        ended_pid = sess.get('pid')
                        ended_pids = list(sess.get('pids', [])) or ([ended_pid] if ended_pid else [])
                        sess['ended'] = ended
                        sess['ended_reason'] = 'closed'
                        sess['ended_pid'] = ended_pid
                        sess['ended_pids'] = ended_pids
                    # Kein zweites session_closed wenn Session bereits beendet (z.B. durch Autokill)
                    if not already_ended:
                        to_broadcast.append({'type': 'session_closed',
                                              'remote': remote, 'ended': ended,
                                              'pid': ended_pid, 'pids': ended_pids,
                                              'reason': 'closed'})

            # Tunnel-Aktivitäten dem passenden Session-Tab zuordnen
            # (TUNNEL CMD, TUNNEL INHALT, TUNNEL REQUEST → sichtbar im Session-Tab)
            _TUNNEL_KEYWORDS = ('TUNNEL CMD', 'TUNNEL INHALT', 'TUNNEL REQUEST',
                                 'TUNNEL SENSITIVE', 'TUNNEL SHELL', 'TUNNEL VERDÄCHTIG',
                                 'TUNNEL CREDENTIALS')
            # NICHT: 'TUNNEL SESSION' (Start/Stop-Meldungen), 'BEACONING', 'NEUE VERBINDUNG'
            if any(kw in msg for kw in _TUNNEL_KEYWORDS):
                m = _IP_RE.search(msg)
                if m:
                    remote = m.group(1)
                    if remote in sessions and not sessions[remote].get('ended'):
                        # Richtung aus Keywords ableiten
                        if 'IN ←' in msg or '→ CMD' in msg or 'Befehl:' in msg:
                            direction = 'IN ←'
                        elif 'OUT→' in msg or 'OUTPUT' in msg:
                            direction = 'OUT→'
                        else:
                            direction = '→'
                        # Interessantesten Teil extrahieren
                        data = msg
                        for prefix in ('TUNNEL CMD [öffentlich] via', 'TUNNEL CMD [privat] via',
                                        'TUNNEL INHALT [IN ←]', 'TUNNEL INHALT [OUT→]',
                                        'TUNNEL REQUEST [IN ←]', 'TUNNEL SENSITIVE OUTPUT',
                                        'TUNNEL SHELL PROMPT', 'TUNNEL VERDÄCHTIG –',
                                        'TUNNEL CMD-MARKER'):
                            if prefix in msg:
                                idx = msg.find(prefix) + len(prefix)
                                data = msg[idx:].strip().lstrip('–→←').strip()
                                break
                        if data and len(data) > 3:
                            cmd = {'direction': direction, 'data': data,
                                   'ts': ev.get('ts', '')}
                            sessions[remote]['cmds'].append(cmd)
                            if len(sessions[remote]['cmds']) > MAX_SESSION_CMDS:
                                sessions[remote]['cmds'] = sessions[remote]['cmds'][-MAX_SESSION_CMDS:]
                            to_broadcast.append({'type': 'session_cmd',
                                                  'remote': remote, **cmd})

        elif t == 'detail':
            if event_history:
                last = event_history[-1]
                if last.get('type') == 'alert' and not last.get('detail'):
                    last['detail'] = ev['detail']
                    to_broadcast.append({'type': 'detail_update',
                                         'id': last.get('id'), 'detail': ev['detail']})

                    # PID aus Detail extrahieren wenn Session-Alert
                    _IP_RE2 = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)')
                    _PID_RE = re.compile(r'PID=(\d+)')
                    last_msg = last.get('message', '')
                    _SESS_START2 = ('TUNNEL SESSION AKTIV', 'REVERSE SHELL SESSION ERKANNT')
                    if any(kk in last_msg for kk in _SESS_START2):
                        pid_m2 = _PID_RE.search(ev['detail'])
                        ip_m2  = _IP_RE2.search(last_msg)
                        if pid_m2 and ip_m2 and ip_m2.group(1) in sessions:
                            r2 = ip_m2.group(1)
                            sessions[r2]['pid'] = pid_m2.group(1)
                            if pid_m2.group(1) not in sessions[r2].setdefault('pids', []): sessions[r2]['pids'].append(pid_m2.group(1))
                            to_broadcast.append({'type': 'session_pid',
                                                  'remote': r2, 'pid': pid_m2.group(1)})
                    # IMPLANT: PID steht im Detail, nicht in der Meldung.
                    # Sofort Socket-Lookup versuchen; PID zusätzlich in
                    # _pending_implant_pids merken falls NEUE VERBINDUNG später kommt.
                    if 'IMPLANT' in last_msg:
                        _pid_m_impl = _PID_RE.search(ev['detail'])
                        if _pid_m_impl:
                            _impl_pid_str = _pid_m_impl.group(1)
                            if not any(not s.get('ended') for s in sessions.values()):
                                _implant_no_session_pid = _impl_pid_str
                            _pending_implant_pids.add(_impl_pid_str)

                    # NEUE VERBINDUNG: wenn PID zu einem bekannten Implant gehört,
                    # synthetische Session aus dem Verbindungs-Event bauen (kein docker exec).
                    if 'NEUE VERBINDUNG' in last_msg and _pending_implant_pids:
                        _pid_m_nv = _PID_RE.search(ev['detail'])
                        if _pid_m_nv and _pid_m_nv.group(1) in _pending_implant_pids:
                            _ip_m_nv = _IP_RE2.search(last_msg)
                            if _ip_m_nv:
                                _nv_remote = _ip_m_nv.group(1)
                                _nv_pid    = _pid_m_nv.group(1)
                                if _nv_remote not in sessions or sessions[_nv_remote].get('ended'):
                                    _nv_ts = last.get('ts', datetime.now().strftime('%H:%M:%S'))
                                    sessions[_nv_remote] = {
                                        'remote':  _nv_remote, 'started': _nv_ts,
                                        'ended':   None, 'cmds': [], 'logfile': '',
                                        'pid':     _nv_pid, 'pids': [_nv_pid],
                                    }
                                    stats['SESSION'] = stats.get('SESSION', 0) + 1
                                    to_broadcast.append({'type': 'session_open',
                                                          'remote': _nv_remote,
                                                          'started': _nv_ts,
                                                          'pid': _nv_pid,
                                                          'synthetic': True})
                                    to_broadcast.append({'type': 'stats',
                                                          'stats': copy.copy(stats),
                                                          'sessions': len(sessions)})
                                    _pending_implant_pids.discard(_nv_pid)

                    _TUNNEL_KW = ('TUNNEL CMD', 'TUNNEL INHALT', 'TUNNEL REQUEST',
                                  'TUNNEL SENSITIVE', 'TUNNEL SHELL', 'TUNNEL SHELL PROMPT')
                    if any(k in last_msg for k in _TUNNEL_KW):
                        m2 = _IP_RE2.search(last_msg)
                        if m2:
                            remote = m2.group(1)
                            if remote in sessions and not sessions[remote].get('ended'):
                                detail_text = ev['detail']
                                # "Befehl: ls -la" oder "Daten: root@host:/# ..."
                                for pfx in ('Befehl:', 'Daten:', 'Prompt:', 'Marker:'):
                                    if detail_text.startswith(pfx):
                                        detail_text = detail_text[len(pfx):].strip()
                                        break
                                if detail_text and len(detail_text) > 2:
                                    direction = 'IN ←' if 'IN ←' in last_msg else '→'
                                    cmd = {'direction': direction,
                                           'data': detail_text,
                                           'ts': last.get('ts', '')}
                                    sessions[remote]['cmds'].append(cmd)
                                    if len(sessions[remote]['cmds']) > MAX_SESSION_CMDS:
                                        sessions[remote]['cmds'] = sessions[remote]['cmds'][-MAX_SESSION_CMDS:]
                                    to_broadcast.append({'type': 'session_cmd',
                                                          'remote': remote, **cmd})

        elif t == 'session_cmd':
            remote = ev['remote']
            if remote not in sessions:
                sessions[remote] = {'remote': remote,
                                    'started': datetime.now().strftime('%H:%M:%S'),
                                    'ended': None, 'cmds': [], 'logfile': '',
                                    'pid': None, 'pids': []}
            sess = sessions[remote]
            event_pid = ev.get('pid')
            # Nach einem Autokill dürfen nachlaufende/gepufferte Bytes die
            # geschlossene Session nicht wieder öffnen. Eine echte neue Shell
            # kommt zuerst als TUNNEL SESSION AKTIV mit einer neuen PID.
            if autokill_enabled and sess.get('ended'):
                return
            # Ein Shell-Command nach einem Session-Ende ist ein Reconnect. Das
            # session_open-Event defensiv erneut senden, selbst wenn ein Banner
            # durch TCP-Fragmentierung oder einen kurzen SSE-Ausfall verloren ging.
            if sess.get('ended'):
                sess.update({'ended': None, 'started': ev.get('ts') or datetime.now().strftime('%H:%M:%S'),
                             'pid': None, 'pids': [], 'ended_reason': None,
                             'ended_pid': None, 'ended_pids': []})
                stats['SESSION'] = stats.get('SESSION', 0) + 1
                to_broadcast.append({'type': 'session_open', 'remote': remote,
                                     'started': sess['started'], 'pid': event_pid})
                # PID-Lookup auch bei Reconnect via session_cmd triggern
                # (nicht nur bei Banner-Reconnect), damit UDP-Sessions die PID erhalten.
                threading.Timer(1.5, _lookup_missing_pids).start()
            if event_pid:
                previous_pid = sess.get('pid')
                sess['pid'] = event_pid
                if event_pid not in sess.setdefault('pids', []):
                    sess['pids'].append(event_pid)
                if previous_pid != event_pid:
                    to_broadcast.append({'type': 'session_pid', 'remote': remote,
                                         'pid': event_pid})
            cmd = {'direction': ev['direction'], 'data': ev['data'], 'ts': ev['ts'],
                   'pid': event_pid}
            sess['cmds'].append(cmd)
            if len(sess['cmds']) > MAX_SESSION_CMDS:
                sess['cmds'] = sess['cmds'][-MAX_SESSION_CMDS:]
            to_broadcast.append({'type': 'session_cmd', **ev})
            to_broadcast.append({'type': 'stats', 'stats': copy.copy(stats),
                                  'sessions': len(sessions)})

        elif t == 'session_open_banner':
            remote = ev['remote']
            _banner_reconnect = False
            # Das Banner wird vom Monitor unmittelbar nach dem Session-Alert
            # ausgegeben. Autokill kann die PID bereits davor beendet haben;
            # in diesem Fall ist das Banner verspätet und darf nicht reaktivieren.
            if (autokill_enabled and remote in sessions and
                    sessions[remote].get('ended')):
                return
            if remote not in sessions:
                sessions[remote] = {'remote': remote,
                                    'started': datetime.now().strftime('%H:%M:%S'),
                                    'ended': None, 'cmds': [], 'logfile': '',
                                    'pid': None, 'pids': []}
            elif sessions[remote].get('ended'):
                # Reconnect via Banner → State komplett reset (wie bei _SESS_START)
                sessions[remote].update({
                    'ended': None, 'pid': None, 'pids': [],
                    'ended_reason': None, 'ended_pid': None, 'ended_pids': [],
                    'started': datetime.now().strftime('%H:%M:%S'),
                })
                _banner_reconnect = True
                stats['SESSION'] = stats.get('SESSION', 0) + 1
            sess = sessions[remote]
            to_broadcast.append({'type': 'session_open', 'remote': remote,
                                  'started': sess['started']})
            to_broadcast.append({'type': 'stats', 'stats': copy.copy(stats),
                                  'sessions': len(sessions)})
            if _banner_reconnect:
                # PID im Hintergrund nachschlagen (gibt Sniffer 1s Zeit für TUNNEL SESSION AKTIV)
                threading.Timer(1.5, _lookup_missing_pids).start()

        elif t == 'session_logfile_banner':
            # Ordne die Logfile der letzten noch offenen Session zu
            logfile = ev['logfile']
            for r in reversed(list(sessions.keys())):
                if not sessions[r].get('ended') and not sessions[r].get('logfile'):
                    sessions[r]['logfile'] = logfile
                    to_broadcast.append({'type': 'session_logfile',
                                         'remote': r, 'logfile': logfile})
                    break

        elif t == 'session_end':
            remote = ev['remote']
            if remote in sessions:
                already_ended = sessions[remote].get('ended')
                if not already_ended:
                    sess = sessions[remote]
                    ended_pid = sess.get('pid')
                    ended_pids = list(sess.get('pids', [])) or ([ended_pid] if ended_pid else [])
                    sess['ended'] = datetime.now().strftime('%H:%M:%S')
                    sess['ended_reason'] = 'closed'
                    sess['ended_pid'] = ended_pid
                    sess['ended_pids'] = ended_pids
                    to_broadcast.append({'type': 'session_closed', 'remote': remote,
                                          'ended': sess['ended'], 'pid': ended_pid,
                                          'pids': ended_pids, 'reason': 'closed'})
                # else: bereits beendet (z.B. durch Autokill) → kein zweites session_closed

    for msg in to_broadcast:
        broadcast(msg)

    # Auto-Neutralize außerhalb des Locks (subprocess)
    if _should_auto_neutralize:
        _an_result = _apply_countermeasure('remove_rootkit', _rk_param)
        broadcast({'type': 'auto_neutralize_applied',
                   'ok': _an_result.get('ok', False),
                   'msg': _an_result.get('msg', ''),
                   'ts': _container_ts()})

    # Synthethische Session: IMPLANT ohne TUNNEL SESSION AKTIV
    # VOR dem Auto-Kill prüfen, damit die PID noch in /proc vorhanden ist.
    # Passiert wenn die Shell als Implant-Prozess erkannt wurde, bevor das
    # Netzwerk-Tracking die TCP-Verbindung als Session registriert hat.
    if _implant_no_session_pid:
        try:
            _syn_remote = _implant_pid_remote(_implant_no_session_pid)
            if _syn_remote:
                _do_syn = False
                _syn_ts = _container_ts()
                _syn_stats = None
                with _state_lock:
                    if _syn_remote not in sessions or sessions[_syn_remote].get('ended'):
                        sessions[_syn_remote] = {
                            'remote':  _syn_remote,
                            'started': _syn_ts,
                            'ended':   None, 'cmds': [], 'logfile': '',
                            'pid':     _implant_no_session_pid,
                            'pids':    [_implant_no_session_pid],
                        }
                        stats['SESSION'] = stats.get('SESSION', 0) + 1
                        _syn_stats = copy.copy(stats)
                        _do_syn = True
                if _do_syn:
                    broadcast({'type': 'session_open', 'remote': _syn_remote,
                                'started': _syn_ts, 'pid': _implant_no_session_pid,
                                'synthetic': True})
                    broadcast({'type': 'stats', 'stats': _syn_stats,
                                'sessions': len(sessions)})
                    print(f'[IMPLANT-SYN] Synthetische Session {_syn_remote}'
                          f' (PID {_implant_no_session_pid})', flush=True)
        except Exception as _e:
            print(f'[IMPLANT-SYN] Fehler: {_e}', flush=True)

    # Auto-Entfernen: zugehörigen Implant-Prozess ebenfalls beenden
    # (kill_pid broadcastet bereits 'implant_cleared' für die UI-Banner).
    if _impl_kill_pid:
        _ik_result = _apply_countermeasure('kill_pid', _impl_kill_pid)
        broadcast({'type': 'auto_neutralize_applied',
                   'ok': _ik_result.get('ok', False),
                   'msg': _ik_result.get('msg', ''),
                   'ts': _container_ts()})

# ── Monitor Subprocess ──────────────────────────────────────────────────
def _check_privileged() -> bool:
    r = subprocess.run(
        ['docker', 'exec', '--privileged', CONTAINER, 'python3', '-c',
         'import socket; socket.socket(socket.AF_PACKET,socket.SOCK_RAW,3).close();print("ok")'],
        capture_output=True, text=True, timeout=5)
    return r.stdout.strip() == 'ok'

def _ensure_script() -> bool:
    """Kopiert Script IMMER frisch in den Container. Gibt True zurück wenn OK.
    Vorher wurde nur kopiert wenn die Datei im Container fehlte - dadurch
    blieb nach jeder Änderung an artex-monitor.py die ALTE Version aktiv,
    solange der Container nicht neu erstellt wurde. Ein unbedingtes
    docker cp bei jedem Backend-Start stellt sicher, dass Fixes ankommen."""
    try:
        # Alte Monitor-Instanzen beenden (verhindert doppelte Alerts durch parallele Prozesse)
        subprocess.run(['docker', 'exec', CONTAINER, 'pkill', '-f', MONITOR_DST],
                       capture_output=True, timeout=5)
        time.sleep(0.5)

        if not os.path.exists(MONITOR_SCRIPT):
            broadcast({'type': 'error',
                       'message': f'Monitor-Script nicht gefunden: {MONITOR_SCRIPT}'})
            return False
        subprocess.run(['docker', 'cp', MONITOR_SCRIPT, f'{CONTAINER}:{MONITOR_DST}'],
                       check=True, timeout=15)
        return True
    except Exception as e:
        broadcast({'type': 'error', 'message': f'Script-Copy fehlgeschlagen: {e}'})
        return False

def _run_once() -> None:
    """Startet den Monitor-Subprocess einmal und verarbeitet stdout."""
    if not _ensure_script():
        return

    try:
        privileged = _check_privileged()
    except Exception:
        privileged = False

    cmd = ['docker', 'exec']
    if privileged:
        cmd.append('--privileged')
    cmd += [CONTAINER, 'python3', MONITOR_DST]

    with _state_lock:
        monitor_status['running']    = False
        monitor_status['privileged'] = privileged

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 bufsize=1, universal_newlines=True)
        print(f"[Dashboard] Starte Monitor: {' '.join(cmd)}", flush=True)

        # Stderr in separatem Thread leeren damit kein Deadlock entsteht
        def drain_stderr():
            for _ in proc.stderr:
                pass
        threading.Thread(target=drain_stderr, daemon=True).start()

        ts = datetime.now().strftime('%H:%M:%S')
        with _state_lock:
            monitor_status['running'] = True
            monitor_status['started'] = ts
        broadcast({'type': 'monitor_started', 'privileged': privileged, 'ts': ts})

        pending_id = None   # ID des letzten Alerts das noch ein Detail erwartet

        for line in proc.stdout:
            _logev('RAW', line.rstrip())
            ev = parse_line(line)
            if not ev:
                continue

            if ev['type'] == 'alert':
                process_event(ev)
                with _state_lock:
                    # Find the alert's id in history (not the correlation event that may follow)
                    pending_id = None
                    for _stored in reversed(event_history):
                        if _stored.get('type') == 'alert':
                            pending_id = _stored.get('id')
                            break
            elif ev['type'] == 'detail':
                # Detail an pending Alert hängen – alles AUSSERHALB des Locks
                if pending_id is not None:
                    detail_msg       = None
                    pid_update       = None
                    _ak_remote       = None   # Autokill-Daten
                    _ak_pid          = None
                    _ak_udp_port     = None
                    _needs_pid_lookup = False
                    _impl_lookup_pid  = None   # IMPLANT-PID für Socket-Lookup nach dem Lock
                    _syn_session_ev   = None   # synthetische Session (NEUE VERBINDUNG)
                    _syn_stats_ev     = None
                    _IP_D  = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)')
                    _PID_D = re.compile(r'PID=(\d+)')
                    _UDP_D = re.compile(r'UDP_LOCAL=(\d+)')

                    with _state_lock:
                        for stored in reversed(event_history):
                            if stored.get('id') == pending_id and not stored.get('detail'):
                                stored['detail'] = ev['detail']
                                detail_msg = {'type': 'detail_update',
                                              'id': pending_id, 'detail': ev['detail']}
                                smsg = stored.get('message', '')
                                if any(k in smsg for k in
                                       ('TUNNEL SESSION AKTIV', 'REVERSE SHELL SESSION')):
                                    ip_m  = _IP_D.search(smsg)
                                    pid_m = _PID_D.search(ev['detail'])
                                    udp_m = _UDP_D.search(ev['detail'])
                                    if ip_m:
                                        r_key = ip_m.group(1)
                                        # UDP_LOCAL immer speichern – auch wenn PID=? (kein \d-Match)
                                        if udp_m and r_key in sessions:
                                            sessions[r_key]['udp_local_port'] = udp_m.group(1)
                                            if not pid_m:
                                                # Neue UDP-Session ohne PID → Lookup nötig
                                                _needs_pid_lookup = True
                                    if ip_m and pid_m:
                                        r_key = ip_m.group(1)
                                        pid_v = pid_m.group(1)
                                        if r_key in sessions:
                                            sessions[r_key]['pid'] = pid_v
                                            if pid_v not in sessions[r_key].get('pids', []):
                                                sessions[r_key].setdefault('pids', []).append(pid_v)
                                            pid_update = {'type': 'session_pid',
                                                          'remote': r_key, 'pid': pid_v}
                                        # Autokill-Daten für nach dem Lock merken
                                        if autokill_enabled and r_key in sessions:
                                            _ak_remote = r_key
                                            _ak_pid    = pid_v
                                            _ak_udp_port = udp_m.group(1) if udp_m else None

                                # IMPLANT: PID steht im Detail, nicht in der Meldung.
                                # Socket-Lookup nach dem Lock vormerken + PID/Name für
                                # spätere NEUE VERBINDUNG-Zuordnung merken. Name zusätzlich
                                # zur PID, weil Loader/Watchdog-Paare oft unter einer ANDEREN
                                # PID laufen als der, die als "deleted binary" auffiel.
                                if 'IMPLANT' in smsg:
                                    pid_m_impl = _PID_D.search(ev['detail'])
                                    name_m_impl = re.search(r'name=(\S+)', ev['detail'])
                                    if pid_m_impl:
                                        _impl_pid_str = pid_m_impl.group(1)
                                        if not any(not s.get('ended') for s in sessions.values()):
                                            _impl_lookup_pid = _impl_pid_str
                                        _pending_implant_pids.add(_impl_pid_str)
                                    if name_m_impl:
                                        _pending_implant_names.add(name_m_impl.group(1))

                                # NEUE VERBINDUNG: wenn PID ODER Prozessname (CMD=(...))
                                # zu einem bekannten Implant gehört, synthetische Session
                                # direkt aus dem Verbindungs-Event bauen (kein docker exec).
                                if ('NEUE VERBINDUNG' in smsg and
                                        (_pending_implant_pids or _pending_implant_names)):
                                    pid_m_nv  = _PID_D.search(ev['detail'])
                                    name_m_nv = re.search(r'CMD=\(([^)]+)\)', ev['detail'])
                                    _nv_pid_match  = bool(pid_m_nv and
                                        pid_m_nv.group(1) in _pending_implant_pids)
                                    _nv_name_match = bool(name_m_nv and
                                        name_m_nv.group(1) in _pending_implant_names)
                                    if pid_m_nv and (_nv_pid_match or _nv_name_match):
                                        ip_m_nv = _IP_D.search(smsg)
                                        if ip_m_nv:
                                            _nv_remote = ip_m_nv.group(1)
                                            _nv_pid    = pid_m_nv.group(1)
                                            if (_nv_remote not in sessions or
                                                    sessions[_nv_remote].get('ended')):
                                                _nv_ts = stored.get('ts',
                                                    datetime.now().strftime('%H:%M:%S'))
                                                sessions[_nv_remote] = {
                                                    'remote':  _nv_remote,
                                                    'started': _nv_ts,
                                                    'ended':   None, 'cmds': [],
                                                    'logfile': '',
                                                    'pid':     _nv_pid,
                                                    'pids':    [_nv_pid],
                                                }
                                                stats['SESSION'] = stats.get('SESSION', 0) + 1
                                                _syn_session_ev = {
                                                    'type': 'session_open',
                                                    'remote': _nv_remote,
                                                    'started': _nv_ts, 'pid': _nv_pid,
                                                    'synthetic': True}
                                                _syn_stats_ev = {
                                                    'type': 'stats',
                                                    'stats': copy.copy(stats),
                                                    'sessions': len(sessions)}
                                            _pending_implant_pids.discard(_nv_pid)
                                            if name_m_nv:
                                                _pending_implant_names.discard(name_m_nv.group(1))
                                break

                    # Broadcasts AUSSERHALB des Locks (kein Deadlock)
                    if detail_msg:
                        broadcast(detail_msg)
                    if pid_update:
                        broadcast(pid_update)
                    # Neue UDP-Session ohne PID → PID im Hintergrund nachschlagen
                    if _needs_pid_lookup:
                        threading.Timer(1.5, _lookup_missing_pids).start()

                    # Synthetische Session aus NEUE VERBINDUNG (IMPLANT-Zuordnung)
                    if _syn_session_ev:
                        broadcast(_syn_session_ev)
                        broadcast(_syn_stats_ev)
                        print(f"[IMPLANT-SYN] Session via NEUE VERBINDUNG: "
                              f"{_syn_session_ev['remote']} (PID {_syn_session_ev['pid']})",
                              flush=True)

                    # IMPLANT ohne Session: Socket-Lookup per docker exec versuchen
                    # (deckt den Fall ab, dass die TCP-Verbindung schon vor der
                    # Implant-Erkennung bestand, z.B. Watchdog→Worker bereits aktiv).
                    if _impl_lookup_pid:
                        try:
                            _syn_remote2 = _implant_pid_remote(_impl_lookup_pid)
                            if _syn_remote2:
                                _do_syn2 = False
                                _syn_ts2 = _container_ts()
                                _syn_stats2 = None
                                with _state_lock:
                                    if (_syn_remote2 not in sessions or
                                            sessions[_syn_remote2].get('ended')):
                                        sessions[_syn_remote2] = {
                                            'remote':  _syn_remote2,
                                            'started': _syn_ts2,
                                            'ended':   None, 'cmds': [], 'logfile': '',
                                            'pid':     _impl_lookup_pid,
                                            'pids':    [_impl_lookup_pid],
                                        }
                                        stats['SESSION'] = stats.get('SESSION', 0) + 1
                                        _syn_stats2 = copy.copy(stats)
                                        _do_syn2 = True
                                        _pending_implant_pids.discard(_impl_lookup_pid)
                                if _do_syn2:
                                    broadcast({'type': 'session_open',
                                               'remote': _syn_remote2,
                                               'started': _syn_ts2,
                                               'pid': _impl_lookup_pid,
                                               'synthetic': True})
                                    broadcast({'type': 'stats', 'stats': _syn_stats2,
                                               'sessions': len(sessions)})
                                    print(f"[IMPLANT-SYN] Session via Socket-Lookup: "
                                          f"{_syn_remote2} (PID {_impl_lookup_pid})",
                                          flush=True)
                        except Exception as _e:
                            print(f"[IMPLANT-SYN] Fehler: {_e}", flush=True)

                    # Autokill AUSSERHALB des Locks (subprocess.run + broadcast)
                    if _ak_remote and _ak_pid:
                        _result = _do_kill(_ak_remote, _ak_pid, _ak_udp_port)
                        _ts_k   = _container_ts()
                        if _result['ok']:
                            with _state_lock:
                                if _ak_remote in sessions:
                                    sess = sessions[_ak_remote]
                                    ended_pids = _result.get('pids') or [_ak_pid]
                                    sess['ended'] = _ts_k
                                    sess['ended_reason'] = 'autokill'
                                    sess['ended_pid'] = _ak_pid
                                    sess['ended_pids'] = ended_pids
                                    sess['pid'] = None
                                    sess['pids'] = []
                                    sess.pop('udp_local_port', None)
                            broadcast({'type': 'session_autokilled',
                                       'remote': _ak_remote, 'pid': _ak_pid, 'ts': _ts_k,
                                       'pids': _result.get('pids') or [_ak_pid],
                                       'outcome': _result.get('outcome')})
                            broadcast({'type': 'session_closed',
                                       'remote': _ak_remote, 'ended': _ts_k,
                                       'pid': _ak_pid, 'pids': _result.get('pids') or [_ak_pid],
                                       'reason': 'autokill'})
                            for _kpid in ended_pids:
                                broadcast({'type': 'implant_cleared', 'pid': _kpid})
                            print(f"[Autokill] PID {_ak_pid} @ {_ak_remote} beendet", flush=True)
                        else:
                            print(f"[Autokill] Fehler PID {_ak_pid}: {_result['msg']}", flush=True)

                    pending_id = None

            else:
                pending_id = None
                process_event(ev)

        proc.wait()

    except Exception as e:
        broadcast({'type': 'error', 'message': str(e)})
    finally:
        with _state_lock:
            monitor_status['running'] = False
        broadcast({'type': 'monitor_stopped', 'ts': datetime.now().strftime('%H:%M:%S')})

def run_monitor() -> None:
    """Dauerschleife mit Backoff-Restart."""
    backoff = 5
    while True:
        t_start = time.time()
        _run_once()
        # Backoff zurücksetzen wenn Monitor stabil > 60s lief
        if time.time() - t_start > 60:
            backoff = 5
        broadcast({'type': 'monitor_reconnect', 'backoff': backoff})
        time.sleep(backoff)
        backoff = min(backoff * 2, RESTART_BACKOFF_MAX)

# ── HTTP / SSE Server ───────────────────────────────────────────────────
def _lookup_missing_pids() -> None:
    """Ordnet aktive TCP/UDP-Socket-Inodes direkt ihren /proc-PIDs zu.
    Funktioniert auch in schlanken Images ohne ss/netstat."""
    try:
        mapping = _socket_pid_map()
        to_broadcast = []
        with _state_lock:
            active = [(remote, sess.get('pid'), sess.get('udp_local_port'))
                      for remote, sess in sessions.items()
                      if not sess.get('ended')]
        for remote, current_pid, udp_local_port in active:
            if current_pid:
                continue
            # TCP-Lookup (ESTABLISHED-Verbindungen)
            candidates = mapping.get(remote, [])
            # UDP-Fallback 1: lokaler ephemerer Port (oft schon weg bei DNS)
            if not candidates and udp_local_port:
                try:
                    candidates = _udp_local_owners(udp_local_port)
                except Exception:
                    pass
            # UDP-Fallback 2: connected UDP-Socket zur Remote-IP (z.B. dnscat2)
            if not candidates and ':' in remote:
                try:
                    rem_ip, rem_port = remote.rsplit(':', 1)
                    candidates = _udp_remote_owners(rem_ip, rem_port)
                except Exception:
                    pass
            # UDP-Fallback 3: Cmdline-Scan nach bekannten DNS-Tunnel-Tools
            if not candidates:
                try:
                    hits = _udp_cmdline_scan()
                    if len(hits) == 1:
                        candidates = hits
                except Exception:
                    pass
            if not candidates:
                continue
            # Bei mehreren Verbindungen ist die höchste PID normalerweise der
            # neueste Reconnect. Die UI zeigt trotzdem nur eine aktuelle PID.
            pid = str(max(int(p) for p in candidates))
            with _state_lock:
                if remote in sessions and not sessions[remote].get('ended'):
                    s = sessions[remote]
                    s['pid'] = pid
                    s['pids'] = [pid]
                    to_broadcast.append((remote, pid))
        for remote, pid in to_broadcast:
            broadcast({'type': 'session_pid', 'remote': remote, 'pid': pid})
            print(f"[PID-Lookup] {remote} → PID {pid}", flush=True)
    except Exception as e:
        print(f"[PID-Lookup] Fehler: {e}", flush=True)



class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def do_GET(self):
        path = urllib.parse.unquote(self.path)
        if path == '/':
            # Bei jedem Reload die aktuelle Datei lesen. Frontend-Verbesserungen
            # benötigen dadurch künftig keinen Dashboard-Neustart mehr.
            self._html(_load_dashboard())
        elif path == '/events':
            self._sse()
        elif path == '/api/status':
            with _state_lock:
                data = {'monitor': dict(monitor_status),
                        'stats': dict(stats),
                        'sessions': len(sessions),
                        'clients': len(sse_clients)}
            self._json(data)
        elif path == '/api/sessions':
            with _state_lock:
                data = {r: {**s, 'cmds': s['cmds'][-100:]} for r, s in sessions.items()}
            self._json(data)
        elif path == '/api/log':
            self._serve_log()
        elif path == '/api/blocks':
            with _blocks_lock:
                self._json(dict(_active_blocks))
        elif path == '/api/network_info':
            self._json(_isolation_info())
        elif path == '/api/rootkit_state':
            state: dict = {}
            try:
                r = subprocess.run(
                    ['docker', 'exec', '--privileged', CONTAINER, 'cat', '/etc/ld.so.preload'],
                    capture_output=True, text=True, timeout=3)
                content = r.stdout.strip()
                state['ldpreload'] = content if (r.returncode == 0 and content) else None
            except Exception:
                state['ldpreload'] = None
            try:
                r = subprocess.run(
                    ['docker', 'exec', '--privileged', CONTAINER, 'sh', '-c',
                     'find /tmp /dev/shm -maxdepth 1 \\( -name "*.so" -o -name "*.ko" \\) 2>/dev/null'],
                    capture_output=True, text=True, timeout=3)
                files = [f.strip() for f in r.stdout.splitlines() if f.strip()]
                state['suspicious_files'] = files
            except Exception:
                state['suspicious_files'] = []
            state['active'] = bool(state.get('ldpreload') or state.get('suspicious_files'))
            self._json(state)
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        path = urllib.parse.unquote(self.path)
        if path.startswith('/api/kill/'):
            remote = path[10:]
            self._kill(remote)
        elif path == '/api/autokill':
            self._toggle_autokill()
        elif path == '/api/auto_neutralize':
            self._toggle_auto_neutralize()
        elif path == '/api/block':
            self._handle_block(block=True)
        elif path == '/api/unblock':
            self._handle_block(block=False)
        elif path == '/api/countermeasure':
            self._handle_countermeasure()
        else:
            self.send_response(404); self.end_headers()

    def _handle_block(self, block: bool):
        try:
            length = int(self.headers.get('Content-Length', 0))
            body   = json.loads(self.rfile.read(length) if length else b'{}')
            btype  = str(body.get('type', '')).strip().lower()
            value  = str(body.get('value', '')).strip()
            err = _validate_block_input(btype, value)
            if err:
                self._json({'ok': False, 'msg': err}); return
            fn = _apply_block if block else _apply_unblock
            self._json(fn(btype, value))
        except Exception as e:
            self._json({'ok': False, 'msg': str(e)})

    def _handle_countermeasure(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            body   = json.loads(self.rfile.read(length) if length else b'{}')
            action = str(body.get('action', '')).strip().lower()
            param  = str(body.get('param', '')).strip()
            if not action:
                self._json({'ok': False, 'msg': 'action fehlt'}); return
            self._json(_apply_countermeasure(action, param))
        except Exception as e:
            self._json({'ok': False, 'msg': str(e)})

    def _toggle_autokill(self):
        global autokill_enabled
        try:
            length = int(self.headers.get('Content-Length', 0))
            body   = json.loads(self.rfile.read(length)) if length else {}
            autokill_enabled = bool(body.get('enabled', not autokill_enabled))
        except Exception:
            autokill_enabled = not autokill_enabled

        state = 'AKTIV' if autokill_enabled else 'DEAKTIVIERT'
        print(f"[Autokill] {state}", flush=True)
        broadcast({'type': 'autokill_state', 'enabled': autokill_enabled})
        self._json({'ok': True, 'enabled': autokill_enabled})

        # Wenn Autokill aktiviert: aktive Sessions sofort beenden
        if autokill_enabled:
            # 1. PIDs für Sessions ohne bekannte PID über /proc nachschlagen
            _lookup_missing_pids()
            # 2. Für jede aktive Session nur die aktuellen Socket-Besitzer killen.
            with _state_lock:
                active = [
                    (r, s.get('pid'), s.get('udp_local_port'))
                    for r, s in sessions.items()
                    if not s.get('ended')
                ]
            for remote, pid, udp_local_port in active:
                result = _do_kill(remote, pid, udp_local_port)
                if not result['ok']:
                    print(f"[Autokill] Fehler {remote}: {result['msg']}", flush=True)
                    continue
                ts_k = _container_ts()
                with _state_lock:
                    if remote in sessions and not sessions[remote].get('ended'):
                        sess = sessions[remote]
                        ended_pid = pid or result['pid']
                        ended_pids = result.get('pids') or [ended_pid]
                        sess['ended'] = ts_k
                        sess['ended_reason'] = 'autokill'
                        sess['ended_pid'] = ended_pid
                        sess['ended_pids'] = ended_pids
                        sess['pid'] = None
                        sess['pids'] = []
                        sess.pop('udp_local_port', None)
                broadcast({'type': 'session_autokilled',
                           'remote': remote, 'pid': pid or result['pid'], 'ts': ts_k,
                           'pids': result.get('pids') or [pid or result['pid']],
                           'outcome': result.get('outcome')})
                broadcast({'type': 'session_closed',
                           'remote': remote, 'ended': ts_k,
                           'pid': pid or result['pid'],
                           'pids': result.get('pids') or [pid or result['pid']],
                           'reason': 'autokill'})
                for _kpid in ended_pids:
                    broadcast({'type': 'implant_cleared', 'pid': _kpid})
                print(f"[Autokill] {result['outcome']}: PID(s) {result['pids']} @ {remote}", flush=True)

    def _toggle_auto_neutralize(self):
        global auto_neutralize
        try:
            length = int(self.headers.get('Content-Length', 0))
            body   = json.loads(self.rfile.read(length)) if length else {}
            auto_neutralize = bool(body.get('enabled', not auto_neutralize))
        except Exception:
            auto_neutralize = not auto_neutralize
        state = 'AKTIV' if auto_neutralize else 'DEAKTIVIERT'
        print(f"[Auto-Neutralize] {state}", flush=True)
        broadcast({'type': 'auto_neutralize_state', 'enabled': auto_neutralize})
        self._json({'ok': True, 'enabled': auto_neutralize})

    def _kill(self, remote: str):
        """Beendet den Reverse-Shell-Prozess via SIGKILL im Container."""
        with _state_lock:
            sess = sessions.get(remote, {})
            if sess.get('ended'):
                self._json({'ok': False, 'error': 'Session bereits beendet',
                            'outcome': 'already_ended', 'remote': remote,
                            'ts': sess['ended']})
                return
            pid  = sess.get('pid')
            udp_local_port = sess.get('udp_local_port')

        result = _do_kill(remote, pid, udp_local_port)
        ts_now = _container_ts()
        if result['ok']:
            # Session als beendet markieren — nur broadcasten wenn nicht schon beendet
            already_was_ended = False
            with _state_lock:
                if remote in sessions:
                    sess = sessions[remote]
                    already_was_ended = bool(sess.get('ended'))
                    ended_pid = pid or result['pid']
                    ended_pids = result.get('pids') or [ended_pid]
                    sess['ended'] = ts_now
                    sess['ended_reason'] = 'killed'
                    sess['ended_pid'] = ended_pid
                    sess['ended_pids'] = ended_pids
                    sess['pid'] = None
                    sess['pids'] = []
                    sess.pop('udp_local_port', None)
            if not already_was_ended:
                broadcast({'type': 'session_closed', 'remote': remote, 'ended': ts_now,
                            'pid': pid or result['pid'],
                            'pids': result.get('pids') or [pid or result['pid']],
                            'reason': 'killed'})

        self._json({'ok': result['ok'], 'remote': remote, 'ts': ts_now, **result})

    def _serve_log(self):
        """Liefert die letzten 400 Zeilen des Log-Files als Plaintext."""
        try:
            with open(LOG_FILE, encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
            body = ''.join(lines[-400:]).encode()
            self.send_response(200)
            self.send_header('Content-Type',   'text/plain; charset=utf-8')
            self.send_header('Content-Length', len(body))
            self.end_headers()
            self.wfile.write(body)
        except FileNotFoundError:
            self._json({'error': 'Log noch nicht vorhanden'})
        except Exception as e:
            self._json({'error': str(e)})

    def _html(self, html: str):
        b = html.encode()
        self.send_response(200)
        self.send_header('Content-Type',   'text/html; charset=utf-8')
        self.send_header('Cache-Control',  'no-store, no-cache, must-revalidate')
        self.send_header('Pragma',         'no-cache')
        self.send_header('Content-Length', len(b))
        self.end_headers(); self.wfile.write(b)

    def _json(self, obj):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(b))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers(); self.wfile.write(b)

    def _sse(self):
        self.send_response(200)
        self.send_header('Content-Type',  'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection',    'keep-alive')
        self.end_headers()

        q = _queue.Queue(maxsize=200)

        # Init-Snapshot und Queue-Registrierung atomar unter _state_lock
        with _state_lock:
            init = json.dumps({
                'type':    'init',
                'history': list(event_history),
                'stats':   dict(stats),
                'sessions': {r: {**s, 'cmds': s['cmds'][-100:]} for r, s in sessions.items()},
                'monitor': dict(monitor_status),
                'autokill': autokill_enabled,
                'auto_neutralize': auto_neutralize,
                'container': CONTAINER,
            }, ensure_ascii=False)
            sse_clients.append(q)

        try:
            self.wfile.write(f'data: {init}\n\n'.encode())
            self.wfile.flush()
        except Exception:
            with _state_lock:
                if q in sse_clients: sse_clients.remove(q)
            return

        try:
            while True:
                try:
                    payload = q.get(timeout=25)
                    self.wfile.write(payload)
                    self.wfile.flush()
                except _queue.Empty:
                    self.wfile.write(b': ping\n\n')
                    self.wfile.flush()
        except Exception:
            pass
        finally:
            with _state_lock:
                if q in sse_clients: sse_clients.remove(q)

class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

# ── Dashboard HTML ──────────────────────────────────────────────────────
# Dashboard-HTML wird aus dashboard.html geladen
_DASHBOARD_HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dashboard.html')
def _load_dashboard() -> str:
    try:
        with open(_DASHBOARD_HTML_PATH, encoding='utf-8') as _f:
            return _f.read()
    except FileNotFoundError:
        print(f"[Dashboard] FEHLER: dashboard.html nicht gefunden: {_DASHBOARD_HTML_PATH}", flush=True)
        import sys; sys.exit(1)
DASHBOARD_HTML = _load_dashboard()


# ── Main ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print(f"""
╔══════════════════════════════════════════════════╗
║   ARTEX Monitor Dashboard                       ║
╠══════════════════════════════════════════════════╣
║   Browser  : http://localhost:{PORT:<17}  ║
║   Container: {CONTAINER:<36}  ║
╚══════════════════════════════════════════════════╝
""", flush=True)
    t = threading.Thread(target=run_monitor, daemon=True)
    t.start()

    srv = Server((BIND_HOST, PORT), Handler)
    print(f"[Dashboard] http://{BIND_HOST}:{PORT}  –  Strg+C zum Beenden\n", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[Dashboard] Beendet.", flush=True)
        srv.shutdown()
