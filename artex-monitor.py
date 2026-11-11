#!/usr/bin/env python3
"""
artex-monitor.py – Container Security Monitor
==============================================
Erkennt: Reverse Shells, C2-Verbindungen, Shell-Upgrades, Persistence,
         Fileless Execution, Data Exfiltration, Beaconing, Process Injection

Start: docker exec -it artex-app python3 /tmp/artex-monitor.py
"""

import os, time, struct, socket, re, sys, collections, base64, html
import ctypes, ctypes.util, platform
from datetime import datetime

# ── /proc-Listing ohne libc-readdir (Rootkit-resistent) ────────────────
_SYS_GETDENTS64 = {'x86_64': 217, 'aarch64': 61}.get(platform.machine())
_libc = None
if _SYS_GETDENTS64 is not None:
    try:
        _libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
    except Exception:
        _libc = None

def list_proc_pids():
    """Liest PID-Verzeichnisnamen aus /proc per direktem getdents64-Syscall,
    umgeht damit einen libc-readdir/getdents-Hook (LD_PRELOAD-Rootkit).
    Fällt auf os.listdir('/proc') zurück, falls der Syscall nicht verfügbar ist
    oder fehlschlägt. Gibt eine Liste von PID-Strings zurück."""
    if _libc is not None:
        fd = -1
        try:
            fd = os.open('/proc', os.O_RDONLY | os.O_DIRECTORY)
            buf = ctypes.create_string_buffer(65536)
            pids = []
            while True:
                n = _libc.syscall(_SYS_GETDENTS64, fd, buf, len(buf))
                if n < 0:
                    raise OSError(ctypes.get_errno(), 'getdents64 failed')
                if n == 0:
                    break
                off = 0
                while off < n:
                    reclen = int.from_bytes(buf.raw[off+16:off+18], 'little')
                    if reclen <= 0:
                        break
                    name = buf.raw[off+19:off+reclen].split(b'\x00', 1)[0].decode('latin1')
                    if name.isdigit():
                        pids.append(name)
                    off += reclen
            return pids
        except Exception:
            pass
        finally:
            if fd != -1:
                try:
                    os.close(fd)
                except Exception:
                    pass
    try:
        return os.listdir('/proc')
    except Exception:
        return []

# ── Farben ───────────────────────────────────────────────────────────
RED    = '\033[91m'
ORANGE = '\033[33m'
YELLOW = '\033[93m'
GREEN  = '\033[92m'
CYAN   = '\033[96m'
BLUE   = '\033[94m'
MAGENTA= '\033[95m'
BOLD   = '\033[1m'
DIM    = '\033[2m'
NC     = '\033[0m'

INTERVAL = 1.5

# ── Raw Socket Sniffer (benötigt --privileged) ────────────────────────
import threading, struct as _struct, collections as _col

def _parse_eth(data):
    """Parst Ethernet- und Loopback-Frame, gibt IPv4-Payload zurück."""
    if len(data) < 4: return None
    # Loopback (lo): 4-Byte Header, Family 2 = AF_INET
    family = _struct.unpack_from('>I', data, 0)[0]
    if family == 2:              # AF_INET auf lo
        return data[4:]
    # Loopback little-endian
    family_le = _struct.unpack_from('<I', data, 0)[0]
    if family_le == 2:
        return data[4:]
    # Standard Ethernet: 14-Byte Header
    if len(data) < 14: return None
    eth_type = _struct.unpack_from('>H', data, 12)[0]
    if eth_type == 0x0800:
        return data[14:]
    return None

def _parse_ip(data):
    if not data or len(data) < 20: return None
    ihl = (data[0] & 0x0F) * 4
    proto = data[9]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    return proto, src, dst, data[ihl:]

def _parse_tcp(data):
    if not data or len(data) < 20: return None
    sport, dport = _struct.unpack_from('>HH', data, 0)
    seq          = _struct.unpack_from('>I', data, 4)[0]
    off          = ((data[12] >> 4) & 0xF) * 4
    flags        = data[13]
    payload      = data[off:]
    return sport, dport, seq, flags, payload

def _parse_udp(data):
    if not data or len(data) < 8: return None
    sport, dport, length = _struct.unpack_from('>HHH', data, 0)
    if length < 8: return None
    return sport, dport, data[8:min(len(data), length)]

def _dns_name(data, offset):
    """Dekodiert einen DNS-Namen inklusive Kompressionszeigern."""
    labels, seen, jumped, end = [], set(), False, offset
    while offset < len(data):
        if offset in seen: raise ValueError('DNS compression loop')
        seen.add(offset)
        size = data[offset]
        if size == 0:
            if not jumped: end = offset + 1
            return '.'.join(labels), end
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(data): raise ValueError('truncated DNS pointer')
            ptr = ((size & 0x3F) << 8) | data[offset + 1]
            if not jumped: end = offset + 2
            offset, jumped = ptr, True
            continue
        if size > 63 or offset + 1 + size > len(data):
            raise ValueError('invalid DNS label')
        labels.append(data[offset + 1:offset + 1 + size].decode('ascii', errors='replace'))
        offset += 1 + size
        if not jumped: end = offset
    raise ValueError('truncated DNS name')

def _parse_dns(data):
    """Minimaler DNS-Parser für Query-Namen, Typen und TXT-Antworten."""
    if len(data) < 12: return None
    ident, flags, qdcount, ancount = _struct.unpack_from('>HHHH', data, 0)
    offset, questions = 12, []
    try:
        for _ in range(min(qdcount, 8)):
            name, offset = _dns_name(data, offset)
            if offset + 4 > len(data): return None
            qtype, qclass = _struct.unpack_from('>HH', data, offset)
            offset += 4
            questions.append((name.rstrip('.').lower(), qtype, qclass))
        txt = []
        for _ in range(min(ancount, 16)):
            _, offset = _dns_name(data, offset)
            if offset + 10 > len(data): break
            rtype, _rclass, _ttl, rdlen = _struct.unpack_from('>HHIH', data, offset)
            offset += 10
            rdata = data[offset:offset + rdlen]
            offset += rdlen
            if rtype == 16:
                pos = 0
                while pos < len(rdata):
                    n = rdata[pos]; pos += 1
                    txt.append(rdata[pos:pos+n].decode('utf-8', errors='replace'))
                    pos += n
        return {'id': ident, 'response': bool(flags & 0x8000),
                'questions': questions, 'txt': txt}
    except (ValueError, IndexError, struct.error):
        return None

def _decode_base32hex(value):
    """Dekodiert Base32hex nach HTML-Unescape; ungültige Daten liefern None."""
    value = html.unescape(value or '').strip().replace('.', '')
    if not value or not re.fullmatch(r'[0-9a-vA-V]+', value):
        return None
    try:
        padded = value.upper() + '=' * (-len(value) % 8)
        raw = base64.b32hexdecode(padded)
        text = raw.decode('utf-8', errors='replace').replace('\x00', '')
        return ''.join(ch for ch in text if ch in '\n\r\t' or ord(ch) >= 32).strip()
    except Exception:
        return None

def _dns_tunnel_payload(name):
    """Liefert (hb|oe, zusammengefügtes Base32hex) vor dns-<session>."""
    labels = [html.unescape(x) for x in (name or '').strip('.').split('.') if x]
    marker_idx = next((i for i, x in enumerate(labels) if x.lower() in ('hb', 'oe')), None)
    if marker_idx is None:
        return None, None
    end = next((i for i in range(marker_idx + 1, len(labels))
                if re.fullmatch(r'dns-[a-z0-9_-]+', labels[i], re.I)), len(labels))
    encoded = ''.join(labels[marker_idx + 1:end])
    return labels[marker_idx].lower(), encoded

class TunnelSniffer:
    """
    Snifft TCP-Streams zu bekannten Reverse Shell Verbindungen.
    Zeigt Befehle (inbound) und Ausgaben (outbound) in Echtzeit.
    Benötigt CAP_NET_RAW (docker exec --privileged).
    """
    def __init__(self):
        self.tracked   = {}  # (src,sp,dst,dp) → {'buf': bytearray, 'dir': str}
        self.udp_active = {} # (remote_ip, remote_port, local_port) → Metadaten
        self.dns_hits   = collections.defaultdict(collections.deque)
        self.dns_domains = {} # Basisdomain → letzter verdächtiger Zeitpunkt
        self.udp_hits   = collections.defaultdict(collections.deque)
        self.udp_seen   = {}  # AF_PACKET kann Loopback-Frames doppelt liefern
        self.dns_decoded_seen = {} # Protokoll-Retransmits nicht doppelt anzeigen
        self.udp_owner_cache = {} # local_port → (PID, monotonic timestamp)
        self.lock      = threading.Lock()
        self._running  = False
        self._thread   = None
        self._sock     = None

    def start(self, alert_fn, safe_check_fn, private_check_fn):
        try:
            # ETH_P_ALL (0x0003) – fängt ALLE Interfaces inkl. Loopback
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                       socket.htons(0x0003))
            self._sock.settimeout(0.5)
            self._running = True
            self._udp_owner_thread = threading.Thread(
                target=self._udp_owner_loop, daemon=True)
            self._udp_owner_thread.start()
            self._thread  = threading.Thread(
                target=self._loop, args=(alert_fn, safe_check_fn, private_check_fn),
                daemon=True)
            self._thread.start()
            return True
        except PermissionError:
            return False

    def track(self, rem_ip, rem_port, local_port):
        key_in  = (rem_ip,    rem_port, '0.0.0.0', local_port)
        key_out = ('0.0.0.0', local_port, rem_ip,  rem_port)
        with self.lock:
            for k, direction in [(key_in, 'IN ←'), (key_out, 'OUT→')]:
                if k not in self.tracked:
                    self.tracked[k] = {'buf': bytearray(), 'dir': direction,
                                       'remote': f'{rem_ip}:{rem_port}',
                                       'rem_ip': rem_ip, 'rem_port': rem_port,
                                       'local_port': local_port}

    @staticmethod
    def _owner_pid(info):
        """Ermittelt den Besitzer genau dieser TCP-Verbindung über deren Inode."""
        try:
            for conn in read_tcp('/proc/net/tcp'):
                if (conn['state'] == '01' and
                        conn['rem_ip'] == info.get('rem_ip') and
                        conn['rem_port'] == info.get('rem_port') and
                        conn['local_port'] == info.get('local_port')):
                    return inode_to_pid(conn['inode']) or '?'
        except Exception:
            pass
        return '?'

    def _udp_owner_loop(self):
        """Merkt kurzlebige UDP-Socket-Besitzer, bevor ihr Socket verschwindet."""
        while self._running:
            try:
                inode_ports = {c['inode']: c['local_port']
                               for c in read_tcp('/proc/net/udp')}
                if inode_ports:
                    now = time.monotonic()
                    for pid in list_proc_pids():
                        if not pid.isdigit(): continue
                        try:
                            for fd in os.listdir(f'/proc/{pid}/fd'):
                                m = re.fullmatch(r'socket:\[(\d+)\]',
                                    os.readlink(f'/proc/{pid}/fd/{fd}'))
                                if not m or m.group(1) not in inode_ports: continue
                                owner = pid
                                cmd = get_cmdline(pid)
                                if re.search(r'\b(?:dig|nslookup|host|drill|resolvectl)\b', cmd, re.I):
                                    parent = get_ppid(pid)
                                    if parent and parent not in ('0', '1'):
                                        owner = parent
                                with self.lock:
                                    self.udp_owner_cache[inode_ports[m.group(1)]] = (owner, now)
                        except (FileNotFoundError, PermissionError, ProcessLookupError):
                            pass
                    with self.lock:
                        self.udp_owner_cache = {
                            port: value for port, value in self.udp_owner_cache.items()
                            if now - value[1] < 8
                        }
            except Exception:
                pass
            time.sleep(0.02)

    def _udp_owner_pid(self, local_port, rem_ip=None, rem_port=None):
        """Ordnet einen UDP-Quellport möglichst früh seinem Prozess zu."""
        try:
            fallback = None
            for conn in read_tcp('/proc/net/udp'):
                if conn['local_port'] != local_port:
                    continue
                pid = inode_to_pid(conn['inode'])
                if not pid:
                    continue
                if (rem_ip and rem_port and conn['rem_ip'] == rem_ip and
                        conn['rem_port'] == rem_port):
                    return pid
                fallback = fallback or pid
            if fallback:
                return fallback
            with self.lock:
                cached = self.udp_owner_cache.get(local_port)
            if cached and time.monotonic() - cached[1] < 8:
                return cached[0]
            return '?'
        except Exception:
            return '?'

    @staticmethod
    def _likely_shell_pid():
        """Fallback nur bei genau einem eindeutig shellartigen Langläufer."""
        candidates = []
        shell_re = re.compile(
            r'^\[(?:kworker|ksoftirqd|migration|rcu)[^]]*\].*\s-i\b|'
            r'\b(?:dnscat|iodine|dns2tcp|dns[-_]?shell|heyoka)\b|'
            r'(?:^|/)(?:ba)?sh\s+-i\b', re.I)
        try:
            for pid in list_proc_pids():
                if pid.isdigit() and shell_re.search(get_cmdline(pid)):
                    candidates.append(pid)
        except Exception:
            pass
        return candidates[0] if len(candidates) == 1 else '?'

    @staticmethod
    def _display_pid(pid):
        """Bei kurzlebigen DNS-Helfern möglichst den langlebigen Elternprozess zeigen."""
        if not pid or pid == '?': return '?'
        cmd = get_cmdline(str(pid))
        if re.search(r'\b(?:dig|nslookup|host|drill|resolvectl)\b', cmd, re.I):
            parent = get_ppid(str(pid))
            if parent and parent not in ('0', '1') and get_cmdline(parent):
                return parent
        return str(pid)

    @staticmethod
    def _dns_base(name):
        labels = [x for x in name.split('.') if x]
        return '.'.join(labels[-2:]) if len(labels) >= 2 else name

    @staticmethod
    def _encoded_label(label):
        if len(label) < 20: return False
        compact = label.replace('-', '').replace('_', '')
        if not compact: return False
        allowed = sum(ch.isalnum() for ch in compact) / len(compact)
        return allowed > 0.95 and len(set(compact.lower())) >= 8

    def _dns_suspicious(self, name, qtype, src_ip, dst_ip):
        now = time.monotonic()
        base = self._dns_base(name)
        key = (src_ip, dst_ip, base)
        hits = self.dns_hits[key]
        hits.append((now, name))
        while hits and now - hits[0][0] > 15:
            hits.popleft()
        labels = name.split('.')
        longest = max((len(x) for x in labels), default=0)
        encoded = any(self._encoded_label(x) for x in labels[:-2] or labels)
        unique = len({n for _, n in hits})
        tool_mark = bool(re.search(r'(?:dnscat|iodine|dns2tcp|dns[-_]?shell|heyoka)', name, re.I))
        suspicious = (
            tool_mark or qtype == 10 or
            (qtype == 16 and (encoded or len(name) >= 50)) or
            (encoded and len(hits) >= 3) or
            (len(hits) >= 6 and unique >= 4)
        )
        if suspicious:
            self.dns_domains[base] = now
        return suspicious or now - self.dns_domains.get(base, -9999) < 60, base

    def _open_udp_session(self, alert_fn, remote, pid, local_port, shell_kind, detail):
        scope = 'privat' if is_private_ip(remote.rsplit(':', 1)[0]) else 'öffentlich'
        is_new = not session_monitor.is_open(remote)
        if is_new:
            alert_fn('CRITICAL', f"TUNNEL SESSION AKTIV → {remote} [{scope}]",
                     f"PID={pid}  UDP_LOCAL={local_port}  Shell: {shell_kind}")
            session_monitor.open_session(remote, pid, shell_kind)
            alert_fn('CRITICAL', detail, f"PID={pid}  UDP-Session: {remote}")

    def _log_dns_decoded(self, remote, direction, kind, text, pid):
        """Schreibt nur dekodierte Nutzdaten, ohne DNS-Protokollrauschen."""
        if not text: return
        now = time.monotonic()
        key = (remote, kind, text)
        if now - self.dns_decoded_seen.get(key, -9999) < 15:
            return
        self.dns_decoded_seen[key] = now
        if len(self.dns_decoded_seen) > 512:
            self.dns_decoded_seen = {
                k:v for k,v in self.dns_decoded_seen.items() if now - v < 60
            }
        if kind == 'cmd':
            compact = text.replace('\r', '').replace('\n', ' ↵ ')
            session_monitor.log(remote, 'IN ←', f'DNS CMD: {compact}', pid)
        else:
            lines = text.replace('\r', '').split('\n')
            for line in lines:
                if line:
                    session_monitor.log(remote, 'OUT→', line, pid)

    def _handle_udp(self, src_ip, dst_ip, data, alert_fn):
        udp = _parse_udp(data)
        if not udp: return
        sport, dport, payload = udp
        if not payload: return
        now = time.monotonic()
        seen_key = (src_ip, sport, dst_ip, dport, hash(payload))
        if now - self.udp_seen.get(seen_key, -9999) < 0.75:
            return
        self.udp_seen[seen_key] = now
        if len(self.udp_seen) > 2048:
            self.udp_seen = {k:v for k,v in self.udp_seen.items() if now - v < 5}

        # DNS: Query- und TXT-Inhalte erkennen und derselben Session zuordnen.
        if sport == 53 or dport == 53:
            dns = _parse_dns(payload)
            if not dns or not dns['questions']: return
            name, qtype, _qclass = dns['questions'][0]
            type_name = {1:'A', 5:'CNAME', 10:'NULL', 16:'TXT', 28:'AAAA'}.get(qtype, str(qtype))
            if dport == 53:
                remote_ip, local_port, direction = dst_ip, sport, 'OUT→'
                suspicious, base = self._dns_suspicious(name, qtype, src_ip, dst_ip)
                if not suspicious: return
                raw_pid = self._udp_owner_pid(local_port, remote_ip, 53)
                if raw_pid == '?': raw_pid = self._likely_shell_pid()
                pid = self._display_pid(raw_pid)
                remote = f'{remote_ip}:53'
                with self.lock:
                    self.udp_active[(remote_ip, 53, local_port)] = {
                        'remote': remote, 'pid': pid, 'last': time.monotonic(),
                        'kind': 'UDP/DNS-Tunnel', 'base': base,
                    }
                self._open_udp_session(alert_fn, remote, pid, local_port, 'UDP/DNS-Tunnel',
                                       f'DNS-TUNNEL ERKANNT – {base}')
                marker, encoded = _dns_tunnel_payload(name)
                # Heartbeats und Protokoll-Metadaten bleiben unsichtbar. oe.
                # enthält die aus mehreren Labels zusammengesetzte Ausgabe.
                if marker == 'oe':
                    decoded = _decode_base32hex(encoded)
                    self._log_dns_decoded(remote, 'OUT→', 'out', decoded, pid)
                return

            key = (src_ip, 53, dport)
            with self.lock:
                info = self.udp_active.get(key)
                if info: info['last'] = time.monotonic()
            if not info: return
            # Nur cmd=<Base32hex> ist Nutzlast. sid=, ack, Heartbeats,
            # Zeitstempel und sonstige DNS-Metadaten werden nicht angezeigt.
            for value in dns['txt']:
                value = html.unescape(value).strip()
                m = re.fullmatch(r'cmd=([0-9a-vA-V]+)', value)
                if not m: continue
                decoded = _decode_base32hex(m.group(1))
                self._log_dns_decoded(info['remote'], 'IN ←', 'cmd', decoded, info['pid'])
            return

        # Beliebige UDP-Reverse-Shell: erst bei Shell-Inhalt alarmieren.
        printable = ''.join(chr(b) if 32 <= b < 127 or b in (9,10,13) else ' ' for b in payload).strip()
        if len(printable) < 2: return
        remote_ip, remote_port, local_port, direction = dst_ip, dport, sport, 'OUT→'
        raw_pid = self._udp_owner_pid(local_port, remote_ip, remote_port)
        if raw_pid == '?':
            inbound_pid = self._udp_owner_pid(dport, src_ip, sport)
            if inbound_pid != '?':
                remote_ip, remote_port, local_port, direction = src_ip, sport, dport, 'IN ←'
                raw_pid = inbound_pid
        pid = self._display_pid(raw_pid)
        strong = re.search(r'KPDG_[SE]_|uid=\d+\(|/bin/(?:ba)?sh|bash\s+-i|root:x:0:', printable, re.I)
        weak = re.search(r'^(?:id|whoami|pwd|uname(?:\s+-a)?|ls(?:\s+-la)?|cat\s+/etc/\w+)\s*$', printable, re.I)
        hit_key = (src_ip, sport, dst_ip, dport)
        hits = self.udp_hits[hit_key]
        if strong or weak: hits.append(now)
        while hits and now - hits[0] > 10: hits.popleft()
        if not strong and len(hits) < 2: return
        remote = f'{remote_ip}:{remote_port}'
        with self.lock:
            self.udp_active[(remote_ip, remote_port, local_port)] = {
                'remote': remote, 'pid': pid, 'last': now,
                'kind': 'UDP-Reverse-Shell', 'base': '',
            }
        self._open_udp_session(alert_fn, remote, pid, local_port, 'UDP-Reverse-Shell',
                               'UDP REVERSE SHELL ERKANNT')
        session_monitor.log(remote, direction, printable[:240], pid)

    def _expire_udp(self, alert_fn):
        now, expired = time.monotonic(), []
        with self.lock:
            for key, info in list(self.udp_active.items()):
                if now - info.get('last', now) > 45:
                    expired.append((key, info))
                    self.udp_active.pop(key, None)
        for _key, info in expired:
            remote = info['remote']
            if not any(x.get('remote') == remote for x in self.udp_active.values()):
                alert_fn('MEDIUM', f'TUNNEL SESSION BEENDET ← {remote}',
                         f"PID={info.get('pid', '?')}  UDP-Timeout")
                session_monitor.close_session(remote)

    def _loop(self, alert_fn, is_safe, is_private):
        PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

        # Muster für aktive Shell-Sessions im Tunnel
        SHELL_PROMPT_RE = re.compile(r'[\w@\-]+:/[\w./~-]*\s*[#$]')
        # ARTEX/KPDG command framing is a strong shell signal.  The actual
        # wire form is commonly "echo; echo 'KPDG_S_<hex>'", so the old
        # "echo + token" expression missed reconnects without a shell prompt.
        CMD_MARKER_RE   = re.compile(
            r"KPDG_[SE]_[0-9a-f]{10,}|echo\s+['\"]?[A-Z0-9_]{10,}",
            re.IGNORECASE,
        )
        SHELL_OUT_RE    = re.compile(
            r'uid=\d+\(|gid=\d+\('
            r'|root:x:0:0'
            r'|/etc/passwd|/etc/shadow'
            r'|\btotal\s+\d+$'
            r'|drwx|drwxr'
        )
        HTTP_STATUS_RE  = re.compile(r'^HTTP/[\d.]+ (\d{3})\s')
        HTTP_HEADER_RE  = re.compile(
            r'^(Date|Server|Content-Type|Content-Length|Content-Encoding|'
            r'Vary|Cache-Control|X-Powered-By|Transfer-Encoding|'
            r'Connection|Keep-Alive|Accept-Ranges|ETag|Last-Modified|'
            r'Strict-Transport|Access-Control|X-Frame|X-XSS):'
        )
        INTERESTING_RE  = re.compile(
            r'password|passwd|secret|token|flag|key\b|admin|'
            r'<script|alert\(|onerror=|onload=|eval\(|'
            r'traversal|lfi|rfi|injection|BRIEFING|'
            r'File not found|path.*need.*traversal',
            re.IGNORECASE
        )

        # Pro Verbindung: HTTP-Zustand merken
        conn_http = {}  # id(info) → {'phase': 'headers'|'body'|None, 'status': 0}

        while self._running:
            try:
                raw = self._sock.recv(65535)
            except socket.timeout:
                self._expire_udp(alert_fn)
                continue
            except Exception:
                break

            ip = _parse_eth(raw)
            if not ip: continue
            parsed = _parse_ip(ip)
            if not parsed: continue
            proto, src_ip, dst_ip, rest = parsed
            if proto == 17:
                self._handle_udp(src_ip, dst_ip, rest, alert_fn)
                continue
            if proto != 6: continue

            tcp = _parse_tcp(rest)
            if not tcp: continue
            sport, dport, seq, flags, payload = tcp
            if not payload: continue

            with self.lock:
                for (r_ip, r_port, l_ip, l_port), info in list(self.tracked.items()):
                    if ((src_ip == r_ip and sport == r_port and dport == l_port) or
                        (dst_ip == r_ip and dport == r_port and sport == l_port)):
                        info['buf'].extend(payload)
                        cid = id(info)
                        if cid not in conn_http:
                            conn_http[cid] = {'phase': None, 'status': 0}
                        st = conn_http[cid]

                        while b'\n' in info['buf']:
                            idx  = info['buf'].index(b'\n')
                            line = bytes(info['buf'][:idx])
                            info['buf'] = info['buf'][idx+1:]

                            printable = bytes(b for b in line if b in PRINTABLE)
                            text = printable.decode('ascii', errors='replace').strip()
                            if not text or len(text) < 3:
                                continue

                            # Binary-Content-Filter
                            _r = sum(1 for _x in text if _x.isalnum() or _x in " .,:/@ ")
                            if len(text) > 4 and _r / len(text) < 0.35: continue


                            remote = info['remote']
                            scope  = 'privat' if is_private(remote.split(':')[0]) else 'öffentlich'
                            ext    = scope == 'öffentlich'

                            # ── HTTP Status-Zeile ────────────────────────────
                            m = HTTP_STATUS_RE.match(text)
                            if m:
                                st['phase']  = 'headers'
                                st['status'] = int(m.group(1))
                                alert_fn('HIGH' if ext else 'LOW',
                                    f"TUNNEL HTTP [{info['dir']}] {remote} [{scope}]",
                                    f"Status: {text[:80]}")
                                continue

                            # ── Reine HTTP-Standard-Header überspringen ───────
                            if st['phase'] == 'headers':
                                # Binary Content-Type → body komplett überspringen
                                if re.match(r'content-type:.*(?:octet-stream|x-exec|x-elf|zip|gzip|tar|binary)', text, re.IGNORECASE):
                                    st['phase'] = 'binary'
                                    continue
                                if re.match(r"content-type:.*octet-stream|x-exec|x-elf", text, re.IGNORECASE): st["phase"]="binary"; continue
                                if HTTP_HEADER_RE.match(text):
                                    continue
                                if not text:
                                    st['phase'] = 'body'
                                    continue

                            # Binärer Body komplett überspringen
                            if st['phase'] == 'binary':
                                continue

                            # ── HTTP Request-Zeile ────────────────────────────
                            if re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+/', text):
                                alert_fn('HIGH' if ext else 'MEDIUM',
                                    f"TUNNEL REQUEST [{info['dir']}] {remote} [{scope}]",
                                    f"Request: {text[:150]}")
                                continue

                            # ── Authorization Header (Credentials!) ───────────
                            if re.match(r'^authorization:', text, re.IGNORECASE):
                                alert_fn('CRITICAL',
                                    f"TUNNEL CREDENTIALS [{info['dir']}] {remote} [{scope}]",
                                    f"Header: {text[:150]}")
                                continue

                            # ── Shell-Prompt = aktive interaktive Shell ────────
                            if SHELL_PROMPT_RE.search(text):
                                owner_pid = self._owner_pid(info)
                                info['pid'] = owner_pid
                                # Session öffnen falls noch nicht offen
                                if not session_monitor.is_open(remote):
                                    if owner_pid != '?':
                                        alert_fn('CRITICAL',
                                            f"TUNNEL SESSION AKTIV → {remote} [{scope}]",
                                            f"PID={owner_pid}  Shell: Raw-Socket-Prompt")
                                        session_monitor.open_session(remote, owner_pid, 'Raw-Socket-Prompt')
                                if owner_pid != '?':
                                    session_monitor.log(remote, info['dir'], text, owner_pid)
                                alert_fn('CRITICAL',
                                    f"TUNNEL SHELL PROMPT [{info['dir']}] {remote} [{scope}]",
                                    f"Prompt: {text[:150]}")
                                continue

                            # ── C2 Command-Marker (echo XXXXXXXXXXX; (cmd)) ───
                            if CMD_MARKER_RE.search(text):
                                # Marker bedeutet, dass über diese TCP-Verbindung
                                # tatsächlich Shell-Befehle laufen. Auch nach einem
                                # kurzen Disconnect die Session wieder öffnen.
                                owner_pid = self._owner_pid(info)
                                info['pid'] = owner_pid
                                if not session_monitor.is_open(remote):
                                    # Kein lebender Socket-Besitzer: Das ist ein
                                    # gepuffertes Paket einer bereits beendeten
                                    # Session, keine neue Shell.
                                    if owner_pid != '?':
                                        alert_fn('CRITICAL',
                                            f"TUNNEL SESSION AKTIV → {remote} [{scope}]",
                                            f"PID={owner_pid}  Shell: KPDG-Command-Stream")
                                        session_monitor.open_session(remote, owner_pid, 'KPDG-Command-Stream')
                                if owner_pid != '?':
                                    session_monitor.log(remote, info['dir'], text, owner_pid)
                                alert_fn('CRITICAL',
                                    f"TUNNEL CMD-MARKER [{info['dir']}] {remote} [{scope}]",
                                    f"Marker: {text[:150]}")
                                continue

                            # ── Sensible Ausgaben (id, passwd, ls-Ausgabe) ─────
                            if SHELL_OUT_RE.search(text):
                                if session_monitor.is_open(remote):
                                    owner_pid = info.get('pid') or self._owner_pid(info)
                                    info['pid'] = owner_pid
                                    session_monitor.log(remote, info['dir'], text, owner_pid)
                                alert_fn('CRITICAL',
                                    f"TUNNEL SENSITIVE OUTPUT [{info['dir']}] {remote} [{scope}]",
                                    f"Daten: {text[:200]}")
                                continue

                            if st.get("phase") == "binary": continue
                            # ── HTML-Body: nur interessante Zeilen ───────────
                            if st['phase'] == 'body':
                                if INTERESTING_RE.search(text):
                                    alert_fn('HIGH' if ext else 'MEDIUM',
                                        f"TUNNEL INTERESSANT [{info['dir']}] {remote} [{scope}]",
                                        f"Daten: {text[:200]}")
                                continue  # uninteressante HTML-Zeilen silent

                            # ── Rohdaten außerhalb HTTP (z.B. Shell-Rohdaten) ─
                            # Rate-Limiting: max 15 Alerts pro 5s pro Verbindung
                            import time as _t2
                            _now2 = _t2.monotonic()
                            if _now2 - st.get('rl_ts', 0) > 5:
                                st['rl_cnt'] = 0; st['rl_ts'] = _now2
                            st['rl_cnt'] = st.get('rl_cnt', 0) + 1
                            if st['rl_cnt'] > 15: continue

                            # Nur zeigen wenn kein HTTP-Kontext → wahrscheinlich Shell
                            sev = ('CRITICAL' if ext else 'MEDIUM') if not st['phase'] else ('HIGH' if ext else 'LOW')

                            # In Session loggen wenn eine offen ist
                            if session_monitor.is_open(remote):
                                owner_pid = info.get('pid') or self._owner_pid(info)
                                info['pid'] = owner_pid
                                session_monitor.log(remote, info['dir'], text, owner_pid)
                            else:
                                alert_fn(sev,
                                    f"TUNNEL INHALT [{info['dir']}] {remote} [{scope}]",
                                    f"Daten: {text[:200]}")

                            for pat, lbl, pat_sev in compiled:
                                if pat.search(text):
                                    alert_fn(pat_sev if ext else 'LOW',
                                        f"TUNNEL VERDÄCHTIG – {lbl}",
                                        f"Daten: {text[:120]}")
                                    break

    def add_suspicious_conn(self, rem_ip, rem_port, local_port):
        self.track(rem_ip, rem_port, local_port)

    def stop(self):
        self._running = False
        if self._sock:
            try: self._sock.close()
            except: pass

sniffer = TunnelSniffer()

# ── Session Monitor ───────────────────────────────────────────────────
import datetime

class SessionMonitor:
    """
    Öffnet automatisch ein dediziertes Log wenn eine Reverse Shell erkannt wird.
    Zeigt alle Befehle (IN) und Ausgaben (OUT) getrennt und schreibt in eine Datei.
    """
    def __init__(self):
        self.sessions = {}   # remote → {'file': path, 'fh': filehandle, 'started': time}
        self._lock    = threading.Lock()

    def _banner(self, remote, logfile):
        ts_str = datetime.datetime.now().strftime('%H:%M:%S')
        banner = (
            f"\n{RED}{BOLD}"
            f"╔══════════════════════════════════════════════════════════════╗\n"
            f"║  ⚠  REVERSE SHELL SESSION ERKANNT  ⚠                        ║\n"
            f"║  Remote : {remote:<50}  ║\n"
            f"║  Start  : {ts_str:<50}  ║\n"
            f"╠══════════════════════════════════════════════════════════════╣\n"
            f"║  Session-Log öffnen (neues Terminal):                       ║\n"
            f"║  tail -f {logfile:<51} ║\n"
            f"╚══════════════════════════════════════════════════════════════╝"
            f"{NC}\n"
        )
        print(banner, flush=True)

    def open_session(self, remote, pid='?', shell_cmd=''):
        """Startet eine neue Session für eine erkannte Reverse Shell."""
        with self._lock:
            if remote in self.sessions:
                return  # Bereits offen

            ts  = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
            safe_remote = re.sub(r'[^A-Za-z0-9_-]+', '_', remote).strip('_') or 'unknown'
            logfile = f"/tmp/artex-session-{safe_remote}-{ts}.log"

            try:
                fh = open(logfile, 'w', buffering=1)
            except Exception as e:
                print(f"[Session] Log konnte nicht geöffnet werden: {e}", flush=True)
                return

            self.sessions[remote] = {
                'file':    logfile,
                'fh':      fh,
                'started': datetime.datetime.now(),
                'cmds':    0,
            }

            # Log-Header schreiben
            fh.write(f"{'='*64}\n")
            fh.write(f"ARTEX Reverse Shell Session Log\n")
            fh.write(f"Remote   : {remote}\n")
            fh.write(f"Start    : {datetime.datetime.now()}\n")
            fh.write(f"PID      : {pid}\n")
            fh.write(f"Shell    : {shell_cmd[:80]}\n")
            fh.write(f"{'='*64}\n\n")
            fh.flush()

            self._banner(remote, logfile)

    def log(self, remote, direction, text, pid='?'):
        """Loggt eine Zeile in die Session-Datei + formatierte Ausgabe."""
        with self._lock:
            if remote not in self.sessions:
                return

            sess = self.sessions[remote]
            ts   = datetime.datetime.now().strftime('%H:%M:%S.%f')[:12]

            # Richtung: IN ← = Angreifer → Shell (Befehle)
            #           OUT→ = Shell → Angreifer (Ausgaben)
            if 'IN' in direction or '←' in direction:
                prefix_file  = f"[{ts}] → CMD  "
                prefix_term  = f"{RED}→ CMD {NC}"
                color         = RED
            else:
                prefix_file  = f"[{ts}] ← OUT  "
                prefix_term  = f"{GREEN}← OUT {NC}"
                color         = GREEN

            # In Datei schreiben
            sess['fh'].write(f"{prefix_file}: {text}\n")
            sess['fh'].flush()

            # Im Hauptterminal kompakt anzeigen
            ts_short = datetime.datetime.now().strftime('%H:%M:%S')
            print(
                f"{DIM}[{ts_short}]{NC} "
                f"{RED}{BOLD}[SESSION]{NC} "
                f"{DIM}PID={pid or '?'}{NC} "
                f"{color}{direction:<5}{NC} "
                f"{DIM}{remote}{NC} "
                f"{BOLD}{text[:120]}{NC}",
                flush=True
            )

            # Output auf kritische Muster pruefen (Rootkit, Anti-Monitor, Exfil)
            if 'OUT' in direction or '\u2192' in direction or 'OUT' in direction:
                for _op, _ol, _os in _output_compiled:
                    if _op.search(text):
                        alert(_os, f'SESSION OUTPUT: {_ol}',
                              f'Remote={remote}  PID={pid}  Text={text[:120]}')
                        break
            sess['cmds'] += 1

    def close_session(self, remote):
        """Schließt eine Session und schreibt Zusammenfassung."""
        with self._lock:
            if remote not in self.sessions:
                return
            sess = self.sessions.pop(remote)
            duration = datetime.datetime.now() - sess['started']
            summary = (
                f"\n{'='*64}\n"
                f"Session beendet: {datetime.datetime.now()}\n"
                f"Dauer          : {duration}\n"
                f"Aktivitäten    : {sess['cmds']}\n"
                f"{'='*64}\n"
            )
            sess['fh'].write(summary)
            sess['fh'].close()
            print(
                f"\n{YELLOW}{BOLD}[SESSION ENDED]{NC} {remote} "
                f"(Dauer: {str(duration).split('.')[0]}, "
                f"Aktivitäten: {sess['cmds']})\n"
                f"  Log: {sess['file']}\n",
                flush=True
            )

    def is_open(self, remote):
        with self._lock:
            return remote in self.sessions

session_monitor = SessionMonitor()

# ── Bekannte sichere Verbindungen (Docker-Stack) ─────────────────────
SAFE_PORTS_LOCAL  = {8787, 8788, 5432, 4000, 443, 80}
SAFE_REMOTE_PORTS = {5432, 4000}

def is_docker_internal(ip):
    return (ip.startswith('172.') or ip.startswith('192.168.')
            or ip in ('127.0.0.1', '0.0.0.0', '::'))

def is_private_ip(ip):
    """RFC 1918 + Link-Local + Loopback – nicht öffentlich erreichbar."""
    return (
        ip.startswith('10.')          or   # 10.0.0.0/8
        ip.startswith('192.168.')     or   # 192.168.0.0/16
        ip.startswith('127.')         or   # loopback
        ip.startswith('169.254.')     or   # link-local
        ip in ('0.0.0.0', '::')       or
        any(ip.startswith(f'172.{i}.') for i in range(16, 32))  # 172.16-31.x
    )

def classify_severity(rem_ip, rem_port, base_severity):
    """
    Stuft Severity herunter wenn Ziel eine private IP ist.
    Reverse Shell zu 10.x.x.x ist immer noch verdächtig,
    aber kein CRITICAL/HIGH – eher INFO/MEDIUM.
    """
    if is_private_ip(rem_ip):
        downgrade = {'CRITICAL': 'MEDIUM', 'HIGH': 'LOW', 'MEDIUM': 'LOW'}
        return downgrade.get(base_severity, base_severity)
    return base_severity

# ── Bekannte C2/Angriffs-Ports ────────────────────────────────────────
C2_PORTS = {
    4444:  'Metasploit default',
    4445:  'Metasploit',
    4446:  'Metasploit',
    5555:  'Metasploit/ADB',
    1234:  'C2 typisch',
    1337:  'C2 typisch',
    31337: 'Back Orifice/C2',
    8888:  'Empire C2',
    8080:  'C2/Proxy (non-standard)',
    9001:  'Tor/C2',
    9002:  'C2',
    6666:  'C2/IRC',
    6667:  'IRC-basiertes C2',
    6668:  'IRC C2',
    6669:  'IRC C2',
    7777:  'C2 typisch',
    1111:  'C2 typisch',
    2222:  'Alt-SSH/C2',
    3333:  'C2 typisch',
    5000:  'C2/Flask',
    8443:  'Cobalt Strike / HTTPS C2',
    8888:  'Empire / Jupyter',
    9999:  'C2 typisch',
    10000: 'C2/Webmin',
    12345: 'NetBus/C2',
    54321: 'C2 reversed',
    65535: 'C2 max port',
    443:   None,  # legitim wenn zu bekanntem Host
    80:    None,
}

# ── Reverse Shell & Attack Patterns ──────────────────────────────────
# Format: (regex, label, severity)  severity: CRITICAL / HIGH / MEDIUM
PATTERNS = [

    # ── Reverse Shells: Bash / Sh ──────────────────────────────
    (r'bash\s+-i\s*>&?\s*/dev/tcp/',     'REVERSE SHELL – bash /dev/tcp',      'CRITICAL'),
    (r'bash\s+-i',                        'REVERSE SHELL – bash -i',            'CRITICAL'),
    (r'/bin/(?:ba)?sh\s+-i',              'REVERSE SHELL – sh -i',              'CRITICAL'),
    (r'0>&1',                             'REVERSE SHELL – stdout redirect',    'HIGH'),
    (r'/dev/tcp/\d',                      'REVERSE SHELL – /dev/tcp',           'CRITICAL'),
    (r'/dev/udp/\d',                      'REVERSE SHELL – /dev/udp',           'CRITICAL'),
    (r'exec\s+\d+<>/dev/tcp/',           'REVERSE SHELL – exec /dev/tcp fd',   'CRITICAL'),

    # ── Reverse Shells: Netcat ─────────────────────────────────
    (r'\bnc\b.*-[ec]\s',                  'REVERSE SHELL – nc exec',            'CRITICAL'),
    (r'\bncat\b.*-[ec]\s',                'REVERSE SHELL – ncat exec',          'CRITICAL'),
    (r'\bnetcat\b.*-[ec]\s',              'REVERSE SHELL – netcat exec',        'CRITICAL'),
    (r'\bnc\b\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{2,5}',
                                          'NETCAT – Verbindung zu Host:Port',   'HIGH'),
    (r'\bnc\b.*mkfifo|mkfifo.*\bnc\b',   'REVERSE SHELL – mkfifo+nc',         'CRITICAL'),
    (r'\bnc\b.*-l.*-p',                   'BIND SHELL – nc listen',             'HIGH'),
    (r'rm\s+/tmp/[a-z];mkfifo',          'REVERSE SHELL – mkfifo Pipe',        'CRITICAL'),

    # ── Reverse Shells: Socat ──────────────────────────────────
    (r'socat\s+TCP[46]?:',               'REVERSE SHELL – socat TCP',          'CRITICAL'),
    (r'socat\s+.*EXEC',                   'REVERSE SHELL – socat exec',         'CRITICAL'),
    (r'socat\s+.*pty',                    'SHELL UPGRADE – socat pty',          'HIGH'),
    (r'socat\s+file:`tty`',              'SHELL UPGRADE – socat tty',          'HIGH'),
    (r'socat\s+.*OPENSSL',               'REVERSE SHELL – socat SSL',          'CRITICAL'),

    # ── Reverse Shells: Python ────────────────────────────────
    (r'python[23]?\s+-c\s+.*socket',     'REVERSE SHELL – Python socket',      'CRITICAL'),
    (r'python[23]?\s+-c\s+.*connect',    'REVERSE SHELL – Python connect',     'CRITICAL'),
    (r'python[23]?\s+-c\s+.*SOCK_STREAM','REVERSE SHELL – Python TCP',         'CRITICAL'),
    (r'import\s+pty[;\s].*spawn',        'SHELL UPGRADE – Python pty.spawn',   'HIGH'),
    (r'pty\.spawn\(["\']',               'SHELL UPGRADE – pty.spawn',          'HIGH'),
    (r'python[23]?\s+-c\s+.*subprocess.*sh',
                                          'REVERSE SHELL – Python subprocess',  'CRITICAL'),
    (r'python[23]?\s+-c\s+.*os\.system.*sh',
                                          'REVERSE SHELL – Python os.system',   'CRITICAL'),

    # ── Reverse Shells: Perl ──────────────────────────────────
    (r'perl\s+-e\s+.*[Ss]ocket',         'REVERSE SHELL – Perl Socket',        'CRITICAL'),
    (r'perl\s+-e\s+.*connect',           'REVERSE SHELL – Perl connect',       'CRITICAL'),
    (r'perl\s+-e\s+.*SOCK_STREAM',       'REVERSE SHELL – Perl TCP',           'CRITICAL'),
    (r'perl\s+-e\s+.*exec.*sh',          'REVERSE SHELL – Perl exec sh',       'CRITICAL'),

    # ── Reverse Shells: Ruby ──────────────────────────────────
    (r'ruby\s+-rsocket',                  'REVERSE SHELL – Ruby socket',        'CRITICAL'),
    (r'ruby\s+-e\s+.*TCPSocket',         'REVERSE SHELL – Ruby TCPSocket',     'CRITICAL'),
    (r'ruby\s+-e\s+.*exec.*sh',          'REVERSE SHELL – Ruby exec sh',       'CRITICAL'),

    # ── Reverse Shells: PHP ───────────────────────────────────
    (r'php\s+-r\s+.*fsockopen',          'REVERSE SHELL – PHP fsockopen',      'CRITICAL'),
    (r'php\s+-r\s+.*socket_create',      'REVERSE SHELL – PHP socket',         'CRITICAL'),
    (r'php\s+-r\s+.*exec.*sh',           'REVERSE SHELL – PHP exec',           'CRITICAL'),
    (r'php\s+-r\s+.*/dev/tcp/',          'REVERSE SHELL – PHP /dev/tcp',       'CRITICAL'),

    # ── Reverse Shells: Node.js ───────────────────────────────
    (r'node\s+-e\s+.*net\.connect',      'REVERSE SHELL – Node net.connect',   'CRITICAL'),
    (r'node\s+-e\s+.*child_process',     'REVERSE SHELL – Node child_process', 'CRITICAL'),
    (r'node\s+-e\s+.*exec.*sh',          'REVERSE SHELL – Node exec sh',       'CRITICAL'),

    # ── Reverse Shells: Lua ───────────────────────────────────
    (r'lua\s+-e\s+.*socket',             'REVERSE SHELL – Lua socket',         'CRITICAL'),
    (r'lua\s+-e\s+.*require.*socket',    'REVERSE SHELL – Lua require socket', 'CRITICAL'),

    # ── Reverse Shells: AWK ───────────────────────────────────
    (r'gawk\s+.*BEGIN.*\|&',             'REVERSE SHELL – gawk coprocess',     'CRITICAL'),
    (r'awk\s+.*BEGIN.*tcp',              'REVERSE SHELL – awk TCP',            'CRITICAL'),

    # ── Reverse Shells: Golang ────────────────────────────────
    (r'go\s+run\s+.*dial',               'REVERSE SHELL – Go dial',            'HIGH'),

    # ── Reverse Shells: OpenSSL ───────────────────────────────
    (r'openssl\s+s_client.*-quiet',      'REVERSE SHELL – OpenSSL s_client',   'CRITICAL'),
    (r'openssl\s+s_client.*-connect',    'REVERSE SHELL – OpenSSL connect',    'HIGH'),

    # ── Reverse Shells: telnet ─────────────────────────────────
    (r'telnet\s+\d{1,3}\.\d{1,3}',      'REVERSE SHELL – telnet',             'CRITICAL'),
    (r'TF=\$\(mktemp\)',                 'REVERSE SHELL – telnet mktemp',      'CRITICAL'),

    # ── C2 Frameworks ─────────────────────────────────────────
    (r'msfvenom',                         'C2 – Metasploit msfvenom',           'CRITICAL'),
    (r'msfconsole',                       'C2 – Metasploit console',            'CRITICAL'),
    (r'meterpreter',                      'C2 – Meterpreter session',           'CRITICAL'),
    (r'cobalt.?strike',                   'C2 – Cobalt Strike',                 'CRITICAL'),
    (r'empire\s+http\|empire\s+agent',   'C2 – PowerEmpire',                   'CRITICAL'),
    (r'havoc\.py|havoc\s+server',         'C2 – Havoc Framework',               'CRITICAL'),
    (r'sliver-server|sliver-client',      'C2 – Sliver',                        'CRITICAL'),
    (r'\bmythic\b.*agent',                'C2 – Mythic',                        'CRITICAL'),
    (r'covenant.*listener',               'C2 – Covenant',                      'CRITICAL'),

    # ── Shell Upgrades ─────────────────────────────────────────
    (r'script\s+/dev/null',              'SHELL UPGRADE – script /dev/null',   'HIGH'),
    (r'script\s+-q\s+/dev/null',         'SHELL UPGRADE – script -q',          'HIGH'),
    (r'stty\s+raw\s+-echo',              'SHELL UPGRADE – stty raw',           'HIGH'),
    (r'stty\s+rows\s+\d+\s+cols',        'SHELL UPGRADE – stty resize',        'MEDIUM'),
    (r'export\s+TERM=xterm',             'SHELL UPGRADE – TERM=xterm',         'MEDIUM'),
    (r'reset\s*$',                        'SHELL UPGRADE – terminal reset',     'MEDIUM'),
    (r'xterm\s+-display',                'REVERSE SHELL – xterm display',      'HIGH'),

    # ── RCE: Pipe to Shell ─────────────────────────────────────
    (r'curl\s+.*\|\s*(?:ba)?sh',         'RCE – curl | sh',                    'CRITICAL'),
    (r'curl\s+.*\|\s*bash',              'RCE – curl | bash',                  'CRITICAL'),
    (r'wget\s+.*-O\s*-.*\|\s*(?:ba)?sh','RCE – wget | sh',                    'CRITICAL'),
    (r'wget\s+.*\|\s*(?:ba)?sh',         'RCE – wget | sh',                    'CRITICAL'),
    (r'curl\s+-s\s+.*\|\s*python',       'RCE – curl | python',                'CRITICAL'),

    # ── Encoded / Obfuscated Commands ─────────────────────────
    (r'echo\s+[A-Za-z0-9+/]{30,}=*\s*\|\s*base64\s+-d\s*\|\s*(?:ba)?sh',
                                          'RCE – base64 decode | sh',           'CRITICAL'),
    (r'base64\s+-d\s*.*\|\s*(?:ba)?sh',  'RCE – base64 | sh',                 'CRITICAL'),
    (r'echo\s+.*\|\s*xxd\s+-r\s*\|\s*(?:ba)?sh',
                                          'RCE – xxd decode | sh',              'CRITICAL'),
    (r'\$\(echo\s+[A-Za-z0-9+/]{20,}\s*\|\s*base64',
                                          'OBFUSCATION – base64 subshell',      'HIGH'),
    (r'eval\s+\$\(base64',               'OBFUSCATION – eval base64',          'CRITICAL'),
    (r'eval\s+`base64',                  'OBFUSCATION – eval base64 backtick', 'CRITICAL'),
    (r'eval\s+"\$\(',                    'OBFUSCATION – eval $( )',             'HIGH'),

    # ── Fileless / Memory Execution ────────────────────────────
    (r'memfd_create',                     'FILELESS – memfd_create',            'CRITICAL'),
    (r'/dev/shm/[a-zA-Z]',               'FILELESS – /dev/shm execution',      'HIGH'),
    (r'/proc/self/mem',                   'PROCESS INJECTION – /proc/self/mem', 'CRITICAL'),
    (r'dd\s+.*if=.*of=/proc/',           'PROCESS INJECTION – dd to /proc',    'CRITICAL'),
    (r'LD_PRELOAD=/tmp/',                 'INJECTION – LD_PRELOAD /tmp',        'CRITICAL'),
    (r'LD_PRELOAD=/dev/',                 'INJECTION – LD_PRELOAD /dev',        'CRITICAL'),
    (r'ptrace\s+ATTACH',                 'PROCESS INJECTION – ptrace',         'CRITICAL'),

    # ── Persistence ───────────────────────────────────────────
    (r'crontab\s+-[el]',                  'PERSISTENCE – crontab bearbeiten',   'HIGH'),
    (r'echo\s+.*>>\s*/etc/cron',         'PERSISTENCE – cron job schreiben',   'HIGH'),
    (r'echo\s+.*>>\s*~?/\.bashrc',       'PERSISTENCE – .bashrc modifizieren', 'HIGH'),
    (r'echo\s+.*>>\s*~?/\.profile',      'PERSISTENCE – .profile modifizieren','HIGH'),
    (r'echo\s+.*authorized_keys',        'PERSISTENCE – SSH Key schreiben',    'CRITICAL'),
    (r'>\s*~?/\.ssh/authorized_keys',    'PERSISTENCE – SSH Key überschreiben','CRITICAL'),
    (r'chmod\s+[46]755\s+',              'PRIVILEGE ESC – SUID chmod',         'HIGH'),
    (r'chmod\s+u\+s\s+',                 'PRIVILEGE ESC – SUID setzen',        'HIGH'),
    (r'systemctl\s+enable\s+',           'PERSISTENCE – systemd enable',       'MEDIUM'),
    (r'echo\s+.*>>\s*/etc/rc\.local',    'PERSISTENCE – rc.local',             'HIGH'),

    # ── Privilege Escalation ───────────────────────────────────
    (r'sudo\s+-l',                        'PRIVESC – sudo -l (Enum)',           'MEDIUM'),
    (r'find\s+/\s+-perm\s+-4000',        'PRIVESC – SUID Suche',               'MEDIUM'),
    (r'find\s+/\s+-perm\s+/4000',        'PRIVESC – SUID Suche alt',           'MEDIUM'),
    (r'python[23]?\s+.*setuid\(0\)',      'PRIVESC – setuid(0)',                'CRITICAL'),
    (r'/etc/passwd.*root',               'PRIVESC – /etc/passwd root lesen',   'HIGH'),
    (r'unshadow\s+',                      'PRIVESC – unshadow (Hash dump)',     'HIGH'),

    # ── Data Exfiltration ──────────────────────────────────────
    (r'tar\s+.*\|\s*curl',               'EXFIL – tar | curl Upload',          'HIGH'),
    (r'tar\s+.*\|\s*nc\b',               'EXFIL – tar | nc Upload',            'HIGH'),
    (r'curl\s+.*-T\s+',                  'EXFIL – curl PUT Upload',            'HIGH'),
    (r'curl\s+.*--upload-file',          'EXFIL – curl Upload',                'HIGH'),
    (r'scp\s+.*\d{1,3}\.\d{1,3}',       'EXFIL – scp zu externem Host',       'HIGH'),
    (r'rsync\s+.*\d{1,3}\.\d{1,3}',     'EXFIL – rsync zu externem Host',     'HIGH'),
    (r'base64\s+.*\|\s*curl',            'EXFIL – base64 | curl',              'HIGH'),
    (r'xxd\s+.*\|\s*curl',               'EXFIL – xxd | curl',                 'HIGH'),
    (r'cat\s+/etc/passwd\s*\|',          'EXFIL – /etc/passwd',                'HIGH'),
    (r'cat\s+/etc/shadow',               'EXFIL – /etc/shadow',                'CRITICAL'),
    (r'cat\s+.*\.key\s*\|',              'EXFIL – private key',                'HIGH'),
    (r'cat\s+.*id_rsa',                  'EXFIL – SSH private key',            'CRITICAL'),

    # ── Suspicious Downloads ───────────────────────────────────
    (r'wget\s+.*-O\s+/tmp/',             'DOWNLOAD – nach /tmp',               'MEDIUM'),
    (r'wget\s+.*-O\s+/dev/shm/',         'DOWNLOAD – nach /dev/shm',           'HIGH'),
    (r'curl\s+-o\s+/tmp/',               'DOWNLOAD – nach /tmp',               'MEDIUM'),
    (r'curl\s+-o\s+/dev/shm/',           'DOWNLOAD – nach /dev/shm',           'HIGH'),
    (r'chmod\s+\+x\s+/tmp/',             'EXEC PREP – chmod /tmp',             'MEDIUM'),
    (r'chmod\s+\+x\s+/dev/shm/',         'EXEC PREP – chmod /dev/shm',        'HIGH'),

    # ── Bind Shells ────────────────────────────────────────────
    (r'nc\s+-[kl].*-p\s*\d+',            'BIND SHELL – nc listen',             'HIGH'),
    (r'nc\s+-[kl].*\d{3,5}',             'BIND SHELL – nc listen port',        'HIGH'),
    (r'socat\s+TCP-LISTEN',              'BIND SHELL – socat listen',          'HIGH'),
    (r'python[23]?\s+-c.*bind\(',        'BIND SHELL – Python bind',           'HIGH'),

    # ── DNS / Tunneling ────────────────────────────────────────
    (r'iodine\s+',                        'TUNNEL – DNS Tunnel (iodine)',       'HIGH'),
    (r'dnscat',                           'TUNNEL – DNScat C2',                 'CRITICAL'),
    (r'dns2tcp',                          'TUNNEL – dns2tcp Tunnel',            'HIGH'),
    (r'chisel\s+client',                 'TUNNEL – Chisel Tunnel',             'HIGH'),
    (r'ngrok\s+',                         'TUNNEL – ngrok',                     'MEDIUM'),
    (r'pwncat',                           'C2 – pwncat',                        'HIGH'),
    (r'ligolo',                           'TUNNEL – Ligolo Proxy',              'HIGH'),

    # ── Container Escape ───────────────────────────────────────
    (r'docker\s+.*--privileged',         'CONTAINER ESCAPE – privileged',      'CRITICAL'),
    (r'nsenter\s+',                       'CONTAINER ESCAPE – nsenter',         'CRITICAL'),
    (r'unshare\s+',                       'CONTAINER ESCAPE – unshare',         'HIGH'),
    (r'mount\s+/dev/',                    'CONTAINER ESCAPE – /dev mount',      'CRITICAL'),
    (r'cgroup.*notify_on_release',       'CONTAINER ESCAPE – cgroup',          'CRITICAL'),
    (r'runc\s+(?!init)',                   'CONTAINER ESCAPE – runc',            'HIGH'),

    # SSH Reverse/Dynamic Tunnel
    (r"ssh\s+.*-[Ro]\s+\d+:",            "TUNNEL - SSH Reverse/Dynamic",   "CRITICAL"),
    (r"ssh\s+.*-D\s+\d+",                "TUNNEL - SSH Dynamic SOCKS",     "CRITICAL"),
    (r"autossh\s+.*-R\s",                "TUNNEL - autossh Reverse SSH",   "HIGH"),
    (r"busybox\s+nc",                  "REVERSE SHELL - busybox nc",     "CRITICAL"),
    (r"ncat?.*--(exec|sh-exec)",   "REVERSE SHELL - ncat --exec",    "CRITICAL"),
    (r"zsh\s+.*>.*\/dev\/tcp\/",         "REVERSE SHELL - zsh /dev/tcp",   "CRITICAL"),
    (r"php\s+-r\s+.*proc_open",          "REVERSE SHELL - PHP proc_open",  "CRITICAL"),
    (r"php\s+-r\s+.*stream_socket",      "REVERSE SHELL - PHP stream",     "CRITICAL"),
    (r"frpc?",                        "TUNNEL - frp Reverse Proxy",     "HIGH"),
    (r"proxychains\s+",                  "TUNNEL - proxychains",            "MEDIUM"),
    (r"ligolo-ng",                     "TUNNEL - Ligolo-ng",              "HIGH"),
    # ── ICMP Tunneling ─────────────────────────────────────────
    (r'ptunnel|icmptunnel|icmpsh',       'TUNNEL - ICMP Tunnel',               'HIGH'),
    (r'hans\s+-s\s+\d',                  'TUNNEL - ICMP Tunnel (hans)',        'HIGH'),

    # ── Rootkit ────────────────────────────────────────────────
    (r'insmod\s+',                        'ROOTKIT - insmod Kernel Module',     'CRITICAL'),
    (r'modprobe\s+(?!--show-depends)',   'ROOTKIT - modprobe',                 'HIGH'),
    (r'rmmod\s+',                         'ROOTKIT - rmmod Module',             'HIGH'),
    (r'LD_PRELOAD\s*=\s*\S',             'ROOTKIT - LD_PRELOAD Injection',     'CRITICAL'),
    (r'/etc/ld\.so\.preload',            'ROOTKIT - ld.so.preload',            'CRITICAL'),
    (r'diamorphine|reptile|bdvl|beurk|suterusu|azazel|adore-ng|knark',
                                           'ROOTKIT - bekanntes Rootkit-Tool',   'CRITICAL'),
    (r'sys_call_table|kallsyms_lookup_name',
                                           'ROOTKIT - Syscall-Tabelle',          'CRITICAL'),
    (r'echo\s+.*>\s*/etc/ld\.so\.preload',
                                           'ROOTKIT - ld.so.preload schreiben',  'CRITICAL'),

    # ── Anti-Forensik / Anti-Monitor ──────────────────────────
    (r'pkill\s+.*(?:artex|monitor\.py|watchdog|auditd|rsyslog)',
                                           'ANTI-MONITOR - Dienst kill',         'CRITICAL'),
    (r'kill\s+-[0-9]+\s+.*(?:artex|monitor|watchdog)',
                                           'ANTI-MONITOR - Monitor kill',        'CRITICAL'),
    (r'rm\s+.*artex-monitor',             'ANTI-MONITOR - Monitor loeschen',    'CRITICAL'),
    (r'systemctl\s+(?:stop|disable|mask)\s+(?:auditd|rsyslog|syslog)',
                                           'ANTI-FORENSIK - Logging stoppen',    'CRITICAL'),
    (r'auditctl\s+-[eD]\s+0',            'ANTI-FORENSIK - Audit deaktivieren', 'CRITICAL'),
    (r'shred\s+|wipe\s+.*-f',            'ANTI-FORENSIK - Datei shredden',     'HIGH'),
    (r'history\s+-c$|unset\s+HISTFILE',  'ANTI-FORENSIK - History loeschen',   'MEDIUM'),
    (r'>\s*/var/log/\w+\.log\s*$',     'ANTI-FORENSIK - Log leeren',         'HIGH'),

    # ── Web Shells ─────────────────────────────────────────────
    (r'eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)',
                                           'WEB SHELL - PHP eval $_REQUEST',     'CRITICAL'),
    (r'system\s*\(\s*\$_(?:GET|POST)', 'WEB SHELL - PHP system()',           'CRITICAL'),
    (r'shell_exec\s*\(\s*\$_',         'WEB SHELL - PHP shell_exec()',       'CRITICAL'),

    # ── Weitere Shell-Typen ────────────────────────────────────
    (r'ksh\s+.*>.*\/dev\/tcp\/',       'REVERSE SHELL - ksh /dev/tcp',       'CRITICAL'),
    (r'powershell.*-enc\s+[A-Za-z0-9+/]{30,}',
                                           'OBFUSCATION - PowerShell -enc',      'CRITICAL'),
    (r'java\s+-jar\s+.*(?:rat|agent|payload|shell)',
                                           'C2 - Java RAT/Agent',                'HIGH'),

    # ── Weitere Shells: fish, dash, zsh ────────────────────
    (r'fish\s+-c\s+.*(?:socket|connect|exec)',
                                           'REVERSE SHELL - fish shell',         'CRITICAL'),
    (r'dash\s+-c\s+.*(?:/dev/tcp|connect)',
                                           'REVERSE SHELL - dash /dev/tcp',      'CRITICAL'),
    (r'mkfifo\s+\S+\s*;\s*\w+\s+\S+\s+\d{2,5}',
                                           'REVERSE SHELL - mkfifo pipeline',    'CRITICAL'),

    # ── Credential Harvesting ──────────────────────────────
    (r'cat\s+/etc/shadow',               'EXFIL - /etc/shadow lesen',          'CRITICAL'),
    (r'cat\s+.*authorized_keys',         'EXFIL - authorized_keys lesen',       'HIGH'),
    (r'unshadow\s+/etc/passwd',          'PRIVESC - Passwort-Hash dump',        'CRITICAL'),
    (r'hashcat\s+|john\s+.*hash',        'PRIVESC - Passwort cracken',          'HIGH'),

    # ── Memory/Proc Injection ──────────────────────────────
    (r'gcore\s+\d+',                     'PROC DUMP - gcore Prozess-Dump',      'HIGH'),
    (r'strings\s+/proc/\d+/mem',         'PROC READ - /proc/mem lesen',         'HIGH'),
]

compiled = [(re.compile(p, re.IGNORECASE), lbl, sev)
            for p, lbl, sev in PATTERNS]
# Muster fuer SESSION-OUTPUT (Ergebnisse die Angreifer sieht)
OUTPUT_PATTERNS = [
    (r'rootkit\s+(?:installed|active|running|loaded)',  'ROOTKIT - im Output bestaetigt',    'CRITICAL'),
    (r'rootkit\s+removed',                              'ROOTKIT - Entfernung im Output',    'HIGH'),
    (r'killing\s+watchdog|watchdog\s+killed',          'ANTI-MONITOR - Watchdog gekillt',   'CRITICAL'),
    (r'module\s+(?:inserted|loaded|installed)',         'ROOTKIT - Modul geladen',           'CRITICAL'),
    (r'hidden\s+(?:process|file|port)',                 'ROOTKIT - Versteckt-Meldung',       'HIGH'),
    (r'backdoor\s+(?:installed|active|listening)',      'BACKDOOR - aktiv im Output',        'CRITICAL'),
    (r'BEGIN\s+(?:RSA|OPENSSH|EC)\s+PRIVATE\s+KEY', 'EXFIL - Privater Key im Output',    'CRITICAL'),
    (r'AWS_(?:SECRET|ACCESS)_KEY',                      'EXFIL - AWS Credentials',           'CRITICAL'),
    (r'\$[0-9]\$[A-Za-z0-9./]{20,}',                 'EXFIL - Passwort-Hash',             'HIGH'),
    (r'root:[x*!]?:\d+:\d+:',                         'EXFIL - /etc/passwd Zeile',         'HIGH'),
    (r'root:.{10,}:\d+:\d+:\d+:',                    'EXFIL - /etc/shadow Zeile',          'CRITICAL'),
]
_output_compiled = [(re.compile(p, re.IGNORECASE), lbl, sev) for p, lbl, sev in OUTPUT_PATTERNS]


_alerted_rootkit:   dict = {}  # key -> last-alert monotonic time
_alerted_implants:  dict = {}  # key -> last-alert monotonic time

# Namen echter Kernel-kworker-Threads (haben keine exe und keine Sockets)
_KWORKER_RE   = re.compile(r'^kworker/')
# Prozesse die gelöschte Binaries legal haben dürfen
_SAFE_DELETED = frozenset({'python3', 'python', 'artex', 'bash', 'sh', 'dash',
                            'ps', 'grep', 'awk', 'sed', 'cat', 'ls', 'find'})
# Bekannte DNS-Dienste (dürfen Port 53 offen haben)
_DNS_PROCS    = frozenset({'named', 'unbound', 'dnsmasq', 'systemd-resolv',
                            'coredns', 'bind', 'pdns', 'pdns_server'})

def _read_all_procs():
    """Liest /proc direkt (umgeht libc readdir-Hook). Liefert {pid: {name,exe,ppid}}."""
    procs = {}
    try:
        for _pid_name in list_proc_pids():
            if not _pid_name.isdigit():
                continue
            pid = int(_pid_name)
            try:
                with open(f'/proc/{pid}/status') as f:
                    st = {}
                    for line in f:
                        k, _, v = line.partition(':')
                        st[k.strip()] = v.strip()
                name = st.get('Name', '')
                ppid = int(st.get('PPid', 0))
                try:
                    exe = os.readlink(f'/proc/{pid}/exe')
                except (PermissionError, FileNotFoundError, OSError):
                    exe = ''
                procs[pid] = {'name': name, 'exe': exe, 'ppid': ppid}
            except Exception:
                pass
    except Exception:
        pass
    return procs

def _check_process_implants():
    """
    Erkennt getarnte Implant-Prozesse:
      1. Fake kworker  – kworker-Name aber /proc/<pid>/exe vorhanden
      2. Watchdog-Paar – Eltern/Kind-Beziehung zwischen Fake-kworkern
      3. Deleted Binary – laufender Prozess dessen Binary auf Disk gelöscht ist
      4. DNS-Tunnel     – Nicht-DNS-Prozess mit direkter UDP:53-Verbindung nach außen
    """
    hits = []
    now  = time.monotonic()
    all_procs = _read_all_procs()

    # ── 1 + 2: Fake kworker + Watchdog-Paar ─────────────────────────
    fake_pids = {pid for pid, info in all_procs.items()
                 if _KWORKER_RE.match(info['name']) and info['exe']}
    for pid in fake_pids:
        info  = all_procs[pid]
        ppid  = info['ppid']
        is_child  = ppid in fake_pids
        is_parent = any(all_procs[c]['ppid'] == pid for c in fake_pids if c != pid)
        role  = 'WATCHDOG' if is_parent else ('WORKER' if is_child else 'IMPLANT')
        parent_str = ''
        if is_child and ppid in all_procs:
            parent_str = f' parent={all_procs[ppid]["name"]}(PID {ppid})'
        key = f'fakekw:{pid}'
        if now - _alerted_implants.get(key, -999) > 60:
            _alerted_implants[key] = now
            # PID + Name GEHÖREN IN DIE MELDUNG: der Dashboard-Parser liest das
            # Detail aus einer separaten Zeile, die bei paralleler Alert-Ausgabe
            # (Sniffer-Thread) am falschen Alert landen kann. Die Meldung bleibt
            # dagegen immer beim Alert, daher trägt sie die Korrelationsdaten.
            # anc=... ist die Prozess-Abstammung (pid + ppid-Kette): das Dashboard
            # ordnet das Implant damit NUR der Session zu, aus der es gestartet
            # wurde, statt pauschal allen. Es entfernt das Feld vor der Anzeige.
            anc = [str(pid)]
            _cur, _seen = ppid, set()
            while _cur and _cur > 1 and _cur not in _seen:
                _seen.add(_cur)
                anc.append(str(_cur))
                _cur = all_procs.get(_cur, {}).get('ppid', 0)
            anc_str = ' anc=' + ','.join(anc)
            hits.append(('CRITICAL',
                f'IMPLANT - Fake kworker [{role}] PID={pid} {info["name"]}{anc_str}',
                f'PID={pid} name={info["name"]} exe={info["exe"][:70]}{parent_str}'))

    # ── 3: Deleted Binary ────────────────────────────────────────────
    for pid, info in all_procs.items():
        if pid in fake_pids:
            continue
        if info['exe'].endswith(' (deleted)') and info['name'] not in _SAFE_DELETED:
            key = f'deleted:{pid}'
            if now - _alerted_implants.get(key, -999) > 60:
                _alerted_implants[key] = now
                hits.append(('HIGH',
                    'IMPLANT - Laufendes gelöschtes Binary',
                    f'PID={pid} name={info["name"]} exe={info["exe"][:70]}'))

    # ── 4: DNS-Tunnel – direktes UDP nach Port 53 (kein lokaler Resolver) ──
    try:
        # inode → pid Map einmal aufbauen (effizienter als pro-Socket)
        inode_map = {}
        for pid, info in all_procs.items():
            try:
                for fd in os.listdir(f'/proc/{pid}/fd'):
                    try:
                        lnk = os.readlink(f'/proc/{pid}/fd/{fd}')
                        if lnk.startswith('socket:['):
                            inode_map[lnk[8:-1]] = (pid, info['name'])
                    except Exception:
                        pass
            except Exception:
                pass
        with open('/proc/net/udp') as f:
            next(f)  # Header
            for line in f:
                parts = line.split()
                if len(parts) < 10:
                    continue
                rem_parts = parts[2].split(':')
                if len(rem_parts) < 2:
                    continue
                rem_port = int(rem_parts[1], 16)
                rem_ip_int = int(rem_parts[0], 16)
                if rem_port != 53:
                    continue
                # Loopback / unrouted ignorieren
                if rem_ip_int in (0, 0x0100007f):
                    continue
                inode = parts[9]
                owner = inode_map.get(inode)
                if owner:
                    o_pid, o_name = owner
                    if o_name not in _DNS_PROCS:
                        key = f'dns53:{o_pid}'
                        if now - _alerted_implants.get(key, -999) > 60:
                            _alerted_implants[key] = now
                            rem_ip = socket.inet_ntoa(struct.pack('<I', rem_ip_int))
                            hits.append(('CRITICAL',
                                'IMPLANT - DNS-Tunnel (direktes UDP:53)',
                                f'PID={o_pid} name={o_name} → {rem_ip}:53'))
    except Exception:
        pass

    # Stale Keys bereinigen (Prozess nicht mehr vorhanden)
    for stale in list(_alerted_implants.keys()):
        pid_str = stale.split(':')[-1]
        if pid_str.isdigit() and int(pid_str) not in all_procs:
            del _alerted_implants[stale]

    return hits

def _check_rootkit_indicators():
    """Prueft Dateisystem auf Rootkit-Spuren. Wird periodisch aus main() aufgerufen."""
    hits = []
    # /etc/ld.so.preload mit Inhalt = LD_PRELOAD Rootkit
    try:
        with open('/etc/ld.so.preload') as f:
            data = f.read().strip()
        if data:
            hits.append(('CRITICAL', 'ROOTKIT - /etc/ld.so.preload aktiv', data[:120]))
    except FileNotFoundError:
        pass
    except Exception:
        pass
    # Bekannte Rootkit-Module in /proc/modules
    rootkit_names = re.compile(
        r'diamorphine|reptile|bdvl|beurk|suterusu|azazel|adore|knark', re.I)
    try:
        with open('/proc/modules') as f:
            for line in f:
                if rootkit_names.search(line):
                    hits.append(('CRITICAL', 'ROOTKIT - Verdaechtiges Kernel-Modul', line.split()[0]))
    except Exception:
        pass
    # Neue .so Dateien in /tmp oder /dev/shm (haeufig Rootkit-Staging)
    for d in ('/tmp', '/dev/shm'):
        try:
            for fn in os.listdir(d):
                if fn.endswith('.so') or fn.endswith('.ko'):
                    hits.append(('HIGH', f'ROOTKIT - Lib/Modul in {d}', fn))
        except Exception:
            pass
    # Deduplication: gleicher Fund nur alle 60s erneut melden
    # Reset timer wenn Rootkit nicht mehr aktiv (damit Wiedereinschleusung sofort erkannt wird)
    now = time.monotonic()
    active_keys = {msg + ':' + str(detail)[:40] for _, msg, detail in hits}
    for stale in list(_alerted_rootkit.keys()):
        if stale not in active_keys:
            del _alerted_rootkit[stale]
    deduped = []
    for sev, msg, detail in hits:
        key = msg + ':' + str(detail)[:40]
        if now - _alerted_rootkit.get(key, -999) > 60:
            _alerted_rootkit[key] = now
            deduped.append((sev, msg, detail))
    return deduped


# ── File Integrity Monitor ─────────────────────────────────────────────
_fi_baseline:    dict = {}
_alerted_fi:     dict = {}

def _check_file_integrity():
    """
    Erkennt Änderungen an kritischen Systemdateien.
    T1565.001  Data Manipulation – Stored Data Manipulation
    T1053.003  Scheduled Task/Job – Cron
    T1098.004  Account Manipulation – SSH Authorized Keys
    """
    hits = []
    now  = time.monotonic()

    watch: list = [
        ('/etc/passwd',     'CRITICAL', 'FILE INTEGRITY – /etc/passwd geändert [T1565.001]'),
        ('/etc/shadow',     'CRITICAL', 'FILE INTEGRITY – /etc/shadow geändert [T1003.008]'),
        ('/etc/sudoers',    'CRITICAL', 'FILE INTEGRITY – /etc/sudoers geändert [T1548.003]'),
        ('/etc/hosts',      'HIGH',     'FILE INTEGRITY – /etc/hosts geändert [T1565.001]'),
        ('/etc/ld.so.conf', 'HIGH',     'FILE INTEGRITY – /etc/ld.so.conf geändert [T1574.006]'),
    ]
    # SSH authorized_keys fuer alle User
    for home_base in ('/root', '/home'):
        try:
            dirs = ([home_base] if home_base == '/root'
                    else [os.path.join(home_base, e) for e in os.listdir(home_base)
                          if os.path.isdir(os.path.join(home_base, e))])
            for home in dirs:
                ak = os.path.join(home, '.ssh', 'authorized_keys')
                watch.append((ak, 'CRITICAL',
                               'FILE INTEGRITY – authorized_keys geändert [T1098.004]'))
        except Exception:
            pass
    # Bestehende cron.d Dateien
    try:
        for fn in os.listdir('/etc/cron.d'):
            fp = os.path.join('/etc/cron.d', fn)
            watch.append((fp, 'HIGH',
                           f'FILE INTEGRITY – {fp} geändert [T1053.003]'))
    except Exception:
        pass

    for path, sev, msg in watch:
        try:
            st  = os.stat(path)
            sig = (st.st_mtime_ns, st.st_size, st.st_ino)
            old = _fi_baseline.get(path)
            if old is None:
                _fi_baseline[path] = sig
                continue
            if old == sig:
                continue
            _fi_baseline[path] = sig
            ak  = f'fi:{path}'
            if now - _alerted_fi.get(ak, -999) > 30:
                _alerted_fi[ak] = now
                changes = []
                if old[0] != sig[0]: changes.append('mtime')
                if old[1] != sig[1]: changes.append(f'size:{old[1]}→{sig[1]}')
                hits.append((sev, msg,
                             f'Änderung: {", ".join(changes) or "inode"} | {path}'))
        except FileNotFoundError:
            _fi_baseline.pop(path, None)
        except Exception:
            pass
    return hits


# ── Persistence Monitor ────────────────────────────────────────────────
_persist_baseline: dict = {}
_alerted_persist:  dict = {}

def _check_persistence():
    """
    Erkennt neue Persistence-Dateien in bekannten Verzeichnissen.
    T1053.003  Cron
    T1543.002  Systemd Service
    T1543.001  Init-Script
    T1546.004  .profile / profile.d
    """
    hits = []
    now  = time.monotonic()

    watch_dirs = [
        ('/etc/cron.d',              'HIGH',   'PERSISTENCE – Neue Cron-Datei [T1053.003]'),
        ('/etc/cron.daily',          'HIGH',   'PERSISTENCE – Neues cron.daily-Script [T1053.003]'),
        ('/etc/cron.hourly',         'HIGH',   'PERSISTENCE – Neues cron.hourly-Script [T1053.003]'),
        ('/etc/cron.weekly',         'HIGH',   'PERSISTENCE – Neues cron.weekly-Script [T1053.003]'),
        ('/var/spool/cron/crontabs', 'HIGH',   'PERSISTENCE – Neue crontab [T1053.003]'),
        ('/etc/systemd/system',      'HIGH',   'PERSISTENCE – Neuer Systemd-Service [T1543.002]'),
        ('/etc/init.d',              'MEDIUM', 'PERSISTENCE – Neues Init-Script [T1543.001]'),
        ('/etc/profile.d',           'HIGH',   'PERSISTENCE – Neues profile.d-Script [T1546.004]'),
    ]

    for dpath, sev, base_msg in watch_dirs:
        try:
            current = frozenset(os.listdir(dpath))
        except FileNotFoundError:
            continue
        except Exception:
            continue
        prev = _persist_baseline.get(dpath)
        if prev is None:
            _persist_baseline[dpath] = current
            continue
        new_files = current - prev
        _persist_baseline[dpath] = current
        for fn in sorted(new_files):
            ak = f'persist:{dpath}/{fn}'
            if now - _alerted_persist.get(ak, -999) > 60:
                _alerted_persist[ak] = now
                full = os.path.join(dpath, fn)
                hits.append((sev, base_msg, f'Datei: {full}'))
    return hits


# ── SUID Binary Monitor ────────────────────────────────────────────────
_suid_baseline: set = None
_alerted_suid:  dict = {}

def _check_suid_binaries():
    """
    Erkennt neue SUID-Binaries.
    T1548.001  Abuse Elevation Control Mechanism – Setuid and Setgid
    """
    global _suid_baseline
    hits = []
    now  = time.monotonic()

    scan_dirs = ['/usr/bin', '/usr/sbin', '/bin', '/sbin',
                 '/usr/local/bin', '/usr/local/sbin',
                 '/tmp', '/dev/shm', '/var/tmp']
    current: set = set()
    for d in scan_dirs:
        try:
            for fn in os.listdir(d):
                fp = os.path.join(d, fn)
                try:
                    if os.stat(fp).st_mode & 0o4000:
                        current.add(fp)
                except Exception:
                    pass
        except Exception:
            pass

    if _suid_baseline is None:
        _suid_baseline = current
        return hits

    new_suid = current - _suid_baseline
    _suid_baseline = current
    for fp in sorted(new_suid):
        ak = f'suid:{fp}'
        if now - _alerted_suid.get(ak, -999) > 300:
            _alerted_suid[ak] = now
            hits.append(('CRITICAL',
                'PRIVESC – Neues SUID-Binary erkannt [T1548.001]',
                f'Datei: {fp}'))
    return hits


# ── Sensitive File Access Monitor ──────────────────────────────────────
_alerted_fd: dict = {}

def _check_sensitive_fd_access():
    """
    Erkennt Prozesse die kritische Dateien aktuell geöffnet haben.
    T1003.008  OS Credential Dumping – /etc/passwd and /etc/shadow
    T1552.004  Unsecured Credentials – Private Keys
    """
    SENSITIVE: dict = {
        '/etc/shadow':  ('CRITICAL', 'CREDENTIAL ACCESS – /etc/shadow geöffnet [T1003.008]'),
        '/etc/gshadow': ('CRITICAL', 'CREDENTIAL ACCESS – /etc/gshadow geöffnet [T1003.008]'),
        '/etc/sudoers': ('HIGH',     'CREDENTIAL ACCESS – /etc/sudoers geöffnet [T1548.003]'),
    }
    for home_base in ('/root', '/home'):
        try:
            dirs = ([home_base] if home_base == '/root'
                    else [os.path.join(home_base, e) for e in os.listdir(home_base)
                          if os.path.isdir(os.path.join(home_base, e))])
            for home in dirs:
                SENSITIVE[os.path.join(home, '.ssh', 'authorized_keys')] = (
                    'HIGH', 'CREDENTIAL ACCESS – authorized_keys geöffnet [T1552.004]')
                for kn in ('id_rsa', 'id_ecdsa', 'id_ed25519', 'id_dsa'):
                    SENSITIVE[os.path.join(home, '.ssh', kn)] = (
                        'CRITICAL', 'CREDENTIAL ACCESS – Privat-Key geöffnet [T1552.004]')
        except Exception:
            pass

    hits = []
    now  = time.monotonic()
    own  = str(os.getpid())
    try:
        for pid in list_proc_pids():
            if not pid.isdigit() or pid == own:
                continue
            try:
                for fd in os.listdir(f'/proc/{pid}/fd'):
                    try:
                        target = os.readlink(f'/proc/{pid}/fd/{fd}')
                        if target not in SENSITIVE:
                            continue
                        sev, msg = SENSITIVE[target]
                        ak = f'fd:{pid}:{target}'
                        if now - _alerted_fd.get(ak, -999) > 30:
                            _alerted_fd[ak] = now
                            cmd = get_cmdline(pid)
                            hits.append((sev, msg, f'PID={pid} CMD={cmd[:80]}'))
                    except (FileNotFoundError, PermissionError, OSError):
                        pass
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                pass
    except Exception:
        pass
    return hits


# ── Web Shell Spawn Detection ──────────────────────────────────────────
_alerted_webshell: dict = {}
_WEBSERVER_RE = re.compile(
    r'\b(?:apache2|httpd|nginx|php(?:-fpm\d*)?|uwsgi|gunicorn|uvicorn|'
    r'lighttpd|caddy|traefik)\b', re.I)
_SHELL_SPAWN_RE = re.compile(
    r'(?:^|[/ ])(?:ba|da|k|z|c)?sh(?:\s|$)|'
    r'\bpython[23]?\b.*-c\b|'
    r'\bperl\b.*-e\b|'
    r'\bphp\b.*-r\b', re.I)

def _check_webshell_spawn():
    """
    Erkennt Shells die von Web-Server-Prozessen gestartet wurden.
    T1505.003  Server Software Component – Web Shell
    """
    hits = []
    now  = time.monotonic()
    all_procs = _read_all_procs()
    for pid, info in all_procs.items():
        cmd = get_cmdline(str(pid))
        if not _SHELL_SPAWN_RE.search(cmd):
            continue
        ppid = info['ppid']
        if ppid <= 1:
            continue
        parent_cmd = get_cmdline(str(ppid))
        if _WEBSERVER_RE.search(parent_cmd):
            ak = f'webshell:{pid}'
            if now - _alerted_webshell.get(ak, -999) > 60:
                _alerted_webshell[ak] = now
                hits.append(('CRITICAL',
                    'WEBSHELL – Shell via Web-Server gestartet [T1505.003]',
                    f'PID={pid} CMD={cmd[:80]} | PPID={ppid} PARENT={parent_cmd[:60]}'))
    return hits


# ── Defense Evasion – Log Tampering ───────────────────────────────────
_logfile_baseline: dict = {}
_alerted_logtamper: dict = {}

def _check_log_tampering():
    """
    Erkennt Verkleinerung oder Leerung von Logdateien.
    T1070.002  Indicator Removal – Clear Linux or Mac System Logs
    """
    hits = []
    now  = time.monotonic()
    try:
        for fn in os.listdir('/var/log'):
            if not (fn.endswith('.log') or fn in ('syslog', 'auth.log', 'kern.log',
                                                    'messages', 'secure', 'lastlog')):
                continue
            path = os.path.join('/var/log', fn)
            try:
                st  = os.stat(path)
                sig = (st.st_mtime_ns, st.st_size)
                old = _logfile_baseline.get(path)
                if old is None:
                    _logfile_baseline[path] = sig
                    continue
                if sig[1] < old[1] or (sig[1] == 0 and old[1] > 0):
                    _logfile_baseline[path] = sig
                    ak = f'logtamper:{path}'
                    if now - _alerted_logtamper.get(ak, -999) > 60:
                        _alerted_logtamper[ak] = now
                        hits.append(('HIGH',
                            'DEFENSE EVASION – Log-Datei verkleinert [T1070.002]',
                            f'Datei: {path} | vorher: {old[1]} Bytes, jetzt: {sig[1]} Bytes'))
                else:
                    _logfile_baseline[path] = sig
            except FileNotFoundError:
                _logfile_baseline.pop(path, None)
            except Exception:
                pass
    except Exception:
        pass
    return hits


# ── Hilfsfunktionen ──────────────────────────────────────────────────

SEV_COLOR = {
    'CRITICAL': RED + BOLD,
    'HIGH':     ORANGE + BOLD,
    'MEDIUM':   YELLOW,
    'LOW':      DIM + GREEN,
}

def ts():
    return datetime.datetime.now().strftime('%H:%M:%S')

def alert(severity, msg, detail=''):
    color  = SEV_COLOR.get(severity, YELLOW)
    prefix = f"{DIM}[{ts()}]{NC} {color}[{severity:8s}]{NC}"
    print(f"{prefix} {msg}", flush=True)
    if detail:
        print(f"           {DIM}↳ {detail}{NC}", flush=True)

def info(msg):
    print(f"{DIM}[{ts()}]{NC} {CYAN}[INFO    ]{NC} {msg}", flush=True)

def hex_ip(h):
    return socket.inet_ntoa(struct.pack('<I', int(h, 16)))

def hex_port(h):
    return int(h, 16)

def read_tcp(path):
    conns = []
    try:
        with open(path) as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if len(p) < 10:
                    continue
                li, lp = p[1].split(':')
                ri, rp = p[2].split(':')
                conns.append({
                    'local_ip':   hex_ip(li),
                    'local_port': hex_port(lp),
                    'rem_ip':     hex_ip(ri),
                    'rem_port':   hex_port(rp),
                    'state':      p[3],
                    'inode':      p[9],
                })
    except Exception:
        pass
    return conns

def get_procs():
    procs = {}
    try:
        for pid in list_proc_pids():
            if not pid.isdigit():
                continue
            try:
                with open(f'/proc/{pid}/cmdline', 'rb') as f:
                    cmd = f.read().replace(b'\x00', b' ').decode(errors='replace').strip()
                if cmd:
                    procs[pid] = cmd
            except Exception:
                pass
    except Exception:
        pass
    return procs

def inode_to_pid(inode):
    target = f'socket:[{inode}]'
    try:
        for pid in list_proc_pids():
            if not pid.isdigit():
                continue
            try:
                for fd in os.listdir(f'/proc/{pid}/fd'):
                    if os.readlink(f'/proc/{pid}/fd/{fd}') == target:
                        return pid
            except Exception:
                pass
    except Exception:
        pass
    return None

def scan_for_patterns(text, pid='?'):
    hits = []
    for pattern, label, severity in compiled:
        if pattern.search(text):
            hits.append((label, severity))
    return hits

def get_cwd(pid):
    """Gibt das aktuelle Arbeitsverzeichnis eines Prozesses zurück."""
    try:
        return os.readlink(f'/proc/{pid}/cwd')
    except Exception:
        return ''

def is_artex_own_task(pid):
    """Gibt True zurück wenn der Prozess ein ARTEX-eigener Task ist
    (Prozess oder Elternprozess läuft aus /app/)."""
    try:
        # Eigenes CWD prüfen
        if '/app/' in get_cwd(str(pid)):
            return True
        # Elternprozess prüfen
        ppid = get_ppid(str(pid))
        if ppid:
            if '/app/' in get_cwd(ppid):
                return True
            pcmd = ''
            try:
                with open(f'/proc/{ppid}/cmdline', 'rb') as f:
                    pcmd = f.read().replace(b'\x00', b' ').decode(errors='replace')
            except Exception:
                pass
            if '/app/' in pcmd:
                return True
    except Exception:
        pass
    return False

def is_safe(rem_ip, rem_port, local_port):
    if is_docker_internal(rem_ip) and rem_port in SAFE_REMOTE_PORTS:
        return True
    if local_port in SAFE_PORTS_LOCAL and rem_ip == '0.0.0.0':
        return True
    # 0.0.0.0 / :: = nicht verbunden, sicher
    if rem_ip in ('0.0.0.0', '::'):
        return True
    # 127.0.0.1 mit bekannten Stack-Ports = sicher
    if rem_ip == '127.0.0.1' and rem_port in SAFE_PORTS_LOCAL:
        return True
    # Sonst: nicht automatisch als sicher annehmen
    return False

def get_proc_tcp_conns(pid):
    """Gibt alle TCP-Verbindungen eines Prozesses zurück (via /proc/PID/fd + /proc/net/tcp)."""
    conns = []
    inode_map = {}
    for conn in read_tcp('/proc/net/tcp'):
        if conn['state'] == '01':
            inode_map[conn['inode']] = conn
    try:
        for fd in os.listdir(f'/proc/{pid}/fd'):
            try:
                link = os.readlink(f'/proc/{pid}/fd/{fd}')
                m = re.search(r'socket:\[(\d+)\]', link)
                if m and m.group(1) in inode_map:
                    conns.append(inode_map[m.group(1)])
            except Exception:
                pass
    except Exception:
        pass
    return conns

# ── Tunnel Command Monitoring ─────────────────────────────────────────

def get_ppid(pid):
    """Liest Parent-PID aus /proc/PID/stat (robust gegen Leerzeichen im Prozessname)."""
    try:
        with open(f'/proc/{pid}/stat') as f:
            raw = f.read()
        end = raw.rfind(')')
        parts = raw[end + 2:].split()
        return parts[1]  # ppid ist das 2. Feld nach ") state ppid ..."
    except Exception:
        return None

def get_inode_rx_queue(inode):
    """Prüft /proc/net/tcp ob Daten im Receive-Buffer des Sockets stehen."""
    try:
        with open('/proc/net/tcp') as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) > 9 and parts[9] == inode:
                    rx = int(parts[4].split(':')[1], 16)
                    return rx
    except Exception:
        pass
    return 0

def find_tunnel_shells():
    """
    Findet Prozesse deren stdin ein externer TCP-Socket ist. Zusätzlich werden
    stark shell-typische bzw. als Kernel-Thread getarnte Userspace-Prozesse
    berücksichtigt, wenn ihr Socket auf einem anderen FD liegt (z.B. FD 3 und
    stdin/stdout=/dev/null).
    Gibt zurück: {pid: {'cmd': ..., 'remote': 'IP:PORT', 'inode': ...}}
    """
    # inode → connection mapping für externe Verbindungen
    inode_map = {}
    for conn in read_tcp('/proc/net/tcp'):
        if conn['state'] == '01':
            rem_ip   = conn['rem_ip']
            rem_port = conn['rem_port']
            # is_safe() reicht — deckt SAFE_REMOTE_PORTS (5432, 4000) + loopback ab.
            # is_docker_internal hier NICHT verwenden: 172.17.0.1 (Docker-Host) ist
            # eine valide Reverse-Shell-Verbindung und darf nicht ausgeschlossen werden.
            if not is_safe(rem_ip, rem_port, conn['local_port']):
                inode_map[conn['inode']] = conn

    shells = {}
    try:
        shellish_re = re.compile(
            r'(?:^|/)(?:ba)?sh\b.*(?:^|\s)-i\b|'
            r'\b(?:nc|ncat|netcat)\b.*(?:-[ec]|\s\d{2,5})|'
            r'\bsocat\b.*\bEXEC\b|'
            r'^\[(?:kworker|ksoftirqd|migration|rcu[^]]*)',
            re.IGNORECASE,
        )
        for pid in list_proc_pids():
            if not pid.isdigit():
                continue
            try:
                cmd = get_cmdline(pid)
                shellish = bool(shellish_re.search(cmd))
                # FD 0,1,2 immer prüfen (stdin+stdout+stderr), bei shellish alle FDs.
                # So werden auch 'bash -i >& /dev/tcp/IP/PORT 0>&1' Muster erkannt
                # wo der Socket auf FD 1/2 liegt, bevor die 0>&1 Umleitung greift.
                fd_names = ['0', '1', '2']
                if shellish:
                    fd_names = os.listdir(f'/proc/{pid}/fd')
                for fd_name in fd_names:
                    link = os.readlink(f'/proc/{pid}/fd/{fd_name}')
                    m = re.search(r'socket:\[(\d+)\]', link)
                    if not m or m.group(1) not in inode_map:
                        continue
                    inode = m.group(1)
                    conn = inode_map[inode]
                    shells[pid] = {
                        'cmd':        cmd,
                        'remote':     f"{conn['rem_ip']}:{conn['rem_port']}",
                        'inode':      inode,
                        'rem_ip':     conn['rem_ip'],
                        'rem_port':   conn['rem_port'],
                        'local_port': conn['local_port'],
                    }
                    break
            except Exception:
                pass
    except Exception:
        pass
    return shells

def get_cmdline(pid):
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            return f.read().replace(b'\x00', b' ').decode(errors='replace').strip()
    except Exception:
        return ''

def inode_to_pid(inode):
    target = f'socket:[{inode}]'
    try:
        for pid in list_proc_pids():
            if not pid.isdigit():
                continue
            try:
                for fd in os.listdir(f'/proc/{pid}/fd'):
                    if os.readlink(f'/proc/{pid}/fd/{fd}') == target:
                        return pid
            except Exception:
                pass
    except Exception:
        pass
    return None

# ── Beaconing-Detektion ───────────────────────────────────────────────
class BeaconDetector:
    """Erkennt regelmäßige Verbindungen zum gleichen Host (C2 Beacon)."""
    def __init__(self, window=60, threshold=5):
        self.hits    = collections.defaultdict(list)  # host → [timestamps]
        self.window  = window     # Sekunden
        self.threshold = threshold  # min. Treffer in window
        self.alerted = set()

    def record(self, host, port):
        key  = (host, port)
        now  = time.time()
        self.hits[key] = [t for t in self.hits[key] if now - t < self.window]
        self.hits[key].append(now)
        count = len(self.hits[key])
        if count >= self.threshold and key not in self.alerted:
            self.alerted.add(key)
            return count
        return 0

beacon = BeaconDetector()

# ── Hauptschleife ────────────────────────────────────────────────────

def main():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════╗
║   ARTEX Container Security Monitor                          ║
║   Reverse Shells · C2 · Exfil · Persistence · Tunneling    ║
║   Strg+C zum Beenden                                        ║
╚══════════════════════════════════════════════════════════════╝{NC}
""", flush=True)

    info(f"Intervall: {INTERVAL}s | Patterns: {len(compiled)} | Beaconing-Schwelle: {beacon.threshold}x/{beacon.window}s")
    info("Kategorien: Reverse Shells, C2, Shell-Upgrades, Persistence,")
    info("            Fileless, Exfil, Tunneling, Container-Escape, Priv-Esc")

    # Raw Socket Sniffer starten (nur mit --privileged)
    sniff_ok = sniffer.start(alert, is_safe, is_private_ip)
    if sniff_ok:
        info(f"{GREEN}Raw Socket Sniffer AKTIV{NC} – TCP + UDP/DNS, Tunnel-Inhalte und TXT-Rückkanäle")
    else:
        info(f"{YELLOW}Kein Raw Socket{NC} – für vollständige Tunnel-Erkennung:")
        info(f"  docker exec --privileged -it artex-app python3 /tmp/artex-monitor.py")
        info("  Ohne --privileged: nur Befehle > ~10ms erkennbar")

    print(flush=True)

    known_conns   = set()
    alerted_conns = set()
    alerted_pids  = set()
    known_listeners = set()  # (local_port, proto) fuer Bind-Shell-Erkennung

    # Initialer Snapshot. Bereits bestehende externe Verbindungen ebenfalls
    # beim Raw-Sniffer registrieren; sonst bleibt der Monitor nach einem
    # Dashboard-Neustart bis zum nächsten TCP-Reconnect blind.
    for c in read_tcp('/proc/net/tcp'):
        known_conns.add((c['rem_ip'], c['rem_port'], c['local_port']))
        if (sniff_ok and c['state'] in ('01', '02') and
                not is_safe(c['rem_ip'], c['rem_port'], c['local_port'])):
            sniffer.track(c['rem_ip'], c['rem_port'], c['local_port'])
    known_pids = get_procs()

    udp_count = len(read_tcp('/proc/net/udp'))
    info(f"Snapshot: {len(known_conns)} TCP-, {udp_count} UDP-Sockets, {len(known_pids)} Prozesse")
    print(flush=True)

    # Tunnel-Tracking
    tunnel_shells      = {}   # pid → {cmd, remote, inode, children}
    tunnel_child_seen  = set()

    try:
        while True:
            # ── TCP-Verbindungen ──────────────────────────────────────
            for c in read_tcp('/proc/net/tcp'):
                rem_ip    = c['rem_ip']
                rem_port  = c['rem_port']
                local_port= c['local_port']
                state     = c['state']
                key       = (rem_ip, rem_port, local_port)

                if state not in ('01', '02'):
                    continue
                if key in alerted_conns:
                    continue
                if is_safe(rem_ip, rem_port, local_port):
                    known_conns.add(key)
                    continue

                # Neuer unbekannter ausgehender Connect
                is_new = key not in known_conns
                if is_new:
                    known_conns.add(key)
                    pid = inode_to_pid(c['inode'])
                    cmd = ''
                    if pid:
                        try:
                            with open(f'/proc/{pid}/cmdline', 'rb') as f:
                                cmd = f.read().replace(b'\x00', b' ').decode(errors='replace').strip()
                        except Exception:
                            pass

                    alerted_conns.add(key)

                    # Beim Sniffer registrieren → TCP-Stream direkt mitlesen
                    # Auch private IPs tracken (z.B. VPN-Tunnel, lokale Tests)
                    if sniff_ok:
                        sniffer.track(rem_ip, rem_port, local_port)

                    # C2-Port?
                    c2_label = C2_PORTS.get(rem_port)
                    # HTTP-Ports (80, 443, 8080 etc.) die kein bekannter C2-Port sind
                    # → HIGH statt CRITICAL, da normaler Pentest-Traffic erwartet
                    http_like = rem_port in {80, 443, 8080, 8443, 8000, 8888, 1992, 1993}
                    if c2_label:
                        base_sev = 'CRITICAL'
                    elif http_like:
                        base_sev = 'HIGH'
                    else:
                        base_sev = 'HIGH'
                    sev      = classify_severity(rem_ip, rem_port, base_sev)
                    scope    = 'privat' if is_private_ip(rem_ip) else 'öffentlich'

                    if c2_label:
                        alert(sev,
                            f"C2-PORT – {rem_ip}:{rem_port} ({c2_label}) [{scope}]",
                            f"PID={pid}  CMD={cmd[:100]}")
                    else:
                        alert(sev,
                            f"NEUE VERBINDUNG → {rem_ip}:{rem_port}  (lokal :{local_port}) [{scope}]",
                            f"PID={pid}  CMD={cmd[:100]}")

                    # Patterns im CMD prüfen
                    if cmd:
                        _SHELL_CONN = ('REVERSE SHELL', 'BIND SHELL', 'SHELL UPGRADE',
                                       'PTY UPGRADE', 'PROCESS INJECTION',
                                       'CONTAINER ESCAPE', 'C2 –')
                        _has_revshell = False
                        for label, pat_sev in scan_for_patterns(cmd, pid):
                            is_shell_pat = any(label.startswith(x) for x in _SHELL_CONN)
                            # Shell-Patterns: immer original Severity, kein Downgrade
                            final_sev = pat_sev if is_shell_pat else classify_severity(rem_ip, rem_port, pat_sev)
                            alert(final_sev, label, f"CMD: {cmd[:120]}")
                            if label.startswith(('REVERSE SHELL', 'BIND SHELL')):
                                _has_revshell = True
                        # Wenn Reverse/Bind Shell erkannt und PID bekannt: sofort
                        # TUNNEL SESSION AKTIV signalisieren. find_tunnel_shells() prüft
                        # nur ESTABLISHED-Verbindungen (state='01') – bei einer Verbindung
                        # die noch im SYN-Zustand (state='02') ist, würde der Session-Tab
                        # sonst nicht geöffnet. Hier kennen wir IP:Port bereits.
                        if _has_revshell and pid:
                            _r = f"{rem_ip}:{rem_port}"
                            if not session_monitor.is_open(_r):
                                alert('CRITICAL',
                                      f"TUNNEL SESSION AKTIV → {_r} [{scope}]",
                                      f"PID={pid}  Shell: {cmd[:80]}")
                                session_monitor.open_session(_r, pid, cmd[:80])
                            if pid not in tunnel_shells:
                                tunnel_shells[pid] = {
                                    'cmd': cmd, 'remote': _r, 'inode': c['inode'],
                                    'rem_ip': rem_ip, 'rem_port': rem_port,
                                    'local_port': local_port,
                                }
                            if sniff_ok:
                                sniffer.track(rem_ip, rem_port, local_port)


            # Neue TCP-Listener (Bind Shells) erkennen
            for path, proto in [('/proc/net/tcp', 'TCP'), ('/proc/net/tcp6', 'TCP6')]:
                try:
                    for c in read_tcp(path):
                        if c['state'] == '0A':  # LISTEN
                            # Docker-interner Embedded-DNS-Resolver (127.0.0.11) –
                            # läuft ausserhalb des Container-PID-Namespace (daher
                            # nie auflösbare PID) auf wechselndem Port. Fixer
                            # Bestandteil jedes Containers mit Default-Bridge-
                            # Netzwerk, kein Bind-Shell-Indikator.
                            if c['local_ip'] == '127.0.0.11':
                                continue
                            lport = c['local_port']
                            lkey = (lport, proto)
                            if lkey not in known_listeners and lport not in {80,443,8080,8787,8788,9999,5432,4000,22}:
                                known_listeners.add(lkey)
                                pid_l = inode_to_pid(c['inode'])
                                if not pid_l:
                                    for _p in list_proc_pids():
                                        if not _p.isdigit(): continue
                                        try:
                                            for _fd in os.listdir(f'/proc/{_p}/fd'):
                                                lnk = os.readlink(f'/proc/{_p}/fd/{_fd}')
                                                if lnk == f'socket:[{c["inode"]}]':
                                                    pid_l = _p; break
                                        except Exception: pass
                                        if pid_l: break
                                cmd_l = get_cmdline(pid_l) if pid_l else ''
                                sev_l = 'CRITICAL' if lport in C2_PORTS else 'HIGH'
                                alert(sev_l,
                                    f'BIND SHELL / NEUER LISTENER :{lport} [{proto}]',
                                    f'PID={pid_l}  CMD={cmd_l[:100]}')
                except Exception:
                    pass

                # Beaconing prüfen
                if not is_docker_internal(rem_ip):
                    count = beacon.record(rem_ip, rem_port)
                    if count:
                        sev   = classify_severity(rem_ip, rem_port, 'HIGH')
                        scope = 'privat' if is_private_ip(rem_ip) else 'öffentlich'
                        alert(sev,
                            f"BEACONING – {count}x zu {rem_ip}:{rem_port} in {beacon.window}s [{scope}]",
                            'Regelmäßige Verbindungen → mögliches C2-Polling')

            # ── Neue Prozesse ─────────────────────────────────────────
            current_pids = get_procs()
            newly_alerted_shell_pids = set()

            for pid, cmd in current_pids.items():
                if pid in alerted_pids or pid in known_pids:
                    continue
                hits = scan_for_patterns(cmd, pid)
                if hits:
                    alerted_pids.add(pid)
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', cmd)
                    cmd_ip   = ip_match.group(1) if ip_match else '0.0.0.0'
                    scope    = 'privat' if is_private_ip(cmd_ip) else ('öffentlich' if cmd_ip != '0.0.0.0' else '')
                    # ARTEX-eigene Tasks (CWD oder Parent aus /app/) → nie CRITICAL
                    # AUSNAHME: Shell-Patterns immer voll bewerten
                    _SHELL_LABELS = ('REVERSE SHELL', 'BIND SHELL', 'SHELL UPGRADE',
                                     'PTY UPGRADE', 'PROCESS INJECTION',
                                     'CONTAINER ESCAPE', 'C2 –')
                    artex_own = is_artex_own_task(pid)
                    for label, sev in hits:
                        is_shell = any(label.startswith(x) for x in _SHELL_LABELS)
                        if artex_own and not is_shell:
                            final_sev = 'LOW'
                            suffix    = f" [{scope}]" if scope else ''
                            alert(final_sev, f"[ARTEX-TASK] {label}{suffix}",
                                  f"PID={pid}  CMD={cmd[:150]}")
                        elif is_shell:
                            # Shell-Patterns: immer original Severity — KEIN Downgrade für private IPs
                            suffix = f" [{scope}]" if scope else ''
                            alert(sev, label + suffix, f"PID={pid}  CMD={cmd[:150]}")
                        else:
                            final_sev = classify_severity(cmd_ip, 0, sev)
                            suffix    = f" [{scope}]" if scope else ''
                            alert(final_sev, label + suffix, f"PID={pid}  CMD={cmd[:150]}")
                    # Reverse/Bind Shell Tracking: immer, unabhängig von ARTEX-Status
                    if any(lbl.startswith('REVERSE SHELL') or lbl.startswith('BIND SHELL') for lbl, _ in hits):
                        newly_alerted_shell_pids.add(pid)
                        # Sniffer: alle Sockets des Shell-Prozesses direkt tracken
                        if sniff_ok:
                            for conn in get_proc_tcp_conns(pid):
                                sniffer.track(conn['rem_ip'], conn['rem_port'], conn['local_port'])

            known_pids = current_pids

            # ── Tunnel Command Tracking ───────────────────────────────
            # Überwacht Kind-Prozesse von:
            #   a) Shells mit externem TCP-Socket als stdin (echte Tunnel-Sessions)
            #   b) Alle neu erkannten bash-i / Reverse-Shell-Prozesse
            active_shells = find_tunnel_shells()

            # Neu erkannte externe Shell-Sessions
            for pid, info_d in active_shells.items():
                if pid not in tunnel_shells:
                    scope = 'privat' if is_private_ip(info_d['remote'].split(':')[0]) else 'öffentlich'
                    # Eine aktive Reverse Shell ist immer CRITICAL – egal ob privat oder öffentlich
                    alert('CRITICAL',
                        f"TUNNEL SESSION AKTIV → {info_d['remote']} [{scope}]",
                        f"PID={pid}  Shell: {info_d['cmd'][:80]}")
                    tunnel_shells[pid] = info_d
                    # Dediziertes Session-Monitoring + Sniffer-Tracking
                    if sniff_ok and not session_monitor.is_open(info_d['remote']):
                        session_monitor.open_session(
                            info_d['remote'], pid, info_d['cmd'][:80]
                        )
                        if 'rem_ip' in info_d:
                            sniffer.track(info_d['rem_ip'], info_d['rem_port'],
                                          info_d['local_port'])


            # Neu erkannte Shell-Prozesse (bash -i etc.) auch tracken
            for pid in newly_alerted_shell_pids:
                if pid not in tunnel_shells:
                    cmd = current_pids.get(pid, '')
                    tunnel_shells[pid] = {'cmd': cmd, 'remote': 'lokal/unbekannt', 'inode': '0'}
                    if sniff_ok:
                        # Tatsächliche Remote-IP aus Socket-Verbindungen holen
                        conns = get_proc_tcp_conns(pid)
                        remote_str = 'lokal/unbekannt'
                        for conn in conns:
                            if not is_safe(conn['rem_ip'], conn['rem_port'], conn['local_port']):
                                remote_str = f"{conn['rem_ip']}:{conn['rem_port']}"
                                tunnel_shells[pid]['remote'] = remote_str
                                break
                        if remote_str != 'lokal/unbekannt':
                            scope = 'privat' if is_private_ip(remote_str.split(':')[0]) else 'öffentlich'
                            # Aktive Reverse Shell immer CRITICAL
                            alert('CRITICAL',
                                f"TUNNEL SESSION AKTIV → {remote_str} [{scope}]",
                                f"PID={pid}  Shell: {cmd[:80]}")
                            if not session_monitor.is_open(remote_str):
                                session_monitor.open_session(remote_str, pid, cmd[:80])
                        else:
                            if not session_monitor.is_open('lokal/unbekannt'):
                                session_monitor.open_session('lokal/unbekannt', pid, cmd[:80])

            # Beendete externe Sessions entfernen
            for gone in set(tunnel_shells) - set(active_shells) - newly_alerted_shell_pids:
                if tunnel_shells[gone].get('remote', '') != 'lokal/unbekannt':
                    remote_gone = tunnel_shells[gone]['remote']
                    alert('MEDIUM',
                        f"TUNNEL SESSION BEENDET ← {remote_gone}",
                        f"PID={gone}")
                    session_monitor.close_session(remote_gone)
                tunnel_shells.pop(gone, None)

            # Kind-Prozesse aller bekannten Shell-Sessions überwachen
            if tunnel_shells:
                tunnel_parent_pids = set(tunnel_shells.keys())
                skip_keywords = {
                    'python3 /tmp/artex-monitor.py', 'artex-monitor',
                    '/proc', 'sleep ', 'wait ',
                }

                # ── Schnell-Scan via /proc/PID/task/PID/children ─────────
                # Liest direkte Kind-Prozesse live – mehrere schnelle Durchläufe
                # um auch kurzlebige Befehle (whoami, id etc.) zu erwischen
                for _ in range(30):  # 30 Durchläufe × 0.01s = 0.3s Fenster bei 10ms Auflösung
                    for parent_pid in list(tunnel_parent_pids):
                        try:
                            with open(f'/proc/{parent_pid}/task/{parent_pid}/children') as f:
                                child_pids = f.read().split()
                            for cpid in child_pids:
                                if cpid in tunnel_child_seen or cpid == parent_pid:
                                    continue
                                cmd = get_cmdline(cpid)
                                if not cmd or any(kw in cmd for kw in skip_keywords):
                                    continue
                                tunnel_child_seen.add(cpid)
                                parent_info = tunnel_shells.get(parent_pid, {})
                                remote      = parent_info.get('remote', 'unbekannt')
                                scope       = 'privat' if is_private_ip(remote.split(':')[0]) else 'öffentlich'
                                sev         = 'HIGH' if scope == 'öffentlich' else 'MEDIUM'
                                alert(sev,
                                    f"TUNNEL CMD [{scope}] via {remote}",
                                    f"Befehl: {cmd[:150]}")
                                for label, pat_sev in scan_for_patterns(cmd):
                                    final_sev = classify_severity(remote.split(':')[0], 0, pat_sev)
                                    alert(final_sev, f"TUNNEL CMD VERDÄCHTIG – {label}",
                                        f"Befehl: {cmd[:120]}")
                                if re.search(r'\b(bash|sh|zsh|ksh|fish|dash|python[23]?|perl|ruby)\b', cmd):
                                    if cpid not in tunnel_shells:
                                        tunnel_shells[cpid] = {'cmd': cmd, 'remote': remote, 'inode': '0'}
                                        tunnel_parent_pids.add(cpid)
                        except Exception:
                            pass
                    time.sleep(0.01)  # 10ms Auflösung

                # ── Vollständiger PID-Scan (Backup für verpasste Prozesse) ──
                for pid, cmd in current_pids.items():
                    if pid in tunnel_child_seen or pid in tunnel_parent_pids:
                        continue
                    ppid = get_ppid(pid)
                    if ppid not in tunnel_parent_pids:
                        continue
                    tunnel_child_seen.add(pid)
                    if any(kw in cmd for kw in skip_keywords):
                        continue
                    parent_info = tunnel_shells.get(ppid, {})
                    remote      = parent_info.get('remote', 'unbekannt')
                    scope       = 'privat' if is_private_ip(remote.split(':')[0]) else 'öffentlich'
                    sev         = 'HIGH' if scope == 'öffentlich' else 'MEDIUM'
                    alert(sev,
                        f"TUNNEL CMD [{scope}] via {remote}",
                        f"Befehl: {cmd[:150]}")
                    for label, pat_sev in scan_for_patterns(cmd):
                        final_sev = classify_severity(remote.split(':')[0], 0, pat_sev)
                        alert(final_sev, f"TUNNEL CMD VERDÄCHTIG – {label}",
                            f"Befehl: {cmd[:120]}")
                    # Shell-Prozess weiterverfolgen
                    if re.search(r'\b(bash|sh|zsh|ksh|fish|dash|python[23]?|perl|ruby)\b', cmd):
                        if pid not in tunnel_shells:
                            tunnel_shells[pid] = {'cmd': cmd, 'remote': remote, 'inode': '0'}

                # Receive-Buffer externer Tunnel prüfen
                for pid, info_d in active_shells.items():
                    rx = get_inode_rx_queue(info_d['inode'])
                    if rx > 0:
                        alert('MEDIUM',
                            f"TUNNEL DATEN EINGEHEND – {rx} Bytes",
                            f"Session: {info_d['remote']}  PID={pid}")


            # Periodische Checks mit eigenem Zähler
            if not hasattr(main, '_rk_counter'):
                main._rk_counter = 0
            main._rk_counter += 1
            _c = main._rk_counter
            _i = max(1, INTERVAL)

            # ~10s: Rootkit + Implants + File Integrity + Persistence
            if _c % max(1, int(10 / _i)) == 0:
                for sev, msg, detail in _check_rootkit_indicators():
                    alert(sev, msg, detail)
                for sev, msg, detail in _check_process_implants():
                    alert(sev, msg, detail)
                for sev, msg, detail in _check_file_integrity():
                    alert(sev, msg, detail)
                for sev, msg, detail in _check_persistence():
                    alert(sev, msg, detail)
                for sev, msg, detail in _check_log_tampering():
                    alert(sev, msg, detail)

            # ~30s: SUID-Scan (teurer Verzeichnis-Walk)
            if _c % max(1, int(30 / _i)) == 0:
                for sev, msg, detail in _check_suid_binaries():
                    alert(sev, msg, detail)

            # ~5s: Schnelle FD + Webshell-Checks
            if _c % max(1, int(5 / _i)) == 0:
                for sev, msg, detail in _check_sensitive_fd_access():
                    alert(sev, msg, detail)
                for sev, msg, detail in _check_webshell_spawn():
                    alert(sev, msg, detail)

            time.sleep(INTERVAL)

    except KeyboardInterrupt:
        print(f"\n{DIM}[{ts()}]{NC} {GREEN}Monitor beendet.{NC}", flush=True)

if __name__ == '__main__':
    main()
