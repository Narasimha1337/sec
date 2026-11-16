#!/bin/bash
# ============================================================================
#  OpenText Network Automation CE 25.2 — Security Enumeration (read-only)
#  Scope   : authorized assessment. Web/app server AND DB server.
#  Design  : NO modification, NO outbound network, NO persistence, built-ins
#            only. Auto-detects server role + product + DB engine, flags
#            findings, prints severity-ranked summary.
#  Note    : RHEL backports security fixes without version bumps — CVE flags
#            are "possible" until confirmed against OpenText/RHEL advisories.
#  Usage   : bash na_enum.sh        (run on BOTH servers)
#
#  CHANGELOG vs original:
#   - Added a privilege-level banner (root / passwordless-sudo / unprivileged)
#     printed up front, and a skip() helper so a permission-denied read shows
#     as an explicit INFO finding instead of silently vanishing.
#   - Added docker/lxd-group membership check (distinct from socket readability).
#   - Findings summary now dedupes with sort -u.
#   - See na_cve_reference.md (now provided) for the maintained CVE list
#     instead of the hardcoded echo lines below, which can drift.
# ============================================================================
usage() {
  cat <<'EOF'
Usage: bash na_enum.sh [-h|--help]

Read-only security enumeration for an OpenText Network Automation CE 25.2
host (app/web server OR DB server — auto-detects role). No arguments or
environment variables needed; run it directly on the target host.
Makes no changes, no outbound network calls.

Options:
  -h, --help    Show this help and exit

Run this on BOTH the app/web server and the DB server. If your access
level differs between the two (e.g. user-level on one, admin on the
other), run it once per access level on the same host when possible and
diff the outputs — INFO "not readable" lines mark what the lower-privilege
run couldn't actually check.

See also: na_db_enum.sh, na_webapp_surface.sh, na_hardening_audit.sh,
na_cve_reference.md
EOF
}
case "${1:-}" in -h|--help) usage; exit 0;; esac

export LC_ALL=C

B="==================================================================="
sec() { printf '\n%s\n[ %s ]\n%s\n' "$B" "$1" "$B"; }

FINDINGS=""
add() {
  local k
  case "$1" in CRITICAL) k=0;; HIGH) k=1;; MEDIUM) k=2;; LOW) k=3;; INFO) k=4;; esac
  FINDINGS="${FINDINGS}${k}|$1|$2"$'\n'
}
ver_lt() { [ "$1" != "$2" ] && [ "$1" = "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" ]; }
skip() { add INFO "Not readable as $(id -un) (needs root/service account): $2 — $1"; }

# ============================================================================
sec "SYSTEM & ROLE"
echo "[hostname]"; hostname; hostname -f 2>/dev/null
echo "[user]"; id
echo "[release]"; cat /etc/redhat-release 2>/dev/null
echo "[kernel]"; uname -r

sec "PRIVILEGE LEVEL (read this first)"
CUR_USER=$(id -un); CUR_UID=$(id -u)
if [ "$CUR_UID" -eq 0 ]; then
  PRIV="root"
elif sudo -n true 2>/dev/null; then
  PRIV="passwordless-sudo"
elif sudo -n -l >/dev/null 2>&1; then
  PRIV="partial-sudo"
else
  PRIV="unprivileged"
fi
echo "running as: $CUR_USER (uid=$CUR_UID) — privilege level: $PRIV"
echo "(an INFO 'not readable' finding below means a check was SKIPPED, not that"
echo " the thing it checks is absent. Re-run on the admin-access box, or ask an"
echo " admin for the file, before treating a skipped section as clean.)"

TOMCAT_XML=$(find / -xdev -name 'server.xml' -path '*tomcat*' 2>/dev/null | head -1)
PSQL_BIN=$(command -v psql 2>/dev/null)
PG_CONFS=$(find / -xdev -name 'pg_hba.conf' 2>/dev/null)
ORA_LISTENER=$(find / -xdev -name 'listener.ora' 2>/dev/null)
ROLE=""
[ -n "$TOMCAT_XML" ] && ROLE="${ROLE}app/web "
[ -n "$PSQL_BIN" ] || [ -n "$PG_CONFS" ] && ROLE="${ROLE}db-postgres "
[ -n "$ORA_LISTENER" ] || [ -n "${ORACLE_HOME:-}" ] && ROLE="${ROLE}db-oracle "
echo "[detected role]: ${ROLE:-unknown}"

# ============================================================================
sec "PRODUCT DISCOVERY (OpenText / NA / Micro Focus)"
NA_PATHS=$(find / -xdev \( -iname '*opentext*' -o -iname '*microfocus*' -o -iname '*networkautomation*' -o -iname '*network_automation*' -o -iname '*hpna*' -o -iname '*hpena*' -o -iname '*networksatellite*' \) 2>/dev/null)
echo "$NA_PATHS"
[ -n "$NA_PATHS" ] && add INFO "NA install paths discovered (see above)"
echo "[common install dirs]"; ls -ld /opt/opentext /opt/microfocus /opt/NA /opt/NetworkAutomation /var/opt/opentext /var/opt/microfocus 2>/dev/null

# ============================================================================
sec "NA PRODUCT DEEP-DIVE (credential vault / encryption / trust)"
NA_ROOT=$(find / -xdev \( -iname '*networkautomation*' -o -iname '*opentext*' -o -iname '*microfocus*' -o -iname '*hpna*' \) -maxdepth 5 -type d 2>/dev/null | head -1)
echo "[NA install root]: ${NA_ROOT:-not-found}"
[ -n "$NA_ROOT" ] && ls -ld "$NA_ROOT"
SRC="/opt /etc /usr/local /var/opt"
[ -n "$NA_ROOT" ] && SRC="$NA_ROOT $SRC"

echo "[process owner (NA/Tomcat/Java)]"
ps auxww 2>/dev/null | grep -iE 'java|tomcat|catalina|opentext|microfocus|networkautomation' | grep -v grep
ps auxww 2>/dev/null | grep -iE 'java|tomcat|catalina' | grep -v grep | awk '{print $1}' | grep -qx 'root' \
  && add HIGH "NA/Tomcat Java process runs as root (least-privilege violation)"

echo "[encryption / master-key config]"
grep -rIlE 'encrypt|crypto|masterkey|keystore|secretkey' $SRC 2>/dev/null | head -30

echo "[datasource / DB creds]"
grep -rIlE 'jdbc:|datasource|dbpassword|db_user|dbuser' $SRC 2>/dev/null | head -30

echo "[world/group-readable NA secrets]"
NA_SECRETS=""
[ -n "$NA_ROOT" ] && NA_SECRETS=$(find "$NA_ROOT" -xdev \( -name '*.jks' -o -name '*.p12' -o -name '*.keystore' -o -name '*.key' -o -name '*.pem' -o -name '*.properties' -o -name '*.xml' -o -name '*.conf' \) 2>/dev/null)
while IFS= read -r f; do
  if [ -r "$f" ]; then ls -l "$f"; add HIGH "NA secret file readable by unprivileged user: $f"; fi
done <<< "$NA_SECRETS"

echo "[backups / dumps / exports]"
find / -xdev \( -name '*.sql' -o -name '*.dump' -o -name '*.bak' -o -name '*.zip' -o -name '*.tar' -o -name '*.tar.gz' \) 2>/dev/null | head -40

echo "[license files]"
find / -xdev \( -iname '*.lic' -o -iname '*license*' \) 2>/dev/null | head -20

echo "[SNMP community / device creds in config]"
grep -rIlE 'community|snmp|telnet|enable secret|enable password|sharedsecret' $SRC 2>/dev/null | head -30

echo "[logs leaking credentials]"
LOGSRC="$NA_ROOT"
[ -d /var/log/opentext ] && LOGSRC="$LOGSRC /var/log/opentext"
[ -d /var/log/microfocus ] && LOGSRC="$LOGSRC /var/log/microfocus"
if [ -n "$LOGSRC" ]; then
  grep -rIlE 'password[[:space:]]*[=:]|community|enable secret' $LOGSRC 2>/dev/null | head -30
fi

echo "[satellite / agent trust config]"
grep -rIlE 'satellite|agent|proxy|sharedsecret|sharedkey|trust' $SRC 2>/dev/null | head -30

# ============================================================================
sec "SECRETS-HEAVY FILES (JDBC / datasource / keystores / backups)"
SECRET_FILES=$(find / -xdev \( -name '*.properties' -o -name '*.conf' -o -name '*.jks' -o -name '*.p12' -o -name '*.keystore' -o -name '*.truststore' -o -name '*.bak' -o -name '*.sql' -o -name '*.dump' -o -name '.git' \) 2>/dev/null)
echo "$SECRET_FILES"
echo "[world-readable secret files]"
while IFS= read -r f; do
  [ -r "$f" ] && { ls -l "$f"; add HIGH "World/group-readable secret file: $f"; }
done <<< "$SECRET_FILES"
echo "[JDBC / password strings in config]"
grep -rIlE 'jdbc:(postgresql|oracle)|dbpassword|db_password|password[[:space:]]*=|password=|datasource|secretkey|encryption' \
  /opt /etc /var/opt /usr/local 2>/dev/null

# ============================================================================
sec "TOMCAT / JAVA / LOG4J"
echo "[server.xml]"
if [ -n "$TOMCAT_XML" ]; then
  ls -l "$TOMCAT_XML"
  if [ -r "$TOMCAT_XML" ]; then cat "$TOMCAT_XML" 2>/dev/null; else skip "$TOMCAT_XML" "server.xml"; fi
else
  echo "(no tomcat server.xml found)"
fi
echo "[AJP connector (Ghostcat CVE-2020-1938)]"
if [ -n "$TOMCAT_XML" ] && [ -r "$TOMCAT_XML" ]; then
  AJP=$(grep -iE 'AJP|8009' "$TOMCAT_XML" 2>/dev/null)
  echo "$AJP"
  echo "$AJP" | grep -qiE 'AJP|8009' && { echo "$AJP" | grep -qiE 'address="127\.0\.0\.1"|address="::1"|address="localhost"' \
    && add LOW "AJP connector present but loopback-bound" \
    || add CRITICAL "AJP connector exposed (possible Ghostcat RCE)"; }
fi
echo "[tomcat version artifacts]"; find / -xdev \( -name 'catalina.jar' -o -name 'RELEASE-NOTES*' \) -path '*tomcat*' 2>/dev/null
echo "[tomcat manager apps]"; find / -xdev -type d \( -name 'manager' -o -name 'host-manager' \) -path '*webapps*' 2>/dev/null
echo "[java version]"; java -version 2>&1; rpm -qa 2>/dev/null | grep -iE 'java|jdk|jre|openjdk'
echo "[log4j jars]"
LOG4J=$(find / -xdev -name 'log4j-core-*.jar' 2>/dev/null); echo "$LOG4J"
while IFS= read -r j; do
  v=$(basename "$j" | sed -E 's/^log4j-core-([0-9.]+).*/\1/')
  [ -n "$v" ] && ver_lt "$v" "2.17.1" && add HIGH "log4j-core $v possibly Log4Shell-vulnerable (CVE-2021-44228): $j"
done <<< "$LOG4J"

# ============================================================================
sec "WEB APP FILES (contexts, endpoints, backups)"
find / -xdev -path '*webapps*' \( -name '*.war' -o -name '*.jsp' -o -name '*.xml' \) 2>/dev/null | head -60
echo "[NA UI / API config hints]"
grep -rIlE 'context-path|/na|/api|REST|soap|swagger|openapi' /opt /var/opt /usr/local 2>/dev/null | head -40

# ============================================================================
sec "GENERIC PRIVESC (SUID / CAPS / WORLD-WRITABLE / CRON / CONTAINER)"
SUID=$(find / -xdev -perm -4000 -type f 2>/dev/null); echo "-- SUID --"; echo "$SUID"
DANGEROUS="bash|sh|dash|ash|zsh|ksh|csh|tcsh|python|python2|python3|perl|ruby|php|lua|node|nodejs|find|vim|vi|nano|less|more|man|cp|mv|dd|tar|zip|unzip|gzip|bzip2|awk|gawk|sed|env|nice|socat|nc|ncat|netcat|nmap|docker|git|make|xargs|script|screen|tmux|ed|tee|timeout|base32|base64|fold|expand|install|chmod|chown|busybox|ionice|taskset|watch|setsid|flock|date|sleep|printf|cut|head|tail|sort|uniq|od|xz|lzma|unshare|runc|gcc|cc"
while IFS= read -r f; do
  b=$(basename "$f"); echo "$b" | grep -Eq "^($DANGEROUS)([0-9.]+)?$" && add HIGH "SUID on privesc-capable binary: $f"
done <<< "$SUID"
CAPOUT=$(getcap -r / 2>/dev/null); echo "-- capabilities --"; echo "$CAPOUT"
while IFS= read -r line; do
  echo "$line" | grep -Eq 'cap_(setuid|setgid|chown|dac_read_search|dac_override|sys_admin|sys_ptrace|sys_module|sys_chroot|net_admin|net_raw)' \
    && add HIGH "Dangerous file capability: $line"
done <<< "$CAPOUT"
echo "-- world-writable dirs WITHOUT sticky bit --"
WWNOSTICKY=$(find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null); echo "$WWNOSTICKY"
while IFS= read -r d; do add HIGH "World-writable dir without sticky bit: $d"; done <<< "$WWNOSTICKY"
echo "-- world-writable files --"; find / -xdev -type f -perm -0002 2>/dev/null
echo "-- writable \$PATH --"
WRPATH=$(echo "$PATH" | tr ':' '\n' | while read -r d; do [ -n "$d" ] && [ -w "$d" ] && echo "$d"; done)
[ -n "$WRPATH" ] && add HIGH "Writable dir(s) in \$PATH: $(echo "$WRPATH" | tr '\n' ' ')"
CRONWW=$(find /etc/cron* /var/spool/cron /var/spool/anacron -type f -perm -0002 2>/dev/null)
while IFS= read -r f; do add CRITICAL "World-writable cron script: $f"; done <<< "$CRONWW"
echo "-- docker/lxd group membership --"
id -Gn 2>/dev/null | grep -qwE 'docker' && \
  add CRITICAL "Current user is in the 'docker' group — root-equivalent via 'docker run -v /:/host'"
id -Gn 2>/dev/null | grep -qwE 'lxd' && \
  add CRITICAL "Current user is in the 'lxd' group — root-equivalent via a privileged LXD container mount"

# ============================================================================
sec "ACCOUNTS & /etc/passwd"
[ -w /etc/passwd ] && add CRITICAL "/etc/passwd writable (append UID 0 user)"
if [ -r /etc/shadow ]; then add HIGH "/etc/shadow readable (hash cracking)"; else skip /etc/shadow "/etc/shadow"; fi
UID0=$(awk -F: '$3==0{print $1}' /etc/passwd); echo "[UID 0] $UID0"
[ "$(echo "$UID0" | grep -c .)" -gt 1 ] && add MEDIUM "Multiple UID 0 accounts"
echo "[sudo]"; sudo -n -l 2>/dev/null || echo "(no passwordless sudo)"
sudo -n -l >/dev/null 2>&1 && add CRITICAL "Passwordless sudo available"
sudo -V 2>/dev/null | head -1 | grep -Eq '1\.8\.([2-9]|[12][0-9]|3[01])(\.|p|$)|1\.9\.[0-4]|1\.9\.5p?0?$' \
  && add CRITICAL "sudo possibly vulnerable to CVE-2021-3156 (Baron Samedit) — confirm patch level"
PKV=$(pkexec --version 2>/dev/null | sed -E 's/.*version //; s/[^0-9.].*//')
[ -n "$PKV" ] && ver_lt "$PKV" "0.120" && add CRITICAL "pkexec $PKV possibly CVE-2021-4034 (PwnKit)"

# ============================================================================
sec "SSH & KERNEL HARDENING"
if [ -r /etc/ssh/sshd_config ]; then
  grep -qE '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config 2>/dev/null && add HIGH "SSH PermitRootLogin yes"
  grep -qE '^\s*PermitEmptyPasswords\s+yes' /etc/ssh/sshd_config 2>/dev/null && add CRITICAL "SSH PermitEmptyPasswords yes"
else
  skip /etc/ssh/sshd_config "sshd_config"
fi
ASLR=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
echo "randomize_va_space=$ASLR kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null) dmesg_restrict=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)"
[ "$ASLR" = "0" ] && add HIGH "ASLR disabled"
SE=$(getenforce 2>/dev/null); echo "[selinux] $SE"
{ [ "$SE" = "Permissive" ] || [ "$SE" = "Disabled" ]; } && add HIGH "SELinux ${SE}"

# ============================================================================
sec "LISTENING PORTS (product-relevant)"
ss -tulnp 2>/dev/null
echo "-- product port quick-check --"
ss -tuln 2>/dev/null | grep -E ':(443|8443|8080|8009|5432|1521|1099|1090|9010|4447)\b' \
  && add INFO "Product-relevant ports listening (see above)"

# ============================================================================
sec "DATABASE ENGINE DETECTION"
echo "[PostgreSQL binary]"; command -v psql 2>/dev/null; psql --version 2>/dev/null
echo "[PostgreSQL packages]"; rpm -qa 2>/dev/null | grep -i postgres
echo "[pg_hba.conf locations]"; echo "$PG_CONFS"
echo "[Oracle packages]"; rpm -qa 2>/dev/null | grep -i oracle
echo "[Oracle listener.ora]"; echo "$ORA_LISTENER"
echo "[Oracle env]"; env 2>/dev/null | grep -iE 'ORACLE|TNS|DB_'

if [ -n "$PG_CONFS" ]; then
  sec "POSTGRESQL CONFIG (pg_hba.conf)"
  for c in $PG_CONFS; do
    echo "== $c =="; ls -l "$c"
    if [ -r "$c" ]; then
      cat "$c" 2>/dev/null
      grep -E '^[[:space:]]*(host|local)' "$c" | grep -iE 'trust' && add CRITICAL "pg_hba.conf uses 'trust' (passwordless) auth: $c"
      grep -E '^[[:space:]]*host' "$c" | grep -E '0\.0\.0\.0/0|::/0' && add HIGH "pg_hba.conf allows all remote hosts (0.0.0.0/0): $c"
      grep -E '^[[:space:]]*host' "$c" | grep -qE 'md5' && add MEDIUM "pg_hba.conf uses md5 (weak; prefer scram-sha-256): $c"
    else
      skip "$c" "pg_hba.conf"
    fi
  done
  PG_CONF=$(find / -xdev -name 'postgresql.conf' 2>/dev/null | head -1)
  [ -n "$PG_CONF" ] && [ -r "$PG_CONF" ] && grep -E '^\s*listen_addresses' "$PG_CONF" | grep -E '\*|0\.0\.0\.0' && add HIGH "postgresql.conf listen_addresses='*' (exposed to network)"
fi

if [ -n "$ORA_LISTENER" ] || [ -n "${ORACLE_HOME:-}" ]; then
  sec "ORACLE LISTENER"
  for l in $ORA_LISTENER; do
    echo "== $l =="; ls -l "$l"
    if [ -r "$l" ]; then cat "$l" 2>/dev/null; else skip "$l" "listener.ora"; fi
  done
  [ -n "$ORA_LISTENER" ] && add INFO "Oracle listener.ora present — test 1521 exposure & default accounts externally"
fi

# ============================================================================
sec "SERVICE ACCOUNTS & IDENTITY (S5)"
echo "[login-shell accounts]"; awk -F: '$7!~/nologin|false/{print $1" -> "$7}' /etc/passwd
echo "[interactive accounts (uid>=1000)]"; awk -F: '$3>=1000 && $7!~/nologin|false/{print $1" -> "$7}' /etc/passwd
echo "[last logins]"; lastlog 2>/dev/null | head -20

# ============================================================================
sec "INTEGRITY MONITORING (T5)"
echo "[AIDE]"; command -v aide 2>/dev/null; ls -ld /var/lib/aide 2>/dev/null
echo "[Tripwire]"; command -v tripwire 2>/dev/null
[ -z "$(command -v aide 2>/dev/null)$(command -v tripwire 2>/dev/null)" ] \
  && add MEDIUM "No file-integrity monitoring (AIDE/Tripwire) detected"
echo "[rpm -Va (root-only, sample)]"; rpm -Va 2>/dev/null | head -50

# ============================================================================
sec "LOG & AUDIT POSTURE (R3/R5/T6)"
echo "[auditd active]"; systemctl is-active auditd 2>/dev/null
echo "[rsyslog active]"; systemctl is-active rsyslog 2>/dev/null
echo "[auditd retention]"
if [ -r /etc/audit/auditd.conf ]; then
  grep -E '^(max_log_file|num_logs|space_left_action|max_log_file_action)' /etc/audit/auditd.conf 2>/dev/null
else
  skip /etc/audit/auditd.conf "auditd.conf"
fi
echo "[logrotate policy]"; grep -rEh '^\s*(weekly|monthly|daily|rotate|maxsize|compress)' /etc/logrotate.conf /etc/logrotate.d/* 2>/dev/null | head -40
WRITELOG=$(find /var/log -xdev -writable -type f 2>/dev/null)
echo "[writable log files]"; echo "$WRITELOG"
[ -n "$WRITELOG" ] && add HIGH "Log files writable by current user under /var/log"
echo "[log dir perms]"; ls -ld /var/log /var/log/secure /var/log/audit 2>/dev/null

# ============================================================================
sec "PII / SENSITIVE DATA SCAN (I2)"
PII=$(grep -rIlE '[0-9]{3}-[0-9]{2}-[0-9]{4}|[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' \
  /etc /home /opt /var/opt /usr/local /var/log /tmp 2>/dev/null | head -40)
echo "$PII"
[ -n "$PII" ] && add MEDIUM "PII patterns (SSN/card/email) found in readable files"

# ============================================================================
sec "DB TRANSPORT ENCRYPTION (S7)"
JDBC_FILES=$(grep -rIlE 'jdbc:(postgresql|oracle)' /opt /etc /var/opt /usr/local 2>/dev/null)
echo "$JDBC_FILES"
while IFS= read -r f; do
  echo "== $f =="; grep -iE 'jdbc:|sslmode|tcp|tcps|encrypt' "$f" 2>/dev/null
  if grep -qiE 'jdbc:postgresql' "$f" && ! grep -qiE 'sslmode=(require|verify-ca|verify-full)' "$f"; then
    add MEDIUM "PostgreSQL JDBC URL lacks TLS (sslmode) in $f"
  fi
done <<< "$JDBC_FILES"

# ============================================================================
sec "UNPRIVILEGED DEEP-DIVE (user-visible secrets & privesc)"

echo "[auto-login credential files]"
CRED_FILES=$(find /home /root -maxdepth 4 \( -name '.pgpass' -o -name '.my.cnf' -o -name '.netrc' -o -name '.git-credentials' -o -name 'config.json' -o -name 'credentials' \) 2>/dev/null)
echo "$CRED_FILES"
while IFS= read -r f; do
  if [ -r "$f" ]; then ls -l "$f"; add HIGH "Auto-login credential file readable: $f"; else skip "$f" "auto-login credential file"; fi
done <<< "$CRED_FILES"

echo "[shell history files]"
HISTF=$(find /home /root -maxdepth 3 \( -name '.*_history' -o -name '.viminfo' -o -name '.lesshst' -o -name '.psql_history' -o -name '.mysql_history' \) 2>/dev/null)
echo "$HISTF"
while IFS= read -r f; do
  [ -r "$f" ] && add MEDIUM "Shell history readable (may leak creds): $f"
done <<< "$HISTF"

echo "[dotfiles w/ embedded secrets]"
for f in /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /home/*/.env /root/.bashrc /root/.profile /root/.env; do
  [ -r "$f" ] && grep -HIE 'password|token|secret|api[_-]?key|AWS_|DB_PASS|PGPASS' "$f" 2>/dev/null
done

echo "[current process capabilities]"
grep -E '^(CapInh|CapPrm|CapEff|CapBnd|CapAmb)' /proc/self/status 2>/dev/null
capsh --print 2>/dev/null | grep -iE 'Current|Bounding'

echo "[writable LD paths]"
LDW=$(echo "${LD_LIBRARY_PATH:-}" | tr ':' '\n' | while read -r d; do [ -n "$d" ] && [ -w "$d" ] && echo "$d"; done)
[ -n "$LDW" ] && add HIGH "Writable LD_LIBRARY_PATH dir(s): $(echo "$LDW" | tr '\n' ' ')"
[ -w /etc/ld.so.preload ] && add CRITICAL "/etc/ld.so.preload writable"

echo "[tmux/screen sockets (session hijack)]"
ls -la /tmp/tmux-* /tmp/.screen* /run/screen /tmp/.X11-unix 2>/dev/null

echo "[systemd timers (missed scheduler)]"
systemctl list-timers --all 2>/dev/null | head -30

echo "[systemd units w/ Environment secrets]"
grep -rIlE 'Environment=.*(PASS|SECRET|TOKEN|KEY|PWD)' /etc/systemd /usr/lib/systemd/system 2>/dev/null | head -30

echo "[process cmdline password leaks]"
ps auxww 2>/dev/null | grep -iE 'passwd|password|token|secret' | grep -v grep

echo "[NSS users beyond /etc/passwd (LDAP/AD)]"
getent passwd 2>/dev/null | head -40

echo "[domain/realm + kerberos tickets]"
realm list 2>/dev/null
command -v klist >/dev/null 2>&1 && klist 2>/dev/null | head -10

echo "[ssh known_hosts (lateral movement targets)]"
find /home /root /etc/ssh -maxdepth 3 \( -name 'known_hosts' -o -name 'ssh_known_hosts' \) 2>/dev/null | while read -r f; do
  [ -r "$f" ] && { echo "== $f =="; cat "$f" 2>/dev/null; }
done

echo "[git repos w/ creds in config]"
GIT_DIRS=$(find / -xdev -type d -name '.git' 2>/dev/null)
echo "$GIT_DIRS"
while IFS= read -r d; do
  [ -r "$d/config" ] && grep -qiE 'url[[:space:]]*=.*(token|password)|token|password' "$d/config" && add MEDIUM "Git repo with creds in config: $d"
done <<< "$GIT_DIRS"

echo "[dmesg access]"
if dmesg >/dev/null 2>&1; then add MEDIUM "dmesg readable (kernel info disclosure)"; else echo "(blocked)"; fi

echo "[current sessions]"
who -a 2>/dev/null; w 2>/dev/null | head

echo "[login banners (info disclosure)]"
cat /etc/issue /etc/motd 2>/dev/null

echo "[world-readable files in /tmp /dev/shm /var/tmp]"
find /tmp /dev/shm /var/tmp -maxdepth 2 -type f -perm -0004 2>/dev/null | head -40

# ============================================================================
sec "PRODUCT VERSION & KNOWN CVEs"
echo "[NA version/build files]"
NA_VER_FILES=$(find / -xdev \( -name 'build.properties' -o -name 'VERSION' -o -name 'product.version' -o -name 'version.properties' -o -name 'release-notes*' -o -name '*.build' \) 2>/dev/null)
echo "$NA_VER_FILES"
while IFS= read -r f; do
  [ -r "$f" ] && { echo "== $f =="; grep -iE 'version|build|release' "$f" 2>/dev/null | head -20; }
done <<< "$NA_VER_FILES"

echo "[bundled JDK (Azul Zulu?)]"
java -version 2>&1
rpm -qa 2>/dev/null | grep -iE 'zulu|azul|jdk|java-'

echo "[known NA CVEs — see na_cve_reference.md for the maintained list]"
echo "  (summary only here; na_cve_reference.md is the source of truth)"
echo "  * Hotfix 2447300 / KM000044586  -> NA 24.4 / 25.2 / 25.4 (verify applied)"
echo "  * Azul Java: CVE-2025-31257, CVE-2025-53057, CVE-2025-53066, CVE-2025-61748"
echo "  * Historical: CVE-2018-6493 (SQLi 8.8), CVE-2018-6492 (XSS), CVE-2019-3493 (RCE 8.8)"

# ============================================================================
sec "INSTALLED PACKAGES (offline CVE diff)"
rpm -qa 2>/dev/null

# ============================================================================
echo
echo "########################################################################"
echo "#                         FINDINGS SUMMARY                              #"
echo "########################################################################"
echo "Run as: $CUR_USER (level: $PRIV)"
if [ -z "$FINDINGS" ]; then
  echo "  No automated findings."
else
  printf '%s' "$FINDINGS" | sort -u | sort -t'|' -k1,1n -s | while IFS='|' read -r k sev msg; do
    [ -n "$sev" ] || continue
    printf '  [%-8s] %s\n' "$sev" "$msg"
  done
  echo; echo "  Unique issues flagged: $(printf '%s' "$FINDINGS" | sort -u | grep -c .)"
fi
echo
echo "NOTE: version-based CVE flags are 'possible' only — confirm against"
echo "OpenText / RHEL advisories (backported patches don't bump versions)."
echo "Run this script on BOTH servers, and once unprivileged + once with admin"
echo "access on each, so SKIPPED findings don't get mistaken for clean ones."
echo "Enumeration complete. Nothing modified."
