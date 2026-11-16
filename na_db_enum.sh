#!/bin/bash
# ============================================================================
#  OpenText Network Automation CE 25.2 — DATABASE SERVER deep-dive (read-only)
#
#  Run on the DB server. Auto-detects PostgreSQL / Oracle / SQL Server / MySQL.
#  Complements na_enum.sh (host basics) and na_hardening_audit.sh (CIS).
#
#  Covers what na_enum.sh does NOT:
#    - full postgresql.conf audit (TLS, logging, password_encryption, pgaudit,
#      data-dir mode, log_file_mode, unix_socket_permissions, timeouts)
#    - pg_hba.conf AND pg_ident.conf, peer/trust/md5, 0.0.0.0/0
#    - engine version vs known-CVE floor
#    - passive local-auth probe (proves whether trust/peer lets anyone in)
#    - DB role/privilege review, dangerous extensions (dblink, plpython,
#      pg_execute_server_program), PUBLIC schema grants
#    - Oracle: listener.ora ADMIN_RESTRICTIONS/extproc, sqlnet.ora encryption,
#      init params (remote_os_authent, O7_DICTIONARY_ACCESSIBILITY, audit_trail),
#      orapw file mode, TDE wallet auto-login, adump
#    - SQL Server on Linux: mssql.conf forceencryption/tlsprotocols/auditlevel
#    - MySQL/MariaDB: local_infile, secure_file_priv, require_secure_transport
#    - backups & dumps: location, mode, encryption, retention, NFS exposure
#    - DB OS account hygiene, .pgpass, PGPASSWORD in env/systemd/cron
#    - which network ranges can reach the DB port (exposure vs app server only)
#    - NA schema objects that hold device credentials (names only, no dumping)
#
#  Design : NO writes, NO DDL/DML, read-only SELECTs only, no outbound network.
#  Usage  : bash na_db_enum.sh
#           NO_DB_PROBE=1 bash na_db_enum.sh   # fully passive, no client connect
#  Output : stdout only. Capture it on YOUR box:
#           ssh user@db 'bash -s' < na_db_enum.sh | tee db_enum.txt
#
#  RoE    : the local-auth probe is ONE no-password connection attempt per
#           engine (never prompts, never retries) — it is a trust-config check,
#           not credential brute-forcing. Set NO_DB_PROBE=1 to skip it.
#
#  CHANGELOG vs original:
#   - Added a privilege-level banner up front (root / dba-group member /
#     passwordless-sudo / plain unprivileged user) and folded it into the
#     findings summary, so a user-level run and an admin-level run on the
#     same box are clearly labelled when you diff them.
# ============================================================================
usage() {
  cat <<'EOF'
Usage: bash na_db_enum.sh [-h|--help]
       NO_DB_PROBE=1 bash na_db_enum.sh

Read-only DATABASE SERVER deep-dive for OpenText Network Automation CE
25.2. Auto-detects PostgreSQL / Oracle / SQL Server / MySQL and audits
auth config, TLS, backups, and DB-side audit posture. No writes, no
DDL/DML beyond read-only SELECTs, no outbound network.

Options:
  -h, --help     Show this help and exit

Environment:
  NO_DB_PROBE=1  Skip the passive local-auth probe (one no-password
                 connection attempt per engine). Use this for a fully
                 passive run with zero live connection attempts.

Capture output on your own box:
  ssh user@db 'bash -s' < na_db_enum.sh | tee db_enum.txt

See also: na_enum.sh (host basics), na_hardening_audit.sh (CIS-lite),
na_webapp_surface.sh (run on the app/web server).
EOF
}
case "${1:-}" in -h|--help) usage; exit 0;; esac

export LC_ALL=C
export PGCONNECT_TIMEOUT=5
PROBE="${NO_DB_PROBE:-0}"

B="==================================================================="
sec() { printf '\n%s\n[ %s ]\n%s\n' "$B" "$1" "$B"; }
sub() { printf '\n-- %s --\n' "$1"; }

FINDINGS=""
add() {
  local k
  [ -n "${2:-}" ] || return 0
  case "$1" in CRITICAL) k=0;; HIGH) k=1;; MEDIUM) k=2;; LOW) k=3;; *) k=4;; esac
  FINDINGS="${FINDINGS}${k}|$1|$2"$'\n'
}
ver_lt() { [ "$1" != "$2" ] && [ "$1" = "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" ]; }
has() { command -v "$1" >/dev/null 2>&1; }
mode_of() { stat -c '%a' "$1" 2>/dev/null; }
# flag a file that should be owner-only
chk_mode() { # chk_mode <file> <label>
  local m; m=$(mode_of "$1"); [ -n "$m" ] || return 0
  echo "  mode=$m $(ls -l "$1" 2>/dev/null)"
  case "$m" in
    *[4567]) add HIGH "$2 is world-readable (mode $m): $1";;
  esac
  case "$m" in
    ??[0-7]) : ;;
  esac
  [ -w "$1" ] && add CRITICAL "$2 is writable by the current unprivileged user: $1"
}

summary() {
  echo
  echo "########################################################################"
  echo "#                    DATABASE SERVER — FINDINGS SUMMARY                 #"
  echo "########################################################################"
  echo "Run as: $CUR_USER (level: $PRIV)"
  if [ -z "$FINDINGS" ]; then
    echo "  No automated findings."
  else
    printf '%s' "$FINDINGS" | sort -u | sort -t'|' -k1,1n -s | \
      while IFS='|' read -r k sev msg; do
        [ -n "$sev" ] || continue
        printf '  [%-8s] %s\n' "$sev" "$msg"
      done
    echo
    echo "  Unique issues flagged: $(printf '%s' "$FINDINGS" | sort -u | grep -c .)"
  fi
  echo
  echo "If run unprivileged, re-run (or diff) against an admin/DBA-level pass"
  echo "before treating any INFO 'not readable as current user' line as clean."
}

# ============================================================================
sec "HOST & ENGINE DETECTION"
hostname 2>/dev/null; hostname -f 2>/dev/null; id
cat /etc/redhat-release 2>/dev/null; uname -r

sec "PRIVILEGE LEVEL (read this first)"
CUR_USER=$(id -un); CUR_UID=$(id -u)
if [ "$CUR_UID" -eq 0 ]; then
  PRIV="root"
elif sudo -n true 2>/dev/null; then
  PRIV="passwordless-sudo"
elif id -Gn 2>/dev/null | grep -qwE 'postgres|oinstall|dba|mysql|mssql'; then
  PRIV="DB-privileged group member ($(id -Gn 2>/dev/null | grep -owE 'postgres|oinstall|dba|mysql|mssql' | sort -u | tr '\n' ',' | sed 's/,$//'))"
else
  PRIV="unprivileged"
fi
echo "running as: $CUR_USER (uid=$CUR_UID) — privilege level: $PRIV"
echo "(an INFO 'not readable' line below means a check was SKIPPED, not that the"
echo " underlying config is safe — confirm against an admin/DBA-level pass too.)"

PG=0; ORA=0; MSSQL=0; MYSQL=0
has psql     && PG=1
has pg_ctl   && PG=1
has sqlplus  && ORA=1
has tnsping  && ORA=1
has mysql    && MYSQL=1
has sqlcmd   && MSSQL=1
[ -d /opt/mssql ] || [ -d /var/opt/mssql ] && MSSQL=1
[ -n "${ORACLE_HOME:-}" ] && ORA=1
[ -r /etc/oratab ] && ORA=1

PG_CONFS=$(find / -xdev -maxdepth 9 -name 'pg_hba.conf' 2>/dev/null)
PG_MAIN=$(find / -xdev -maxdepth 9 -name 'postgresql.conf' 2>/dev/null)
[ -n "$PG_CONFS$PG_MAIN" ] && PG=1
ORA_LSNR=$(find / -xdev -maxdepth 9 -name 'listener.ora' 2>/dev/null)
ORA_SQLNET=$(find / -xdev -maxdepth 9 -name 'sqlnet.ora' 2>/dev/null)
[ -n "$ORA_LSNR$ORA_SQLNET" ] && ORA=1
MY_CNF=$(ls /etc/my.cnf /etc/mysql/my.cnf /etc/my.cnf.d/*.cnf 2>/dev/null)
[ -n "$MY_CNF" ] && MYSQL=1

echo "[engines detected] postgres=$PG oracle=$ORA sqlserver=$MSSQL mysql=$MYSQL"
echo "[db processes]"
ps auxww 2>/dev/null | grep -iE '[p]ostgres|[o]racle|[t]nslsnr|[s]qlservr|[m]ysqld|[m]ariadb' | head -20
echo "[db packages]"
rpm -qa 2>/dev/null | grep -iE 'postgres|oracle|mssql|mysql|mariadb|timescale'
echo "[db units]"
systemctl list-units --all --no-pager 2>/dev/null | grep -iE 'postgres|oracle|mssql|mysql|mariadb'

sub "listening DB sockets & who can reach them"
ss -tulnp 2>/dev/null | grep -E ':(5432|1521|1526|1433|3306|2638|5433|1158|8080)\b'
ss -tuln 2>/dev/null | grep -E ':(5432|1521|1433|3306)\b' | grep -qE '0\.0\.0\.0:|\[::\]:' && \
  add HIGH "DB port bound to all interfaces (0.0.0.0/::) — must be restricted to the NA app server only"

sub "firewall view of the DB port"
firewall-cmd --list-all 2>/dev/null
nft list ruleset 2>/dev/null | head -40
iptables -L -n 2>/dev/null | head -40
FWS=$(firewall-cmd --state 2>/dev/null)
{ [ -z "$FWS" ] || [ "$FWS" = "not running" ]; } && \
  add HIGH "No host firewall running on the DB server — the DB port is reachable from anywhere the network allows, not just the NA app server"
firewall-cmd --list-sources 2>/dev/null | grep -q . || \
  add MEDIUM "firewalld has no source-based restriction — confirm only the NA app server IP can reach the DB port"

sub "DB OS service accounts"
for u in postgres oracle mssql mysql; do
  getent passwd "$u" 2>/dev/null | awk -F: -v U="$u" '{print U": shell="$7" home="$6}'
  SH=$(getent passwd "$u" 2>/dev/null | cut -d: -f7)
  case "$SH" in
    */nologin|*/false|"") : ;;
    *) [ -n "$SH" ] && add MEDIUM "DB service account '$u' has an interactive shell ($SH) — confirm it is required and that login is restricted (STRIDE S5)";;
  esac
done
echo "[current user's groups]"; id -Gn 2>/dev/null
id -Gn 2>/dev/null | grep -qwE 'postgres|oinstall|dba|mysql|mssql' && \
  add HIGH "Current unprivileged user is in a DB-privileged group (dba/oinstall/postgres) — direct DB-file/instance access without sudo"
id -Gn 2>/dev/null | grep -qwE 'docker|lxd' && \
  add CRITICAL "Current user is in the docker/lxd group on the DB server — root-equivalent host compromise independent of DB auth"

# ============================================================================
if [ "$PG" = "1" ]; then
sec "POSTGRESQL"
sub "version"
psql --version 2>/dev/null
PGV=$(psql --version 2>/dev/null | grep -oE '[0-9]+(\.[0-9]+)+' | head -1)
echo "[version] ${PGV:-unknown}"
if [ -n "$PGV" ]; then
  PGMAJ=${PGV%%.*}
  [ "$PGMAJ" -lt 13 ] 2>/dev/null && add HIGH "PostgreSQL major $PGMAJ is end-of-life (community support ends at 13+) — no security updates"
  ver_lt "$PGV" "15.7"  && add MEDIUM "PostgreSQL $PGV below 15.7/16.3 — check CVE-2024-10977/10978/10979 and CVE-2024-4317 (row-security/SET ROLE issues); confirm against the RHEL/OpenText errata"
  ver_lt "$PGV" "11.17" && add HIGH "PostgreSQL $PGV may predate CVE-2022-1552 (Autovacuum/REINDEX privilege escalation to superuser)"
fi

sub "data directory"
PGDATA_D=$(ps auxww 2>/dev/null | grep '[p]ostgres' | grep -oE '\-D +[^ ]+' | head -1 | awk '{print $2}')
[ -z "$PGDATA_D" ] && PGDATA_D="${PGDATA:-}"
[ -z "$PGDATA_D" ] && PGDATA_D=$(dirname "$(printf '%s\n' $PG_MAIN | head -1)" 2>/dev/null)
echo "[PGDATA] ${PGDATA_D:-unknown}"
if [ -n "$PGDATA_D" ] && [ -d "$PGDATA_D" ]; then
  ls -ld "$PGDATA_D"
  DM=$(mode_of "$PGDATA_D")
  echo "[mode] $DM"
  case "$DM" in 700|750) : ;; *) add HIGH "PGDATA mode $DM is wider than 0700/0750: $PGDATA_D — data files readable off-instance";; esac
  [ -r "$PGDATA_D" ] && add HIGH "PGDATA readable by the current unprivileged user — raw table files (incl. NA device-credential tables) can be read without any DB auth"
fi

sub "pg_hba.conf (client authentication — STRIDE S7)"
for c in $PG_CONFS; do
  echo "===== $c ====="; chk_mode "$c" "pg_hba.conf"
  [ -r "$c" ] || { add INFO "pg_hba.conf not readable as current user (need root/postgres): $c"; continue; }
  grep -vE '^\s*(#|$)' "$c"
  grep -E '^\s*(host|hostssl|hostnossl|local)' "$c" | grep -qiE '[[:space:]]trust[[:space:]]*$' && \
    add CRITICAL "pg_hba.conf allows 'trust' (no password at all): $c"
  grep -E '^\s*host' "$c" | grep -qE '0\.0\.0\.0/0|::/0' && \
    add HIGH "pg_hba.conf accepts connections from any address (0.0.0.0/0 or ::/0): $c"
  grep -E '^\s*host' "$c" | grep -qiE '[[:space:]]md5[[:space:]]*$' && \
    add MEDIUM "pg_hba.conf uses md5 auth — replayable, use scram-sha-256: $c"
  grep -E '^\s*hostnossl' "$c" | grep -qv '^\s*#' && \
    add MEDIUM "pg_hba.conf has hostnossl rules — plaintext connections explicitly permitted: $c"
  grep -E '^\s*host[[:space:]]' "$c" | grep -q . && ! grep -qE '^\s*hostssl' "$c" && \
    add MEDIUM "pg_hba.conf has no 'hostssl' rules — TLS is not required for remote app connections: $c"
  grep -E '^\s*local' "$c" | grep -qiE '[[:space:]]peer[[:space:]]*$' && \
    echo "  (local peer auth present — any local OS user maps to the same-named DB role)"
  grep -qiE '^\s*(host|local).*[[:space:]](all)[[:space:]]+(all)[[:space:]]' "$c" && \
    add MEDIUM "pg_hba.conf has an 'all all' rule — NA should connect as a single least-privileged role, not via a blanket rule: $c"
done

sub "pg_ident.conf (username mapping)"
for i in $(find / -xdev -maxdepth 9 -name 'pg_ident.conf' 2>/dev/null); do
  echo "== $i =="; chk_mode "$i" "pg_ident.conf"
  [ -r "$i" ] && grep -vE '^\s*(#|$)' "$i" | head -20
done

sub "postgresql.conf (TLS, logging, auth, limits)"
for m in $PG_MAIN; do
  echo "===== $m ====="; chk_mode "$m" "postgresql.conf"
  [ -r "$m" ] || { add INFO "postgresql.conf not readable: $m"; continue; }
  grep -E "^\s*(listen_addresses|port|ssl|ssl_cert_file|ssl_key_file|ssl_ca_file|ssl_min_protocol_version|ssl_ciphers|password_encryption|logging_collector|log_destination|log_directory|log_filename|log_file_mode|log_connections|log_disconnections|log_statement|log_line_prefix|log_hostname|log_min_duration_statement|shared_preload_libraries|unix_socket_permissions|unix_socket_directories|data_directory|hba_file|ident_file|archive_mode|archive_command|row_security|idle_in_transaction_session_timeout|statement_timeout|authentication_timeout|max_connections|superuser_reserved_connections|log_checkpoints|log_lock_waits|log_error_verbosity|log_rotation_age|log_truncate_on_rotation|cluster_name|update_process_title)\s*=" "$m"

  v() { grep -E "^\s*$1\s*=" "$m" 2>/dev/null | tail -1 | sed -E "s/^[^=]*=\s*//; s/\s*#.*//; s/^'//; s/'$//" ; }
  LA=$(v listen_addresses);        echo "  listen_addresses=${LA:-<default localhost>}"
  SSLV=$(v ssl);                   echo "  ssl=${SSLV:-off}"
  PE=$(v password_encryption);     echo "  password_encryption=${PE:-md5}"
  LC=$(v log_connections);         LD=$(v log_disconnections); LS=$(v log_statement)
  SPL=$(v shared_preload_libraries); USP=$(v unix_socket_permissions)
  LFM=$(v log_file_mode);          LLP=$(v log_line_prefix)
  SMPV=$(v ssl_min_protocol_version); LOGCOL=$(v logging_collector)

  case "$LA" in *'*'*|*'0.0.0.0'*) add HIGH "postgresql.conf listen_addresses='$LA' — listening on all interfaces; restrict to the NA app server address: $m";; esac
  case "$SSLV" in on|true|1) : ;; *) add HIGH "postgresql.conf ssl is off — NA app-to-DB traffic (incl. the DB password and every device credential row) crosses the network in cleartext: $m";; esac
  case "$PE" in scram-sha-256) : ;; *) add MEDIUM "password_encryption='${PE:-md5}' — stored password verifiers are md5; switch to scram-sha-256: $m";; esac
  case "$LC" in on|true|1) : ;; *) add MEDIUM "log_connections off — no record of who connected to the NA database (STRIDE R1/R5): $m";; esac
  case "$LD" in on|true|1) : ;; *) add LOW "log_disconnections off — session duration not recorded: $m";; esac
  case "$LS" in ddl|mod|all) : ;; *) add MEDIUM "log_statement='${LS:-none}' — DDL/DML against the NA schema is not logged, so direct DB tampering leaves no trail (STRIDE T4/R1): $m";; esac
  echo "$SPL" | grep -qi 'pgaudit' || add MEDIUM "pgaudit not in shared_preload_libraries — no object-level DB audit trail: $m"
  case "$USP" in ""|0777|0775|0770) [ -n "$USP" ] && add MEDIUM "unix_socket_permissions=$USP — local socket reachable by any local user: $m";; esac
  case "$LFM" in ""|0644|0640) : ;; *) : ;; esac
  [ "$LFM" = "0644" ] && add LOW "log_file_mode=0644 — DB logs world-readable: $m"
  echo "$LLP" | grep -q '%u' || add LOW "log_line_prefix lacks %u/%h — log lines without user/host are weak audit evidence: $m"
  case "$SMPV" in TLSv1.2|TLSv1.3) : ;; *) [ "$SSLV" = "on" ] && add MEDIUM "ssl_min_protocol_version='${SMPV:-TLSv1}' — allow only TLSv1.2+: $m";; esac
  case "$LOGCOL" in on|true|1) : ;; *) add LOW "logging_collector off — logs go to stderr only; confirm they are captured and shipped: $m";; esac
done

sub "TLS key/cert file permissions"
for f in $(find / -xdev -maxdepth 9 \( -name 'server.key' -o -name 'server.crt' -o -name 'root.crt' \) -path '*pg*' 2>/dev/null; \
           find "${PGDATA_D:-/nonexistent}" -maxdepth 1 \( -name 'server.key' -o -name 'server.crt' \) 2>/dev/null); do
  [ -f "$f" ] && { echo "== $f =="; chk_mode "$f" "PostgreSQL TLS file"; }
done

sub "passwordless login material for postgres"
for f in /var/lib/pgsql/.pgpass /home/postgres/.pgpass "${PGDATA_D%/*}/.pgpass" /root/.pgpass; do
  [ -f "$f" ] && { echo "== $f =="; chk_mode "$f" ".pgpass"; [ -r "$f" ] && add CRITICAL "Readable .pgpass — passwordless DB login as whatever role it names: $f"; }
done
echo "[PGPASSWORD in environment / units / cron]"
env 2>/dev/null | grep -iE 'PGPASSWORD|PGUSER|PGHOST|PGSSLMODE'
grep -rIlE 'PGPASSWORD' /etc/systemd /usr/lib/systemd/system /etc/cron* /var/spool/cron 2>/dev/null | head -10 | \
  while read -r f; do [ -n "$f" ] && add HIGH "PGPASSWORD set in a unit/cron file (visible via systemctl show / ps): $f"; done
echo "[psql history]"
for f in /var/lib/pgsql/.psql_history /home/*/.psql_history /root/.psql_history; do
  [ -r "$f" ] && { ls -l "$f"; add MEDIUM "Readable .psql_history — past queries and inline credentials: $f"; }
done

if [ "$PROBE" != "1" ] && has psql; then
sub "passive local-auth probe (single no-password attempt — proves trust/peer exposure)"
  for u in "$(id -un)" postgres na nauser; do
    [ -n "$u" ] || continue
    if psql -w -U "$u" -d postgres -tAc 'select 1' >/dev/null 2>&1; then
      echo "  CONNECTED as DB role '$u' with NO password"
      add CRITICAL "Local passwordless DB access succeeded as role '$u' — any shell user on this host owns the NA database (and its device-credential tables)"
      PGU="$u"; break
    else
      echo "  no passwordless access as '$u' (expected / pass)"
    fi
  done

  if [ -n "${PGU:-}" ]; then
    sub "read-only review via role '$PGU' (SELECT only, no data dumped)"
    q() { psql -w -U "$PGU" -d postgres -tA -F' | ' -c "$1" 2>/dev/null; }
    echo "[server version]"; q "show server_version"
    echo "[superuser roles]"; q "select rolname from pg_roles where rolsuper order by 1"
    echo "[roles that can create roles/DBs]"; q "select rolname,rolcreaterole,rolcreatedb,rolbypassrls from pg_roles where rolcreaterole or rolcreatedb or rolbypassrls order by 1"
    echo "[roles with no password set]"; q "select rolname from pg_authid where rolpassword is null and rolcanlogin order by 1" \
      && q "select rolname from pg_authid where rolpassword is null and rolcanlogin" | grep -q . && \
         add HIGH "DB login roles exist with no password set"
    echo "[roles with md5 verifiers]"; q "select rolname from pg_authid where rolpassword like 'md5%'" | tee /dev/stderr | grep -q . && \
      add MEDIUM "DB roles still use md5 password verifiers (replayable) — rehash under scram-sha-256"
    echo "[roles with no password expiry]"; q "select rolname from pg_roles where rolvaliduntil is null and rolcanlogin order by 1" | head -20
    echo "[databases + owners + encoding]"; q "select datname,pg_get_userbyid(datdba),pg_encoding_to_char(encoding) from pg_database order by 1"
    echo "[PUBLIC grants on databases]"; q "select datname,datacl from pg_database where array_to_string(datacl,',') like '%=%' "
    q "select 1 from pg_database where datname not in ('template0') and (datacl is null)" | grep -q 1 && \
      add MEDIUM "Database has default ACL — PUBLIC retains CONNECT/CREATE on public schema; revoke it"
    echo "[installed extensions]"; q "select extname from pg_extension order by 1"
    EXT=$(q "select extname from pg_extension")
    echo "$EXT" | grep -qiE 'plpython|plperlu|pltclu' && add HIGH "Untrusted procedural-language extension installed (plpythonu/plperlu/pltclu) — a DB superuser gets OS command execution"
    echo "$EXT" | grep -qi 'dblink'     && add MEDIUM "dblink extension installed — outbound DB connections / SSRF-style pivot from the DB"
    echo "$EXT" | grep -qi 'file_fdw'   && add MEDIUM "file_fdw installed — server-side file reads via SQL"
    echo "$EXT" | grep -qi 'pgaudit'    || echo "  (pgaudit not installed)"
    echo "[NA schema: credential-bearing tables — NAMES ONLY, no values read]"
    q "select table_schema||'.'||table_name from information_schema.tables where table_name ~* 'password|cred|secret|key|auth|user|device' order by 1" | head -40
    echo "[columns that look like secrets — NAMES ONLY]"
    q "select table_name||'.'||column_name from information_schema.columns where column_name ~* 'password|passwd|secret|token|private' order by 1" | head -40
    echo "[SECURITY DEFINER functions (privesc inside the DB)]"
    q "select n.nspname||'.'||p.proname from pg_proc p join pg_namespace n on n.oid=p.pronamespace where p.prosecdef and n.nspname not in ('pg_catalog','information_schema') order by 1" | head -20
    echo "[row-level security enabled anywhere?]"
    q "select count(*) from pg_class where relrowsecurity"
    echo "[NA app role privileges]"
    q "select rolname,rolsuper,rolcreatedb,rolcreaterole,rolreplication from pg_roles where rolname !~ '^pg_' order by 1"
    q "select 1 from pg_roles where rolsuper and rolname <> 'postgres'" | grep -q 1 && \
      add HIGH "A non-'postgres' role has SUPERUSER — if the NA app connects as it, SQLi becomes OS-level compromise of the DB server"
  else
    add INFO "Passive local-auth probe found no passwordless role — if run unprivileged, re-run with a DB credential (NA app account) to continue the role/extension/schema review"
  fi
fi

sub "pg log directory"
PGLOG="${PGDATA_D:-}/log"
for d in "$PGLOG" /var/lib/pgsql/data/log /var/log/postgresql /var/log/pgsql; do
  [ -d "$d" ] || continue
  echo "== $d =="; ls -ld "$d"; ls -l "$d" 2>/dev/null | head -10
  WRD=$(find "$d" -maxdepth 1 -writable -type f 2>/dev/null | head -3)
  [ -n "$WRD" ] && add HIGH "PostgreSQL log files writable by current user in $d (audit tampering — STRIDE R2)"
  RDB=$(find "$d" -maxdepth 1 -perm -0004 -type f 2>/dev/null | head -3)
  [ -n "$RDB" ] && add MEDIUM "PostgreSQL logs world-readable in $d (queries may embed credentials)"
done
fi

# ============================================================================
if [ "$ORA" = "1" ]; then
sec "ORACLE DATABASE"
echo "[ORACLE_HOME] ${ORACLE_HOME:-not-set}"; echo "[ORACLE_SID] ${ORACLE_SID:-not-set}"
cat /etc/oratab 2>/dev/null | grep -vE '^\s*(#|$)'
[ -n "${ORACLE_HOME:-}" ] && { ls -ld "$ORACLE_HOME"; chk_mode "$ORACLE_HOME" "ORACLE_HOME"; }
has sqlplus && sqlplus -V 2>/dev/null | head -3
has tnslsnr && tnslsnr version 2>/dev/null | head -3
ORAV=$( (sqlplus -V 2>/dev/null; tnslsnr version 2>/dev/null) | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)*' | head -1)
echo "[oracle version] ${ORAV:-unknown}"
[ -n "$ORAV" ] && ver_lt "$ORAV" "19.0" && \
  add HIGH "Oracle $ORAV predates 19c — outside Premier Support, no current security patches"

sub "listener.ora"
for l in $ORA_LSNR; do
  echo "===== $l ====="; chk_mode "$l" "listener.ora"
  [ -r "$l" ] || { add INFO "listener.ora not readable: $l"; continue; }
  grep -vE '^\s*(#|$)' "$l" | sed -E 's/(PASSWORD[^=]*=)[^)]*/\1***MASKED***/Ig'
  grep -qiE 'ADMIN_RESTRICTIONS[^=]*=[[:space:]]*ON' "$l" || \
    add HIGH "ADMIN_RESTRICTIONS_<listener>=ON not set — remote 'set' commands against the listener are permitted: $l"
  grep -qiE 'PROGRAM[[:space:]]*=[[:space:]]*extproc|SID_NAME[[:space:]]*=[[:space:]]*PLSExtProc' "$l" && \
    add HIGH "extproc/PLSExtProc entry in listener.ora — the classic external-procedure OS-command-execution path: $l"
  grep -qiE 'SECURE_REGISTER|SECURE_CONTROL|SECURE_PROTOCOL' "$l" || \
    add MEDIUM "No SECURE_REGISTER/SECURE_CONTROL in listener.ora — remote service registration/control not restricted: $l"
  grep -qiE 'PASSWORDS_' "$l" && \
    add MEDIUM "Listener password hash stored in listener.ora (deprecated; use OS authentication): $l"
  grep -qiE '\(PROTOCOL[[:space:]]*=[[:space:]]*TCPS\)' "$l" || \
    add MEDIUM "Listener has no TCPS endpoint — no TLS option for the NA app-to-DB link: $l"
  grep -oiE 'HOST[[:space:]]*=[[:space:]]*[^)]+' "$l" | sort -u
done

sub "sqlnet.ora (encryption & node checking)"
for s in $ORA_SQLNET; do
  echo "===== $s ====="; chk_mode "$s" "sqlnet.ora"
  [ -r "$s" ] || continue
  grep -vE '^\s*(#|$)' "$s"
  grep -qiE 'SQLNET\.ENCRYPTION_SERVER[[:space:]]*=[[:space:]]*(REQUIRED|REQUESTED)' "$s" || \
    add HIGH "SQLNET.ENCRYPTION_SERVER not REQUIRED — Oracle Native Network Encryption off, so NA app-to-DB traffic is cleartext: $s"
  grep -qiE 'SQLNET\.CRYPTO_CHECKSUM_SERVER[[:space:]]*=[[:space:]]*(REQUIRED|REQUESTED)' "$s" || \
    add MEDIUM "SQLNET.CRYPTO_CHECKSUM_SERVER not set — no integrity protection on the DB link (STRIDE T3): $s"
  grep -qiE 'TCP\.VALIDNODE_CHECKING[[:space:]]*=[[:space:]]*(YES|ON)' "$s" || \
    add MEDIUM "TCP.VALIDNODE_CHECKING not enabled — any host that can route to 1521 may attempt connections: $s"
  grep -qiE 'SQLNET\.AUTHENTICATION_SERVICES[[:space:]]*=[[:space:]]*\(?NONE' "$s" && \
    echo "  (AUTHENTICATION_SERVICES=NONE — password auth only; OS auth disabled)"
  grep -qiE 'SSL_VERSION[[:space:]]*=[[:space:]]*(1\.0|3\.0|undetermined)' "$s" && \
    add HIGH "sqlnet.ora SSL_VERSION permits SSLv3/TLSv1.0: $s"
  grep -qiE 'SQLNET\.ALLOWED_LOGON_VERSION_SERVER[[:space:]]*=[[:space:]]*(8|9|10)' "$s" && \
    add HIGH "SQLNET.ALLOWED_LOGON_VERSION_SERVER <= 10 — weak (DES/10g) password verifiers accepted: $s"
done

sub "tnsnames.ora / credential leakage"
for t in $(find / -xdev -maxdepth 9 -name 'tnsnames.ora' 2>/dev/null); do
  echo "== $t =="; chk_mode "$t" "tnsnames.ora"
  [ -r "$t" ] && grep -oiE 'HOST[[:space:]]*=[[:space:]]*[^)]+|SERVICE_NAME[[:space:]]*=[[:space:]]*[^)]+' "$t" | sort -u | head -20
done

sub "password file (orapw) & OS authentication"
for p in $(find / -xdev -maxdepth 9 -name 'orapw*' 2>/dev/null); do
  echo "== $p =="; chk_mode "$p" "Oracle password file"
  [ -r "$p" ] && add CRITICAL "Oracle password file (orapw) readable by the current unprivileged user: $p — offline attack on SYS/SYSDBA verifiers"
done

sub "init/spfile parameters"
for ip in $(find / -xdev -maxdepth 9 \( -name 'init*.ora' -o -name 'spfile*.ora' \) 2>/dev/null | head -10); do
  echo "===== $ip ====="; chk_mode "$ip" "Oracle init/spfile"
  [ -r "$ip" ] || continue
  strings "$ip" 2>/dev/null | grep -iE '^\*?\.?(remote_os_authent|remote_os_roles|O7_DICTIONARY_ACCESSIBILITY|audit_trail|audit_sys_operations|sec_case_sensitive_logon|remote_login_passwordfile|sql92_security|resource_limit|sec_max_failed_login_attempts|global_names|utl_file_dir|os_authent_prefix|_trace_files_public)' | head -30
  S=$(strings "$ip" 2>/dev/null)
  echo "$S" | grep -qiE 'remote_os_authent[[:space:]]*=[[:space:]]*true'       && add CRITICAL "remote_os_authent=TRUE — remote OS authentication allows trivial spoofed logins: $ip"
  echo "$S" | grep -qiE 'O7_DICTIONARY_ACCESSIBILITY[[:space:]]*=[[:space:]]*true' && add HIGH "O7_DICTIONARY_ACCESSIBILITY=TRUE — ANY-privilege users can read the data dictionary: $ip"
  echo "$S" | grep -qiE 'audit_trail[[:space:]]*=[[:space:]]*(none|false)'     && add HIGH "audit_trail=NONE — no Oracle audit trail, so direct DB record tampering is unrecorded (STRIDE T4/R1): $ip"
  echo "$S" | grep -qiE 'audit_sys_operations[[:space:]]*=[[:space:]]*false'   && add MEDIUM "audit_sys_operations=FALSE — SYSDBA actions not audited: $ip"
  echo "$S" | grep -qiE 'sec_case_sensitive_logon[[:space:]]*=[[:space:]]*false'&& add HIGH "sec_case_sensitive_logon=FALSE — forces weak 10g password verifiers: $ip"
  echo "$S" | grep -qiE 'remote_login_passwordfile[[:space:]]*=[[:space:]]*(shared|none)' && add MEDIUM "remote_login_passwordfile not EXCLUSIVE: $ip"
  echo "$S" | grep -qiE 'utl_file_dir'    && add HIGH "utl_file_dir set — PL/SQL arbitrary file access: $ip"
  echo "$S" | grep -qiE '_trace_files_public[[:space:]]*=[[:space:]]*true' && add MEDIUM "_trace_files_public=TRUE — trace files world-readable: $ip"
  echo "$S" | grep -qiE 'sec_max_failed_login_attempts' || add LOW "sec_max_failed_login_attempts not set — no server-side connection-attempt limit: $ip"
done

sub "TDE wallet (data-at-rest encryption — STRIDE I3)"
WAL=$(find / -xdev -maxdepth 10 \( -name 'ewallet.p12' -o -name 'cwallet.sso' \) 2>/dev/null)
echo "${WAL:-no wallet files found}"
[ -z "$WAL" ] && add MEDIUM "No Oracle wallet found — confirm whether TDE protects the NA device-credential tablespace at rest"
echo "$WAL" | grep -q 'cwallet.sso' && \
  add MEDIUM "Auto-login wallet (cwallet.sso) present — anyone who can read the wallet directory can open the TDE keys, weakening at-rest encryption"
for w in $WAL; do [ -n "$w" ] && chk_mode "$w" "Oracle wallet"; done

sub "audit & trace directories"
for d in $(find / -xdev -maxdepth 9 -type d \( -name 'adump' -o -name 'trace' -o -name 'audit' \) -path '*oracle*' 2>/dev/null | head -10); do
  echo "== $d =="; ls -ld "$d"
  RD=$(find "$d" -maxdepth 1 -perm -0004 -type f 2>/dev/null | head -3)
  [ -n "$RD" ] && add MEDIUM "World-readable Oracle audit/trace files in $d"
  WD=$(find "$d" -maxdepth 1 -writable -type f 2>/dev/null | head -3)
  [ -n "$WD" ] && add HIGH "Oracle audit/trace files writable by current user in $d (STRIDE R2)"
done
echo "[listener log]"
find / -xdev -maxdepth 10 -name 'listener*.log' 2>/dev/null | head -5 | while read -r f; do [ -n "$f" ] && ls -l "$f"; done

sub "glogin.sql / login.sql hijack (runs for every sqlplus session)"
for f in $(find / -xdev -maxdepth 9 \( -name 'glogin.sql' -o -name 'login.sql' \) 2>/dev/null); do
  echo "== $f =="; ls -l "$f"
  [ -w "$f" ] && add CRITICAL "glogin/login.sql writable by current user: $f — your SQL runs inside every DBA's sqlplus session (privesc to SYSDBA)"
done

sub "patch inventory (slow — opatch)"
if [ -n "${ORACLE_HOME:-}" ] && [ -x "$ORACLE_HOME/OPatch/opatch" ]; then
  "$ORACLE_HOME/OPatch/opatch" lsinventory 2>/dev/null | grep -iE 'Patch *[0-9]+|applied on|Oracle Database|not found' | head -30
else
  echo "(opatch not available to this user)"
  add INFO "Could not read Oracle patch inventory as an unprivileged user — request the DBA's 'opatch lsinventory' output to confirm the quarterly RU level"
fi

if [ "$PROBE" != "1" ] && has sqlplus; then
sub "passive OS-auth probe (single attempt: does '/ as sysdba' work for this user?)"
  if echo 'select 1 from dual;' | sqlplus -S -L '/ as sysdba' >/dev/null 2>&1; then
    add CRITICAL "Current OS user can connect '/ as sysdba' without a password — full DB compromise from a shell account"
    echo "  CONNECTED as SYSDBA via OS authentication"
  else
    echo "  no SYSDBA OS authentication for this user (expected / pass)"
  fi
fi
fi

# ============================================================================
if [ "$MSSQL" = "1" ]; then
sec "MICROSOFT SQL SERVER (on Linux)"
ls -ld /opt/mssql /var/opt/mssql /var/opt/mssql/data 2>/dev/null
/opt/mssql/bin/sqlservr --version 2>/dev/null | head -5
for f in /var/opt/mssql/mssql.conf; do
  [ -r "$f" ] || continue
  echo "== $f =="; chk_mode "$f" "mssql.conf"; grep -vE '^\s*(#|$)' "$f"
  grep -qiE '^\s*forceencryption\s*=\s*1' "$f" || \
    add HIGH "mssql.conf forceencryption not 1 — NA app-to-SQL-Server traffic may be unencrypted: $f"
  grep -oiE '^\s*tlsprotocols\s*=.*' "$f"
  grep -qiE 'tlsprotocols\s*=.*(1\.0|1\.1)' "$f" && add HIGH "mssql.conf permits TLS 1.0/1.1: $f"
  grep -qiE '^\s*auditlevel\s*=\s*(3|all|failure.*success)' "$f" || \
    add MEDIUM "mssql.conf auditlevel does not log both successful and failed logins (STRIDE R1): $f"
done
DM=$(mode_of /var/opt/mssql/data); echo "[data dir mode] ${DM:-n/a}"
case "$DM" in *[4567]) add HIGH "SQL Server data directory world-readable (mode $DM) — raw MDF files readable";; esac
ls -l /var/opt/mssql/log/errorlog 2>/dev/null
find /var/opt/mssql -maxdepth 3 -name '*.bak' 2>/dev/null | head -10
fi

# ============================================================================
if [ "$MYSQL" = "1" ]; then
sec "MYSQL / MARIADB"
mysql --version 2>/dev/null; mysqld --version 2>/dev/null
for f in $MY_CNF; do
  [ -r "$f" ] || continue
  echo "===== $f ====="; chk_mode "$f" "my.cnf"; grep -vE '^\s*(#|$)' "$f" | sed -E 's/(password[[:space:]]*=).*/\1***MASKED***/I'
  grep -qiE '^\s*local[-_]infile\s*=\s*(0|off)' "$f" || add MEDIUM "local_infile not disabled — client-side file read via LOAD DATA LOCAL: $f"
  grep -qiE '^\s*secure[-_]file[-_]priv\s*=' "$f" || add MEDIUM "secure_file_priv not set — SELECT ... INTO OUTFILE can write anywhere the mysqld user can: $f"
  grep -qiE '^\s*(require_secure_transport|ssl)\s*=\s*(1|on|true)' "$f" || add HIGH "TLS not required — NA app-to-MySQL traffic unencrypted: $f"
  grep -qiE '^\s*skip[-_]name[-_]resolve' "$f" || add LOW "skip_name_resolve not set — host-based grants rely on reverse DNS: $f"
  grep -qiE '^\s*(log_bin|general_log|log_error)' "$f" || add MEDIUM "No binlog/general_log/log_error configured — weak DB audit trail (STRIDE R1): $f"
  grep -qiE 'password[[:space:]]*=' "$f" && add HIGH "Cleartext password in $f"
done
for f in /root/.my.cnf /home/*/.my.cnf /var/lib/mysql/.mysql_history /home/*/.mysql_history; do
  [ -r "$f" ] && { ls -l "$f"; add HIGH "Readable MySQL credential/history file: $f"; }
done
DM=$(mode_of /var/lib/mysql); echo "[datadir mode] ${DM:-n/a}"
case "$DM" in *[4567]) add HIGH "MySQL datadir world-readable (mode $DM)";; esac
fi

# ============================================================================
sec "BACKUPS, DUMPS & EXPORTS (at-rest exposure — STRIDE I3)"
DUMPS=$(find / -xdev -maxdepth 8 \( -name '*.dmp' -o -name '*.dump' -o -name '*.sql' -o -name '*.sql.gz' \
  -o -name '*.bak' -o -name '*.rman' -o -name '*backup*.tar*' -o -name '*.tgz' -o -name '*.zip' \) \
  -size +100k -type f 2>/dev/null | head -60)
echo "$DUMPS"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  M=$(mode_of "$f")
  printf '  mode=%s  %s\n' "$M" "$(ls -l "$f" 2>/dev/null)"
  case "$M" in *[4567]) add CRITICAL "World-readable database backup/dump: $f — a full copy of the NA database (device credentials, configs) readable by any local user";; esac
  [ -r "$f" ] && add HIGH "Database backup/dump readable by the current unprivileged user: $f"
  case "$f" in
    *.gpg|*.enc|*.aes|*.age) : ;;
    *) add MEDIUM "Backup appears unencrypted at rest: $f";;
  esac
done <<< "$DUMPS"

sub "backup directories & retention"
for d in /backup /backups /var/backups /opt/backup /var/lib/pgsql/backups /u01/backup /mnt/backup; do
  [ -d "$d" ] && { ls -ld "$d"; ls -l "$d" 2>/dev/null | head -10; }
done
sub "backup jobs in cron / systemd timers"
grep -rIlE 'pg_dump|pg_basebackup|expdp|exp |rman|mysqldump|BACKUP DATABASE' /etc/cron* /var/spool/cron /etc/systemd 2>/dev/null | head -10 | \
  while read -r f; do [ -n "$f" ] && { echo "== $f =="; grep -hE 'pg_dump|pg_basebackup|expdp|rman|mysqldump|BACKUP' "$f" 2>/dev/null | sed -E 's/(password|PGPASSWORD)=[^ ]*/\1=***MASKED***/Ig' | head -5; }; done
grep -rIhE 'pg_dump|mysqldump|expdp' /etc/cron* /var/spool/cron 2>/dev/null | grep -qiE 'password|PGPASSWORD' && \
  add HIGH "Backup job passes a DB password on the command line — visible to every local user via ps"
[ -z "$(grep -rIlE 'pg_dump|pg_basebackup|expdp|rman|mysqldump' /etc/cron* /var/spool/cron /etc/systemd 2>/dev/null)" ] && \
  add MEDIUM "No scheduled DB backup job found on this host — confirm backups exist elsewhere (recoverability of the NA credential store)"

sub "remote shares that could expose data/backups"
mount 2>/dev/null | grep -E 'nfs|cifs|smb'
[ -r /etc/exports ] && { echo "[/etc/exports]"; grep -vE '^\s*(#|$)' /etc/exports; \
  grep -q 'no_root_squash' /etc/exports && add CRITICAL "/etc/exports uses no_root_squash — an NFS client gets root over the exported DB/backup data"; }

# ============================================================================
sec "DB-SIDE AUDIT & NON-REPUDIATION SUPPORT (R1/R3/R4)"
echo "[auditd]";  systemctl is-active auditd 2>/dev/null
echo "[rsyslog]"; systemctl is-active rsyslog 2>/dev/null
echo "[remote syslog targets]"
grep -rhE '^\s*\*\.\*\s+@|^\s*[a-z.*]+\s+@@?[A-Za-z0-9._-]+' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | head -10
grep -rqE '@@?[A-Za-z0-9._-]+' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null || \
  add HIGH "No remote syslog forwarding configured on the DB server — local log deletion erases the only audit trail (STRIDE R2/R4)"
echo "[time sync — required for correlating DB and app audit records]"
systemctl is-active chronyd 2>/dev/null; systemctl is-active ntpd 2>/dev/null; timedatectl 2>/dev/null | head -8
timedatectl 2>/dev/null | grep -qiE 'NTP service: active|synchronized: yes' || \
  add MEDIUM "Time synchronisation not confirmed active — unsynchronised clocks undermine audit-trail correlation between the app and DB servers (STRIDE R1)"

summary
echo
echo "Also run na_hardening_audit.sh on this host, and na_webapp_surface.sh on the web server."
echo "Read-only: no DDL/DML executed, nothing modified, no network egress."
