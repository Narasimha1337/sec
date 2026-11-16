#!/bin/bash
# ============================================================================
#  OpenText Network Automation CE 25.2 — WEB/APP SERVER deep-dive (read-only)
#
#  Run on the WEB/APP server (the one with Tomcat + the NA webapp).
#  Complements na_enum.sh (host basics) and na_hardening_audit.sh (CIS).
#
#  Covers the areas na_enum.sh does NOT:
#    - Tomcat hardening (shutdown port, manager app, TRACE, listings,
#      ErrorReportValve, AccessLogValve, autoDeploy, SecurityManager)
#    - JVM flags: JMX-remote-without-auth, serialFilter, trustURLCodebase,
#      HeapDumpOnOutOfMemoryError, secrets in CATALINA_OPTS
#    - TLS/keystore inspection: default store passwords, cert expiry,
#      key size, sig alg, private-key file permissions
#    - Web attack-surface extraction: every <url-pattern>, servlet class,
#      JSP, unauthenticated path, session/cookie config  -> Burp target list
#    - Legacy NA servlets named in the historical CVEs (RPCServlet,
#      FileServlet, RedirectServlet, PermissionFilter)
#    - Java-library inventory incl. deserialization gadget jars
#      (commons-collections 3.x, commons-beanutils, jackson, xstream, groovy,
#      snakeyaml, spring-beans, struts, log4j 1.x)
#    - NA .rcx options, device-facing services (TFTP/syslog/SSH-Telnet proxy)
#    - NA hotfix / patch inventory, heap & core dumps containing secrets
#
#  Design : NO writes, NO outbound network, NO persistence. Built-ins only.
#  Usage  : bash na_webapp_surface.sh              # normal
#           FAST=1 bash na_webapp_surface.sh       # skip slow filesystem walks
#           NO_KEYSTORE_PROBE=1 bash na_webapp_surface.sh   # skip keytool
#  Output : stdout only. Capture it on YOUR box:
#           ssh user@web 'bash -s' < na_webapp_surface.sh | tee web_surface.txt
#
#  CHANGELOG vs original:
#   - Added a privilege-level banner up front (root / Tomcat service-account
#     member / passwordless-sudo / plain unprivileged user), folded into the
#     findings summary, so user-level and admin-level runs of this same
#     script are clearly distinguishable when compared.
# ============================================================================
usage() {
  cat <<'EOF'
Usage: bash na_webapp_surface.sh [-h|--help]
       FAST=1 bash na_webapp_surface.sh
       NO_KEYSTORE_PROBE=1 bash na_webapp_surface.sh

Read-only WEB/APP SERVER deep-dive for OpenText Network Automation CE
25.2 (the host running Tomcat + the NA webapp). Builds the web attack
surface (endpoints, servlets, legacy-CVE servlets) to feed to Burp/ZAP,
audits Tomcat/JVM hardening, TLS/keystores, and the Java library
inventory for deserialization gadgets. No writes, no outbound network.

Options:
  -h, --help          Show this help and exit

Environment:
  FAST=1              Skip the slow full-filesystem jar/JSP walks
  NO_KEYSTORE_PROBE=1 Skip the keytool documented-default-password check

Capture output on your own box:
  ssh user@web 'bash -s' < na_webapp_surface.sh | tee web_surface.txt

See also: na_enum.sh (host basics), na_db_enum.sh (run on the DB server),
na_hardening_audit.sh (CIS-lite, run on both), na_cve_reference.md.

Note: this script enumerates the server-side attack surface; it does not
itself test the running web app over HTTP (use Burp/ZAP for that).
EOF
}
case "${1:-}" in -h|--help) usage; exit 0;; esac

export LC_ALL=C
FAST="${FAST:-0}"

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
has()    { command -v "$1" >/dev/null 2>&1; }
# grep that never follows into noise and never prints binary
g() { grep -rIl --exclude-dir=.git --exclude-dir=proc "$@" 2>/dev/null; }

summary() {
  echo
  echo "########################################################################"
  echo "#                   WEB/APP SURFACE — FINDINGS SUMMARY                  #"
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
  echo "NOTE: version-based flags are 'possible' only — OpenText/RHEL backport"
  echo "fixes without bumping versions. Confirm against the vendor advisory."
  echo "If run unprivileged, re-run (or diff) against an admin/service-account"
  echo "level pass before treating any 'not readable' line as clean."
}

# ============================================================================
sec "LOCATE TOMCAT / NA / WEBAPPS"
echo "[hostname]"; hostname 2>/dev/null; id

sec "PRIVILEGE LEVEL (read this first)"
CUR_USER=$(id -un); CUR_UID=$(id -u)
if [ "$CUR_UID" -eq 0 ]; then
  PRIV="root"
elif sudo -n true 2>/dev/null; then
  PRIV="passwordless-sudo"
else
  TC_OWNER=$(ps auxww 2>/dev/null | grep -i '[c]atalina' | awk 'NR==1{print $1}')
  if [ -n "$TC_OWNER" ] && [ "$TC_OWNER" = "$CUR_USER" ]; then
    PRIV="same account as the Tomcat/NA service"
  else
    PRIV="unprivileged"
  fi
fi
echo "running as: $CUR_USER (uid=$CUR_UID) — privilege level: $PRIV"
echo "(a 'not readable as current user' line below is a SKIPPED check, not a"
echo " clean result — re-run on the admin/service-account box, or diff the two,"
echo " before concluding a section has nothing to flag.)"

CAT_HOME="${CATALINA_HOME:-}"
if [ -z "$CAT_HOME" ]; then
  CAT_HOME=$(ps auxww 2>/dev/null | grep -i '[c]atalina' \
    | grep -oE '\-Dcatalina\.home=[^ ]+' | head -1 | cut -d= -f2)
fi
if [ -z "$CAT_HOME" ]; then
  CAT_HOME=$(find / -xdev -maxdepth 7 -type d -name conf -path '*tomcat*' 2>/dev/null \
    | head -1 | sed 's#/conf$##')
fi
echo "[CATALINA_HOME]: ${CAT_HOME:-not-found}"

CAT_BASE="${CATALINA_BASE:-$CAT_HOME}"
echo "[CATALINA_BASE]: ${CAT_BASE:-not-found}"

NA_ROOT=""
for d in /opt/NA /opt/opentext/NA /opt/opentext/na /opt/microfocus/NA /opt/NetworkAutomation \
         /opt/opentext/networkautomation /usr/local/NA "${NA_HOME:-}"; do
  [ -n "$d" ] && [ -d "$d" ] && { NA_ROOT="$d"; break; }
done
if [ -z "$NA_ROOT" ]; then
  NA_ROOT=$(find / -xdev -maxdepth 5 -type d \
    \( -iname 'NA' -o -iname '*networkautomation*' -o -iname 'truecontrol' \) 2>/dev/null | head -1)
fi
echo "[NA root]: ${NA_ROOT:-not-found}"
[ -n "$NA_ROOT" ] && ls -ld "$NA_ROOT"

WEBAPPS=$(find / -xdev -maxdepth 9 -type d -name webapps 2>/dev/null)
echo "[webapps dirs]"; echo "$WEBAPPS"

SRC="/opt /etc /usr/local /var/opt"
[ -n "$NA_ROOT" ]  && SRC="$NA_ROOT $SRC"
[ -n "$CAT_BASE" ] && SRC="$CAT_BASE $SRC"

# ============================================================================
sec "NA SERVICE / PROCESS / JVM FLAGS"
sub "truecontrol & related units (NA service names)"
systemctl list-units --all --no-pager 2>/dev/null \
  | grep -iE 'truecontrol|network.?automation|opentext|microfocus|tomcat|nmc|opswgw'
ls -l /etc/init.d/truecontrol* /etc/init.d/na* 2>/dev/null

sub "full java command line (JVM flags matter)"
JAVACMD=$(ps auxww 2>/dev/null | grep -iE '[j]ava|[c]atalina' | head -5)
echo "$JAVACMD"

SVC_USER=$(echo "$JAVACMD" | awk 'NR==1{print $1}')
echo "[service account]: ${SVC_USER:-unknown}"
[ "$SVC_USER" = "root" ] && add HIGH "NA/Tomcat JVM runs as root — a webapp RCE becomes instant root"

sub "JMX remote (unauthenticated JMX = remote code execution)"
echo "$JAVACMD" | grep -oE '\-Dcom\.sun\.management\.jmxremote[^ ]*'
if echo "$JAVACMD" | grep -q 'jmxremote'; then
  if echo "$JAVACMD" | grep -q 'jmxremote.authenticate=false'; then
    add CRITICAL "JMX remote enabled with authenticate=false — unauthenticated JMX leads to RCE"
  else
    add MEDIUM "JMX remote enabled — verify auth + TLS + loopback/firewall restriction"
  fi
  echo "$JAVACMD" | grep -q 'jmxremote.ssl=false' && \
    add HIGH "JMX remote without TLS (jmxremote.ssl=false) — credentials/traffic in clear"
fi

sub "deserialization hardening (NA history: CVE-2016-4385 RMI, CVE-2016-8511 RPCServlet)"
if echo "$JAVACMD" | grep -q 'jdk.serialFilter'; then
  echo "$JAVACMD" | grep -oE '\-Djdk\.serialFilter=[^ ]+'
else
  add MEDIUM "No -Djdk.serialFilter set — no JVM-level deserialization allowlist on a product with two historical Java-deserialization RCEs"
fi
echo "$JAVACMD" | grep -oE 'trustURLCodebase=[^ ]+'
echo "$JAVACMD" | grep -q 'trustURLCodebase=true' && \
  add CRITICAL "JNDI/RMI trustURLCodebase=true — remote codebase loading enabled"

sub "heap dump on OOM (heap dumps contain device credentials in cleartext)"
echo "$JAVACMD" | grep -oE '\-XX:\+HeapDumpOnOutOfMemoryError|\-XX:HeapDumpPath=[^ ]+'
HDP=$(echo "$JAVACMD" | grep -oE '\-XX:HeapDumpPath=[^ ]+' | cut -d= -f2)
if [ -n "$HDP" ]; then
  ls -ld "$HDP" 2>/dev/null
  case "$HDP" in /tmp*|/var/tmp*|/dev/shm*) add HIGH "HeapDumpPath in a world-writable/shared dir ($HDP) — heap dumps hold cleartext device credentials";; esac
fi

sub "secrets on the JVM command line (visible to every local user via ps)"
echo "$JAVACMD" | grep -oiE '\-D[A-Za-z0-9._]*(pass|pwd|secret|token|key)[A-Za-z0-9._]*=[^ ]+'
echo "$JAVACMD" | grep -qiE '\-D[A-Za-z0-9._]*(pass|pwd|secret|token)[A-Za-z0-9._]*=' && \
  add HIGH "Secret passed as a JVM -D property — readable by any local user through ps"

sub "setenv.sh / CATALINA_OPTS / wrapper conf"
for f in "$CAT_BASE/bin/setenv.sh" "$CAT_HOME/bin/setenv.sh" \
         "$NA_ROOT/server/ext/wrapper/conf/wrapper.conf" \
         "$NA_ROOT/server/ext/jboss/bin/run.conf" "$NA_ROOT/bin/setenv.sh"; do
  if [ -n "$f" ] && [ -e "$f" ]; then
    if [ -r "$f" ]; then
      echo "== $f =="; ls -l "$f"; grep -vE '^\s*#' "$f" 2>/dev/null | grep -E '\S' | head -60
    else
      add INFO "Not readable as $CUR_USER (needs root/service account): startup env file — $f"
    fi
  fi
done

# ============================================================================
sec "TOMCAT server.xml HARDENING"
SERVER_XMLS=$(find / -xdev -maxdepth 9 -name 'server.xml' -path '*conf*' 2>/dev/null)
echo "[server.xml found]"; echo "$SERVER_XMLS"
while IFS= read -r sx; do
  [ -n "$sx" ] || continue
  echo; echo "===== $sx ====="; ls -l "$sx"
  [ -r "$sx" ] || { add INFO "server.xml not readable as current user: $sx"; continue; }
  [ -w "$sx" ] && add CRITICAL "server.xml writable by current user: $sx (config tampering / T1)"

  sub "connectors"
  grep -iE '<Connector|port=|protocol=|SSLEnabled|scheme=|secure=|sslProtocol|ciphers|allowTrace|keystoreFile|keystorePass|maxHttpHeaderSize|URIEncoding' "$sx"

  # shutdown port + command
  SHUT=$(grep -oE '<Server[^>]*' "$sx" | head -1)
  echo "[server element] $SHUT"
  echo "$SHUT" | grep -q 'shutdown="SHUTDOWN"' && \
    add HIGH "Tomcat shutdown command left at default \"SHUTDOWN\" — any local/reachable user can stop NA"
  SPORT=$(echo "$SHUT" | grep -oE 'port="[0-9-]+"' | head -1 | tr -dc '0-9-')
  echo "[shutdown port] ${SPORT:-none}"
  [ "$SPORT" = "8005" ] && add MEDIUM "Tomcat shutdown port at default 8005 — confirm it is loopback-only or disabled (-1)"

  # TRACE
  grep -qi 'allowTrace="true"' "$sx" && add MEDIUM "Tomcat allowTrace=\"true\" — HTTP TRACE enabled (cross-site tracing)"

  # plaintext HTTP connector
  if grep -iE '<Connector' "$sx" | grep -v 'SSLEnabled="true"' | grep -qE 'port="(80|8080|8081)"'; then
    add MEDIUM "Plaintext HTTP connector present (80/8080) — confirm it only redirects to 443, never serves the app"
  fi

  # weak TLS on the connector
  TLSCFG=$(grep -iE 'sslProtocol|sslEnabledProtocols|protocols=|ciphers=' "$sx")
  echo "[tls config] ${TLSCFG:-not-specified}"
  echo "$TLSCFG" | grep -qiE 'SSLv2|SSLv3|TLSv1(\.0)?"|TLSv1,|TLSv1\.1' && \
    add HIGH "Connector permits SSLv3/TLSv1.0/TLSv1.1 — deprecated protocols enabled"
  echo "$TLSCFG" | grep -qiE 'RC4|DES|3DES|NULL|EXPORT|MD5|anon' && \
    add HIGH "Connector cipher list includes weak ciphers (RC4/DES/3DES/NULL/EXPORT/MD5/anon)"
  [ -z "$TLSCFG" ] && grep -qi 'SSLEnabled="true"' "$sx" && \
    add LOW "TLS connector does not pin protocols/ciphers — relies on JVM defaults; confirm with testssl.sh from outside"

  # keystore password inline
  grep -oiE 'keystorePass="[^"]*"' "$sx" | sed 's/=.*/="***MASKED***"/'
  grep -qi 'keystorePass=' "$sx" && [ -r "$sx" ] && \
    add MEDIUM "Keystore password stored in cleartext in server.xml — confirm file mode is 0600 and not group/world-readable"

  # AJP / Ghostcat
  sub "AJP (Ghostcat CVE-2020-1938)"
  AJP=$(grep -iE 'AJP|8009' "$sx")
  echo "${AJP:-none}"
  if [ -n "$AJP" ]; then
    if echo "$AJP" | grep -qiE 'address="(127\.0\.0\.1|::1|localhost)"'; then
      add LOW "AJP connector present but loopback-bound"
    else
      add CRITICAL "AJP connector not loopback-bound (possible Ghostcat CVE-2020-1938 file read / RCE)"
    fi
    echo "$AJP" | grep -qi 'secretRequired="false"' && \
      add HIGH "AJP secretRequired=\"false\" — AJP accepts unauthenticated workers"
  fi

  sub "valves (error-page version leak, access logging, manager IP allowlist)"
  grep -iE '<Valve|AccessLogValve|ErrorReportValve|RemoteAddrValve|RemoteIpValve|showServerInfo|showReport' "$sx"
  grep -qi 'ErrorReportValve' "$sx" || \
    add LOW "No ErrorReportValve with showServerInfo=false — stack traces/version disclosed on error pages"
  grep -qi 'AccessLogValve' "$sx" || \
    add MEDIUM "No AccessLogValve configured — no HTTP access trail for non-repudiation (STRIDE R1/R5)"

  sub "auto-deploy (war drop = web shell)"
  grep -iE 'autoDeploy|deployOnStartup|unpackWARs' "$sx"
  grep -qi 'autoDeploy="true"' "$sx" && \
    add MEDIUM "Tomcat autoDeploy=\"true\" — any write into webapps/ becomes deployed code"
done <<< "$SERVER_XMLS"

# ============================================================================
sec "TOMCAT USERS / MANAGER APPS / DEFAULT WEBAPPS"
TU=$(find / -xdev -maxdepth 9 -name 'tomcat-users.xml' 2>/dev/null)
echo "[tomcat-users.xml]"; echo "$TU"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  ls -l "$f"
  if [ -r "$f" ]; then
    grep -iE '<user |<role ' "$f" | sed -E 's/password="[^"]*"/password="***MASKED***"/'
    grep -qiE '<user +[^>]*roles="[^"]*manager' "$f" && \
      add HIGH "tomcat-users.xml defines a manager-role user — manager GUI/text deploy is a direct web-shell path: $f"
    grep -qiE 'username="(tomcat|admin|both|role1)"' "$f" && \
      add CRITICAL "tomcat-users.xml contains a documented default account (tomcat/admin/both/role1): $f"
    add MEDIUM "tomcat-users.xml readable by current user (cleartext Tomcat passwords): $f"
  else
    add INFO "tomcat-users.xml not readable as current user: $f"
  fi
done <<< "$TU"

sub "manager / host-manager / default webapps on disk"
DEFWEB=$(find / -xdev -maxdepth 10 -type d -path '*webapps*' \
  \( -name manager -o -name host-manager -o -name examples -o -name docs -o -name ROOT \) 2>/dev/null)
echo "$DEFWEB"
while IFS= read -r d; do
  [ -n "$d" ] || continue
  case "$(basename "$d")" in
    manager|host-manager) add HIGH "Tomcat $(basename "$d") app deployed: $d — remove it or gate with RemoteAddrValve";;
    examples)             add HIGH "Tomcat examples webapp deployed: $d — known XSS/session-manipulation JSPs";;
    docs)                 add LOW  "Tomcat docs webapp deployed: $d — leaks exact Tomcat version";;
  esac
done <<< "$DEFWEB"

sub "SecurityManager / catalina.policy"
ls -l "$CAT_BASE/conf/catalina.policy" 2>/dev/null
echo "$JAVACMD" | grep -qE '\-securit|\-Djava\.security\.manager' || \
  add LOW "Tomcat not started with a SecurityManager (defense-in-depth for JSP/servlet RCE)"

sub "Tomcat version"
for j in $(find / -xdev -maxdepth 9 -name 'catalina.jar' 2>/dev/null); do
  echo "== $j =="; ls -l "$j"
  has unzip && unzip -p "$j" META-INF/MANIFEST.MF 2>/dev/null | grep -iE 'Implementation-Version|Specification-Version'
done
find / -xdev -maxdepth 9 -name 'RELEASE-NOTES*' -path '*tomcat*' 2>/dev/null | while read -r r; do
  [ -r "$r" ] && { echo "== $r =="; head -20 "$r"; }
done

# ============================================================================
sec "WEB ATTACK SURFACE — every mapped endpoint (feed this list to Burp)"
WEBXMLS=$(find / -xdev -maxdepth 11 -name 'web.xml' -path '*WEB-INF*' 2>/dev/null)
echo "[web.xml found]"; echo "$WEBXMLS"
while IFS= read -r wx; do
  [ -n "$wx" ] || continue
  echo; echo "===== $wx ====="; ls -l "$wx"
  [ -r "$wx" ] || { add INFO "web.xml not readable: $wx"; continue; }

  sub "url-patterns (the endpoint inventory)"
  grep -oE '<url-pattern>[^<]*</url-pattern>' "$wx" | sed 's/<[^>]*>//g' | sort -u

  sub "servlet / filter classes"
  grep -oE '<(servlet-class|filter-class)>[^<]*</(servlet-class|filter-class)>' "$wx" | sed 's/<[^>]*>//g' | sort -u

  sub "legacy NA servlets named in historical CVEs"
  HITS=$(grep -oiE 'RPCServlet|FileServlet|RedirectServlet|PermissionFilter|InvokerServlet|AxisServlet|HttpInvoker' "$wx" | sort -u)
  echo "${HITS:-none}"
  echo "$HITS" | grep -qi 'RPCServlet'      && add HIGH "RPCServlet still mapped (CVE-2016-8511 Java-deserialization RCE lived here) — test it in Burp: $wx"
  echo "$HITS" | grep -qi 'FileServlet'     && add HIGH "FileServlet still mapped (CVE-2017-5811 traversal/RCE lived here) — test traversal: $wx"
  echo "$HITS" | grep -qi 'RedirectServlet' && add HIGH "RedirectServlet still mapped (CVE-2017-5810 SQLi lived here) — test injection: $wx"
  echo "$HITS" | grep -qi 'PermissionFilter'&& add HIGH "PermissionFilter in use (CVE-2017-5812 auth-bypass lived here) — test authz bypass: $wx"
  echo "$HITS" | grep -qiE 'InvokerServlet|HttpInvoker' && add CRITICAL "Invoker/HttpInvoker servlet mapped — arbitrary class invocation / deserialization entry point: $wx"

  sub "security constraints & authentication"
  grep -A6 -E '<security-constraint>|<login-config>|<auth-constraint>|<transport-guarantee>' "$wx" | grep -E '<' | head -60
  grep -q '<security-constraint>' "$wx" || \
    add HIGH "No <security-constraint> in web.xml — no container-level authz on this app: $wx"
  grep -q '<transport-guarantee>CONFIDENTIAL' "$wx" || \
    add MEDIUM "No CONFIDENTIAL transport-guarantee — container does not force HTTPS for protected resources: $wx"

  sub "session & cookie hardening"
  grep -E '<session-timeout>|<http-only>|<secure>|<tracking-mode>|<cookie-config>' "$wx"
  ST=$(grep -oE '<session-timeout>[0-9]+' "$wx" | grep -oE '[0-9]+' | head -1)
  echo "[session-timeout] ${ST:-not-set} minutes"
  [ -n "$ST" ] && [ "$ST" -gt 30 ] 2>/dev/null && add MEDIUM "Session timeout ${ST}min exceeds 30min on a credential-vault product: $wx"
  grep -qE '<http-only>true' "$wx"      || add MEDIUM "Session cookie http-only not set true in web.xml: $wx"
  grep -qE '<secure>true' "$wx"         || add MEDIUM "Session cookie secure flag not set true in web.xml: $wx"
  grep -qE '<tracking-mode>COOKIE'      "$wx" || add LOW "tracking-mode not pinned to COOKIE — URL-rewriting session IDs (jsessionid in URL) possible: $wx"

  sub "directory listings / dangerous servlet params"
  grep -B2 -A4 -iE '<param-name>(listings|debug|readonly|allowLinking)</param-name>' "$wx" | grep -E '<' | head -30
  grep -A2 -i '<param-name>listings</param-name>' "$wx" | grep -qi '<param-value>true' && \
    add MEDIUM "DefaultServlet listings=true — directory browsing enabled: $wx"
  grep -A2 -i '<param-name>readonly</param-name>' "$wx" | grep -qi '<param-value>false' && \
    add CRITICAL "DefaultServlet readonly=false — HTTP PUT/DELETE can write files (web-shell upload): $wx"

  sub "error pages (stack-trace disclosure)"
  grep -E '<error-page>|<error-code>|<exception-type>' "$wx" | head -20
  grep -q '<error-page>' "$wx" || add LOW "No <error-page> defined — raw stack traces/version info returned to clients: $wx"

  sub "security headers filter"
  grep -qi 'HttpHeaderSecurityFilter' "$wx" || \
    add LOW "No HttpHeaderSecurityFilter — HSTS/X-Frame-Options/nosniff not set at the container: $wx"

  sub "CORS filter"
  grep -A6 -i 'CorsFilter' "$wx" | grep -E '<' | head -20
  grep -A8 -i 'cors.allowed.origins' "$wx" | grep -q '\*' && \
    add HIGH "CORS allowed-origins is * — cross-origin reads of authenticated responses: $wx"
done <<< "$WEBXMLS"

sub "JSP inventory (upload/web-shell targets and legacy pages)"
if [ "$FAST" != "1" ]; then
  find / -xdev -maxdepth 12 -path '*webapps*' -name '*.jsp' 2>/dev/null | head -200
else
  echo "(FAST=1 — skipped)"
fi

sub "writable web content (web-shell drop = RCE)"
for w in $WEBAPPS; do
  [ -n "$w" ] || continue
  ls -ld "$w"
  [ -w "$w" ] && add CRITICAL "webapps dir writable by current user: $w — drop a .jsp and get RCE as the NA service account"
done
WRJSP=$(find $WEBAPPS -xdev -writable -type f \( -name '*.jsp' -o -name '*.xml' -o -name '*.class' -o -name '*.jar' \) 2>/dev/null | head -40)
echo "$WRJSP"
[ -n "$WRJSP" ] && add CRITICAL "Web application files writable by current user (code/config tampering -> RCE)"

sub "WEB-INF exposure (must never be world-readable or served)"
find $WEBAPPS -xdev -maxdepth 3 -type d -name 'WEB-INF' 2>/dev/null | while read -r d; do
  [ -n "$d" ] || continue
  ls -ld "$d"
done
WIR=$(find $WEBAPPS -xdev -type f -path '*WEB-INF*' -perm -0004 2>/dev/null | head -20)
[ -n "$WIR" ] && { echo "$WIR"; add MEDIUM "World-readable files under WEB-INF (config/classes readable by any local user)"; }

sub "API docs / actuator / metadata files on disk (free endpoint discovery)"
find $WEBAPPS -xdev -maxdepth 6 \
  \( -iname 'swagger*' -o -iname 'openapi*' -o -iname '*.wsdl' -o -iname 'crossdomain.xml' \
     -o -iname 'clientaccesspolicy.xml' -o -iname 'robots.txt' -o -iname '*.wadl' \) 2>/dev/null | head -40
CD=$(find $WEBAPPS -xdev -maxdepth 4 -iname 'crossdomain.xml' 2>/dev/null)
while IFS= read -r f; do
  [ -n "$f" ] || continue
  [ -r "$f" ] && { cat "$f"; grep -q 'domain="\*"' "$f" && add HIGH "crossdomain.xml allows domain=\"*\": $f"; }
done <<< "$CD"

# ============================================================================
sec "TLS / KEYSTORE / CERTIFICATE INSPECTION"
STORES=$(find / -xdev -maxdepth 9 \( -name '*.jks' -o -name '*.p12' -o -name '*.pfx' \
  -o -name '*keystore*' -o -name '*truststore*' \) ! -name '*.jar' 2>/dev/null)
echo "[keystores]"; echo "$STORES"
KEYTOOL=$(command -v keytool 2>/dev/null)
[ -z "$KEYTOOL" ] && [ -n "$JAVA_HOME" ] && [ -x "$JAVA_HOME/bin/keytool" ] && KEYTOOL="$JAVA_HOME/bin/keytool"
[ -z "$KEYTOOL" ] && KEYTOOL=$(find / -xdev -maxdepth 8 -type f -name keytool 2>/dev/null | head -1)
echo "[keytool]: ${KEYTOOL:-not-found}"

while IFS= read -r ks; do
  [ -n "$ks" ] || continue
  echo; echo "===== $ks ====="; ls -l "$ks"
  PERM=$(stat -c '%a' "$ks" 2>/dev/null)
  echo "[mode] $PERM"
  case "$PERM" in *[4567]) add HIGH "Keystore world-readable (mode $PERM): $ks — TLS private key exposed to any local user";; esac
  [ -r "$ks" ] && add MEDIUM "Keystore readable by current (unprivileged) user: $ks"

  # documented-default store passwords only — config check, not brute force
  if [ -n "$KEYTOOL" ] && [ -r "$ks" ] && [ "${NO_KEYSTORE_PROBE:-0}" != "1" ]; then
    for pw in changeit changeme password tomcat secret; do
      if "$KEYTOOL" -list -keystore "$ks" -storepass "$pw" >/dev/null 2>&1; then
        add CRITICAL "Keystore opens with documented default password '$pw': $ks"
        echo "[default password accepted: $pw]"
        "$KEYTOOL" -list -v -keystore "$ks" -storepass "$pw" 2>/dev/null \
          | grep -iE 'Alias name|Entry type|Owner|Issuer|Valid from|Signature algorithm|Subject Public Key|key size|SHA1|SHA256' | head -60
        break
      fi
    done
  fi
done <<< "$STORES"

sub "PEM / private keys on disk"
PEMS=$(find / -xdev -maxdepth 9 \( -name '*.pem' -o -name '*.key' -o -name '*.crt' -o -name '*.cer' \) 2>/dev/null | head -60)
echo "$PEMS"
while IFS= read -r p; do
  [ -n "$p" ] || continue
  if head -1 "$p" 2>/dev/null | grep -qE 'BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY'; then
    ls -l "$p"
    PERM=$(stat -c '%a' "$p" 2>/dev/null)
    case "$PERM" in *[4567]) add CRITICAL "World-readable TLS/SSH private key (mode $PERM): $p";; esac
    [ -r "$p" ] && add HIGH "Private key readable by current unprivileged user: $p"
    head -1 "$p" | grep -q 'ENCRYPTED' || add MEDIUM "Private key stored unencrypted (no passphrase): $p"
  fi
done <<< "$PEMS"

sub "certificate expiry / key size / signature algorithm"
if has openssl; then
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    case "$c" in *.crt|*.cer|*.pem) : ;; *) continue;; esac
    [ -r "$c" ] || continue
    INFO=$(openssl x509 -in "$c" -noout -subject -issuer -enddate -text 2>/dev/null | head -20)
    [ -z "$INFO" ] && continue
    echo "== $c =="; echo "$INFO" | grep -iE 'subject=|issuer=|notAfter=|Public-Key:|Signature Algorithm:' | head -6
    openssl x509 -in "$c" -noout -checkend 0 >/dev/null 2>&1 || add HIGH "Certificate expired: $c"
    openssl x509 -in "$c" -noout -checkend 2592000 >/dev/null 2>&1 || add MEDIUM "Certificate expires within 30 days: $c"
    echo "$INFO" | grep -qiE 'Signature Algorithm: (md5|sha1)WithRSA' && add HIGH "Certificate signed with MD5/SHA-1: $c"
    echo "$INFO" | grep -qiE 'Public-Key: \((512|1024) bit\)' && add HIGH "Certificate key size < 2048 bits: $c"
    SUBJ=$(openssl x509 -in "$c" -noout -subject 2>/dev/null); ISS=$(openssl x509 -in "$c" -noout -issuer 2>/dev/null)
    [ "${SUBJ#subject=}" = "${ISS#issuer=}" ] && add LOW "Self-signed certificate in use: $c"
  done <<< "$PEMS"
else
  echo "(openssl not present)"
fi

sub "system-wide crypto policy / FIPS"
has update-crypto-policies && update-crypto-policies --show 2>/dev/null
echo "[fips_enabled] $(cat /proc/sys/crypto/fips_enabled 2>/dev/null)"

# ============================================================================
sec "JAVA LIBRARY INVENTORY (deserialization gadgets & known-vulnerable libs)"
if [ "$FAST" = "1" ]; then
  echo "(FAST=1 — skipped full jar walk)"
  JARS=""
else
  JARS=$(find / -xdev -maxdepth 12 -name '*.jar' 2>/dev/null)
fi
echo "[total jars] $(printf '%s' "$JARS" | grep -c .)"

sub "jars of security interest (name + version)"
printf '%s\n' "$JARS" | grep -iE 'log4j|commons-collections|commons-beanutils|commons-fileupload|jackson-databind|xstream|groovy|snakeyaml|spring-(core|beans|web)|struts|bcprov|httpclient|xalan|c3p0|shiro|netty|aspectjweaver|rome|hibernate|velocity|freemarker|xmlrpc|batik' | sort -u

check_jar() { # check_jar <regex> <floor-version> <SEV> <text>
  printf '%s\n' "$JARS" | grep -iE "$1" | while IFS= read -r j; do
    [ -n "$j" ] || continue
    v=$(basename "$j" | grep -oE '[0-9]+(\.[0-9]+){1,3}' | head -1)
    [ -n "$v" ] || continue
    if [ -z "$2" ] || ver_lt "$v" "$2"; then echo "$3|$4 ($v): $j"; fi
  done
}
# collected in a temp var (no subshell loss): read results back
GADGETS=$(
  check_jar '/log4j-core-[0-9]'            '2.17.1' HIGH     'log4j-core possibly Log4Shell-family vulnerable (CVE-2021-44228/45046/45105/44832)'
  check_jar '/log4j-1\.2|/log4j-1\.[0-9]'  ''       HIGH     'log4j 1.x end-of-life — CVE-2019-17571 deserialization / CVE-2021-4104 JMSAppender'
  check_jar '/commons-collections-3'       ''       HIGH     'commons-collections 3.x present — the ysoserial gadget behind NA CVE-2016-4385 RMI RCE'
  check_jar '/commons-collections4-4'      '4.1'    MEDIUM   'commons-collections4 < 4.1 gadget chain (CVE-2015-6420 family)'
  check_jar '/commons-beanutils-[0-9]'     ''       MEDIUM   'commons-beanutils present — ysoserial gadget cited in NA CVE-2016-4385'
  check_jar '/commons-fileupload-[0-9]'    '1.3.3'  HIGH     'commons-fileupload < 1.3.3 (CVE-2016-1000031 RCE)'
  check_jar '/jackson-databind-[0-9]'      '2.13.4' HIGH     'jackson-databind < 2.13.4 — polymorphic deserialization RCE family'
  check_jar '/xstream-[0-9]'               '1.4.19' HIGH     'xstream < 1.4.19 — multiple deserialization RCEs'
  check_jar '/snakeyaml-[0-9]'             '2.0'    MEDIUM   'snakeyaml < 2.0 (CVE-2022-1471 constructor RCE)'
  check_jar '/spring-beans-[0-9]'          '5.3.18' HIGH     'spring-beans < 5.3.18 (CVE-2022-22965 Spring4Shell)'
  check_jar '/spring-core-[0-9]'           '5.3.18' MEDIUM   'spring-core < 5.3.18 — Spring4Shell-era fixes'
  check_jar '/struts2?-core-[0-9]'         ''       HIGH     'Apache Struts present — OGNL RCE family, verify version against S2-0xx advisories'
  check_jar '/groovy-[0-9]'                '2.4.4'  MEDIUM   'groovy < 2.4.4 (CVE-2015-3253 deserialization)'
  check_jar '/bcprov-[0-9]'                '1.73'   LOW      'Bouncy Castle provider — verify against recent CVEs'
  check_jar '/httpclient-4\.[0-9]'         '4.5.13' LOW      'httpclient < 4.5.13 (URI/host confusion)'
  check_jar '/c3p0-[0-9]'                  ''       MEDIUM   'c3p0 present — JNDI/deserialization gadget'
  check_jar '/shiro-core-[0-9]'            '1.11.0' HIGH     'Apache Shiro < 1.11.0 — auth-bypass family'
  check_jar '/netty-[0-9]'                 '4.1.86' LOW      'netty < 4.1.86 — request-smuggling/DoS fixes'
)
echo; sub "flagged libraries"
printf '%s\n' "$GADGETS"
while IFS='|' read -r sv msg; do
  [ -n "$msg" ] || continue
  add "$sv" "$msg"
done <<< "$GADGETS"

sub "JDK / JRE version (NA 24.2+ bundles Azul Zulu — see na_cve_reference.md)"
java -version 2>&1
for jh in "${JAVA_HOME:-}" "$NA_ROOT/jre" "$NA_ROOT/jdk" "$CAT_HOME/../jre"; do
  [ -n "$jh" ] && [ -x "$jh/bin/java" ] && { echo "== $jh =="; "$jh/bin/java" -version 2>&1; }
done
rpm -qa 2>/dev/null | grep -iE 'zulu|azul|jdk|jre|java-'
java -version 2>&1 | grep -qi zulu && \
  add INFO "Azul Zulu JDK in use — check CVE-2025-31257 / 53057 / 53066 / 61748 and the Azul hotfix (see na_cve_reference.md)"

# ============================================================================
sec "NA APPLICATION CONFIG (.rcx options, datasource, credential vault)"
RCX=$(find / -xdev -maxdepth 9 \( -name '*.rcx' -o -name 'site_options*' -o -name 'adjustable_options*' \
  -o -name 'appserver*.xml' -o -name 'distributed.rcx' -o -name 'database.rcx' -o -name 'truecontrol*' \) 2>/dev/null)
echo "[NA .rcx / options files]"; echo "$RCX"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  [ -f "$f" ] || continue
  ls -l "$f"
  if [ -r "$f" ]; then
    PERM=$(stat -c '%a' "$f" 2>/dev/null)
    case "$PERM" in *[4567]) add HIGH "NA config world-readable (mode $PERM): $f";; esac
    [ -w "$f" ] && add CRITICAL "NA config writable by current user: $f (tampering — STRIDE T1)"
  else
    add INFO "NA config not readable as current user: $f"
  fi
done <<< "$RCX"

sub "security-relevant NA option keys (values masked where secret-shaped)"
for f in $RCX; do
  [ -r "$f" ] || continue
  OUT=$(grep -iE 'password|secret|key|crypt|ssl|tls|https|session|timeout|auth|ldap|tacacs|radius|audit|log|proxy|satellite|snmp|community|telnet|tftp|scp|allow|deny|cert' "$f" 2>/dev/null \
    | sed -E 's/(password|secret|key|community)([^>=:]*)([>=:]+)[^<]*/\1\2\3***MASKED***/Ig' | head -40)
  [ -n "$OUT" ] && { echo "== $f =="; echo "$OUT"; }
done

sub "authentication backend (LDAP/AD/TACACS/RADIUS/SAML) — maps to STRIDE S1/S4"
AUTHCFG=$(g -E 'ldap://|ldaps://|tacacs|radius|saml|oauth|kerberos|spnego' $SRC | head -30)
echo "$AUTHCFG"
echo "$AUTHCFG" | while IFS= read -r f; do
  [ -n "$f" ] || continue
  grep -ohiE 'ldap://[^ "<]+' "$f" 2>/dev/null | sort -u
done
g -E 'ldap://' $SRC >/dev/null 2>&1 && \
  add MEDIUM "Plaintext ldap:// URL in config — directory binds (incl. bind password) unencrypted; prefer ldaps://"
[ -z "$AUTHCFG" ] && add MEDIUM "No external auth backend (LDAP/AD/SAML/TACACS) config found — local accounts only means no central MFA/lockout for a credential-vault product"

sub "NA credential-vault encryption material"
find / -xdev -maxdepth 9 \( -name '*.key' -o -name 'master*key*' -o -name 'cleartext*' \
  -o -name '*crypt*.properties' -o -name 'secret*' \) -path "*${NA_ROOT##*/}*" 2>/dev/null | head -30
g -iE 'masterkey|master_key|encryption.key|keyfile|crypto.provider' $SRC | head -20

sub "datasource / JDBC (app -> DB trust, STRIDE S7)"
JDBCF=$(g -E 'jdbc:(postgresql|oracle|sqlserver|jtds|mysql|mariadb)' $SRC)
echo "$JDBCF"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  echo "== $f =="
  grep -ohiE 'jdbc:[^ "<,]+' "$f" 2>/dev/null | sed -E 's/(password|pwd)=[^&;]*/\1=***MASKED***/Ig' | sort -u
  if grep -qi 'jdbc:postgresql' "$f" && ! grep -qiE 'sslmode=(require|verify-ca|verify-full)' "$f"; then
    add MEDIUM "PostgreSQL JDBC URL without sslmode=require/verify-* — app-to-DB traffic unencrypted: $f"
  fi
  if grep -qi 'jdbc:oracle' "$f" && ! grep -qiE 'tcps|\(SECURITY=' "$f"; then
    add MEDIUM "Oracle JDBC URL not using TCPS — app-to-DB traffic unencrypted: $f"
  fi
  if grep -qiE 'jdbc:sqlserver|jdbc:jtds' "$f" && ! grep -qiE 'encrypt=true' "$f"; then
    add MEDIUM "SQL Server JDBC URL without encrypt=true — app-to-DB traffic unencrypted: $f"
  fi
  grep -qiE '(^|[^a-z])(password|dbpassword|db_password)[[:space:]]*[=:]' "$f" && \
    add HIGH "Cleartext DB password in app config: $f (confirm mode 0600 and service-account-only ownership)"
done <<< "$JDBCF"

# ============================================================================
sec "NA DEVICE-FACING SERVICES (TFTP / syslog / SSH+Telnet proxy / SNMP)"
sub "listening sockets (full)"
ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null

sub "NA / product port map"
ss -tuln 2>/dev/null | awk 'NR>1{print $5}' | grep -oE '[0-9]+$' | sort -un | tr '\n' ' '; echo
PORTS=$(ss -tuln 2>/dev/null)
chk_port() { echo "$PORTS" | grep -qE "[:.]$1\b"; }
for p in 21:FTP 23:"Telnet (NA device proxy or host telnetd)" 69:"TFTP (NA device config transfer)" \
         80:"HTTP" 443:HTTPS 445:SMB 514:"Syslog receiver (NA device syslog)" 1099:"Java RMI registry" \
         1098:"RMI activation" 2222:"NA SSH proxy" 4444:"JBoss/RMI" 4446:"JBoss JRMP" 4447:"JBoss remoting" \
         5432:PostgreSQL 1521:"Oracle TNS" 1433:"SQL Server" 3306:MySQL 8009:"Tomcat AJP" 8022:"NA SSH proxy (alt)" \
         8080:"Tomcat HTTP" 8083:"JBoss web service" 8443:"Tomcat HTTPS" 8005:"Tomcat shutdown" 9010:JMX 161:SNMP; do
  pn=${p%%:*}; pd=${p#*:}
  chk_port "$pn" && echo "  OPEN $pn  -> $pd"
done
chk_port 23   && add HIGH   "TCP/23 listening — Telnet (cleartext). If this is the NA telnet proxy, device credentials cross the wire unencrypted"
chk_port 21   && add HIGH   "TCP/21 listening — FTP (cleartext credentials)"
chk_port 69   && add MEDIUM "UDP/69 TFTP listening — NA device-config transfer is unauthenticated and unencrypted by design; confirm it is restricted to device subnets by firewall"
chk_port 514  && add LOW    "514 syslog receiver listening — confirm it only accepts managed-device subnets"
chk_port 1099 && add HIGH   "TCP/1099 RMI registry listening — the vector of NA CVE-2016-4385 (RMI Java-deserialization RCE). Must not be network-reachable"
chk_port 161  && add MEDIUM "UDP/161 SNMP agent on the NA server — check for public/private community strings"
chk_port 8080 && add MEDIUM "TCP/8080 plaintext HTTP listening alongside 443 — confirm it only redirects"
chk_port 8005 && add LOW    "TCP/8005 Tomcat shutdown port listening — confirm loopback-only"

sub "sockets bound to 0.0.0.0 / :: (exposed beyond loopback)"
ss -tuln 2>/dev/null | grep -E '0\.0\.0\.0:|\[::\]:'

sub "TFTP / syslog / SNMP server config on this host"
for f in /etc/xinetd.d/tftp /etc/sysconfig/tftp /etc/default/tftpd-hpa /etc/snmp/snmpd.conf \
         /etc/rsyslog.conf /etc/rsyslog.d/*.conf; do
  [ -r "$f" ] && { echo "== $f =="; grep -vE '^\s*(#|$)' "$f" 2>/dev/null | head -25; }
done
if [ -r /etc/snmp/snmpd.conf ]; then
  grep -qiE '^\s*(rocommunity|rwcommunity)\s+(public|private)' /etc/snmp/snmpd.conf && \
    add HIGH "snmpd.conf uses default community string public/private"
  grep -qiE '^\s*rwcommunity' /etc/snmp/snmpd.conf && \
    add HIGH "snmpd.conf exposes a read-WRITE SNMP community"
fi

sub "device credentials / SNMP strings in NA config and scripts"
g -iE 'community[[:space:]]*[=:]|enable[[:space:]]+(secret|password)|sharedsecret|shared_secret' $SRC | head -20

# ============================================================================
sec "NA PATCH / HOTFIX INVENTORY (Hotfix 2447300 / KM000044586)"
find / -xdev -maxdepth 8 \( -iname '*hotfix*' -o -iname '*patch*' -o -iname 'installed*' \
  -o -iname 'na_install*.log' -o -iname 'install.log' -o -iname '*.installlog' \) 2>/dev/null | head -40
for f in $(find / -xdev -maxdepth 8 \( -iname '*hotfix*' -o -iname 'installed_patches*' \) -type f 2>/dev/null | head -10); do
  [ -r "$f" ] && { echo "== $f =="; head -40 "$f"; }
done
g -iE '2447300|KM000044586' / >/dev/null 2>&1
HFOUND=$(g -iE '2447300|KM000044586' /opt /var/opt /usr/local /tmp 2>/dev/null | head -5)
echo "[hotfix 2447300 references]: ${HFOUND:-none found on disk}"
[ -z "$HFOUND" ] && add HIGH "No on-disk evidence of Hotfix 2447300 / KM000044586 — NA 25.2 without it is missing published security fixes (confirm in the NA UI: Help > About / patch level)"

sub "NA build / version strings"
for f in $(find / -xdev -maxdepth 8 \( -name 'version.properties' -o -name 'build.properties' \
    -o -name 'VERSION' -o -name 'product.version' -o -name 'release-notes*' \) 2>/dev/null | head -20); do
  [ -r "$f" ] && { echo "== $f =="; grep -iE 'version|build|release|patch' "$f" 2>/dev/null | head -10; }
done

# ============================================================================
sec "RUNTIME ARTIFACTS THAT LEAK CREDENTIALS"
sub "heap dumps / core dumps / java_pid files"
DUMPS=$(find / -xdev -maxdepth 8 \( -name '*.hprof' -o -name 'java_pid*' -o -name 'core.[0-9]*' \
  -o -name 'core' -o -name '*.dmp' -o -name 'javacore*' -o -name 'heapdump*' \) -type f 2>/dev/null | head -30)
echo "$DUMPS"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  ls -l "$f"
  add HIGH "Memory/heap dump present: $f — dumps of the NA JVM contain decrypted device credentials; delete and restrict HeapDumpPath"
done <<< "$DUMPS"
echo "[core pattern] $(cat /proc/sys/kernel/core_pattern 2>/dev/null)"
echo "[suid_dumpable] $(cat /proc/sys/fs/suid_dumpable 2>/dev/null)"
[ "$(cat /proc/sys/fs/suid_dumpable 2>/dev/null)" = "1" ] && add MEDIUM "fs.suid_dumpable=1 — setuid processes can be core-dumped"

sub "NA log files leaking secrets (STRIDE I5)"
LOGDIRS=""
for d in "$NA_ROOT/server/log" "$NA_ROOT/logs" "$CAT_BASE/logs" /var/log/opentext /var/log/microfocus /var/log/na; do
  [ -n "$d" ] && [ -d "$d" ] && LOGDIRS="$LOGDIRS $d"
done
echo "[NA log dirs]:${LOGDIRS:- none found}"
for d in $LOGDIRS; do
  ls -ld "$d"; ls -l "$d" 2>/dev/null | head -25
  WR=$(find "$d" -maxdepth 2 -perm -0004 -type f 2>/dev/null | head -10)
  [ -n "$WR" ] && add MEDIUM "World-readable NA log files in $d"
  W2=$(find "$d" -maxdepth 2 -writable -type f 2>/dev/null | head -5)
  [ -n "$W2" ] && add HIGH "NA log files writable by current user in $d — audit-trail tampering (STRIDE R2)"
  HITS=$(grep -rIlE 'password[[:space:]]*[=:]|community[[:space:]]*[=:]|enable secret|Authorization: (Basic|Bearer)' "$d" 2>/dev/null | head -10)
  [ -n "$HITS" ] && { echo "[secret-shaped strings in]"; echo "$HITS"; add HIGH "Credential-shaped strings found in NA logs under $d"; }
done

sub "temp / staging dirs used for device configs and exports"
for d in /tmp /var/tmp /dev/shm "$NA_ROOT/server/tmp" "$CAT_BASE/temp" "$CAT_BASE/work"; do
  [ -n "$d" ] && [ -d "$d" ] && { ls -ld "$d"; find "$d" -maxdepth 2 -type f -perm -0004 2>/dev/null | head -15; }
done

# ============================================================================
sec "FRONT-END WEB SERVER (if httpd/nginx fronts Tomcat)"
for f in /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/ssl.conf /etc/nginx/nginx.conf; do
  [ -r "$f" ] || continue
  echo "== $f =="
  grep -iE '^\s*(ServerTokens|ServerSignature|TraceEnable|SSLProtocol|SSLCipherSuite|SSLHonorCipherOrder|Header|server_tokens|ssl_protocols|ssl_ciphers|add_header|proxy_pass|listen)' "$f" | head -30
  grep -qiE '^\s*ServerTokens\s+(Full|OS|Min)' "$f" && add LOW "Apache ServerTokens not Prod — version disclosure: $f"
  grep -qiE '^\s*TraceEnable\s+On' "$f" && add MEDIUM "Apache TraceEnable On — HTTP TRACE enabled: $f"
  grep -qiE 'SSLProtocol.*(SSLv2|SSLv3|TLSv1(\.0|\.1)?[^.])' "$f" && add HIGH "Front-end web server permits SSLv3/TLSv1.0/1.1: $f"
  grep -qiE 'ssl_protocols.*(SSLv3|TLSv1(\.0|\.1)?[; ])' "$f" && add HIGH "nginx ssl_protocols permits SSLv3/TLSv1.0/1.1: $f"
  grep -qi 'Strict-Transport-Security' "$f" || add LOW "No HSTS header configured in $f"
done
has httpd  && httpd -v 2>/dev/null
has nginx  && nginx -v 2>&1

# ============================================================================
sec "APP -> DB LATERAL MOVEMENT (two-server trust)"
echo "[DB endpoints referenced in app config]"
g -E 'jdbc:' $SRC 2>/dev/null | while read -r f; do
  grep -ohiE 'jdbc:[a-z]+://[^ "/,;]+|\(HOST *= *[^)]+\)' "$f" 2>/dev/null
done | sort -u | head -20
echo "[.pgpass / .my.cnf on the app server (passwordless DB login)]"
find /home /root "$NA_ROOT" -maxdepth 4 \( -name '.pgpass' -o -name '.my.cnf' -o -name '.netrc' \) 2>/dev/null \
  | while read -r f; do [ -n "$f" ] && { ls -l "$f"; [ -r "$f" ] && add HIGH "Passwordless DB credential file readable on the app server: $f"; }; done
echo "[ssh keys / known_hosts pointing at the DB server]"
find /home /root -maxdepth 4 \( -name 'id_*' -o -name 'known_hosts' -o -name 'authorized_keys' \) 2>/dev/null | head -20
echo "[arp/neighbour table — reachable hosts]"; ip neigh 2>/dev/null | head -20
echo "[routes]"; ip route 2>/dev/null

summary
echo
echo "Run na_db_enum.sh on the DB server and na_hardening_audit.sh on BOTH."
echo "Nothing was modified; no network egress."
