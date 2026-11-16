#!/bin/bash
# ============================================================================
#  Linux Local Security Enumeration + Automated Findings (read-only)
#  Purpose : authorized security assessment / hardening review
#  Design  : NO file modification, NO outbound network, NO persistence,
#            standard built-ins only. Output is plain text on stdout.
#            Auto-flags common misconfigs and privesc vectors, then prints a
#            severity-ranked findings summary.
#  Note    : RHEL backports security fixes without bumping upstream versions,
#            so version-based CVE flags are "possible" not "confirmed".
#  Usage   : bash linux_enum.sh
#
#  CHANGELOG vs original:
#   - Added an explicit privilege-level banner at the top (root / passwordless
#     sudo / plain user). Run this on BOTH the user-level and admin-level
#     boxes and diff the "privilege level" + "SKIPPED" lines — that tells you
#     exactly which checks are evidence of "clean" vs evidence of "couldn't see".
#   - Added skip() so a permission-denied read is a visible INFO finding
#     instead of silently vanishing into an empty block.
#   - Added docker-group membership check (not just socket readability —
#     membership alone is root-equivalent via `docker run -v /:/host`).
#   - Findings summary now dedupes with sort -u, matching the other scripts.
# ============================================================================
usage() {
  cat <<'EOF'
Usage: bash linux_enum.sh [-h|--help]

Read-only Linux local security enumeration + automated findings summary.
No arguments or environment variables — just run it on the target host.
Takes no action that modifies the system; makes no outbound network calls.

Options:
  -h, --help    Show this help and exit

Tip: run once as an unprivileged user and once with root/sudo on the same
host, then diff the two outputs — anything that shows as an INFO "not
readable as <user>" line in the unprivileged run and becomes a real
PASS/FAIL finding in the root run was invisible without elevated access.
EOF
}
case "${1:-}" in -h|--help) usage; exit 0;; esac

export LC_ALL=C

B="==================================================================="
sec() { printf '\n%s\n[ %s ]\n%s\n' "$B" "$1" "$B"; }

# ---- findings accumulator: stores "sortkey|SEVERITY|message" lines ----
FINDINGS=""
add() {
  local k
  case "$1" in CRITICAL) k=0;; HIGH) k=1;; MEDIUM) k=2;; LOW) k=3;; INFO) k=4;; esac
  FINDINGS="${FINDINGS}${k}|$1|$2"$'\n'
}
ver_lt() { [ "$1" != "$2" ] && [ "$1" = "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" ]; }

# skip <path> <label>  -> prints + records that <path> could not be read as
# the current user, so a "nothing found" report can be told apart from a
# "couldn't check" report.
skip() {
  add INFO "Not readable as $(id -un) (needs root/service account): $2 — $1"
}

# ============================================================================
sec "SYSTEM & IDENTITY"
echo "[hostname]"; hostname; hostname -f 2>/dev/null
echo "[user]"; id
echo "[release]"; cat /etc/redhat-release 2>/dev/null

sec "PRIVILEGE LEVEL (read this first)"
CUR_USER=$(id -un); CUR_UID=$(id -u)
if [ "$CUR_UID" -eq 0 ]; then
  PRIV="root"
elif sudo -n true 2>/dev/null; then
  PRIV="passwordless-sudo"
elif sudo -n -l >/dev/null 2>&1; then
  PRIV="partial-sudo (some commands only — see SUDO section below)"
else
  PRIV="unprivileged"
fi
echo "running as: $CUR_USER (uid=$CUR_UID)"
echo "privilege level: $PRIV"
echo "(checks below that need root will show as an INFO 'Not readable' finding"
echo " rather than silently returning nothing — review those before concluding"
echo " a section is clean.)"

echo "[kernel]"; uname -a
sec "KERNEL / VERSION (exploit matching)"
uname -r
cat /proc/version
echo "[kernel packages]"; rpm -q kernel 2>/dev/null

# ============================================================================
sec "SUDO & POLKIT"
echo "[sudo -l]"; sudo -n -l 2>/dev/null || echo "(no passwordless sudo or no sudo)"
if sudo -n -l >/dev/null 2>&1; then
  add CRITICAL "Passwordless sudo available to current user"
fi
echo "[sudo version]"; sudo -V 2>/dev/null | head -1
sudo -V 2>/dev/null | head -1 | grep -Eq '1\.8\.([2-9]|[12][0-9]|3[01])(\.|p|$)|1\.9\.[0-4]|1\.9\.5p?0?$' \
  && add CRITICAL "sudo version possibly vulnerable to CVE-2021-3156 (Baron Samedit) — confirm patch level (1.9.5p2+ is fixed) against RHEL errata"
echo "[pkexec version]"; pkexec --version 2>/dev/null
PKV=$(pkexec --version 2>/dev/null | sed -E 's/.*version //; s/[^0-9.].*//')
[ -n "$PKV" ] && ver_lt "$PKV" "0.120" \
  && add CRITICAL "pkexec $PKV possibly vulnerable to CVE-2021-4034 (PwnKit) — confirm against RHEL errata"

# ============================================================================
sec "SUID / SGID BINARIES"
SUID=$(find / -xdev -perm -4000 -type f 2>/dev/null)
echo "-- SUID --"; echo "$SUID"
echo "-- SGID --"; find / -xdev -perm -2000 -type f 2>/dev/null
DANGEROUS="bash|sh|dash|ash|zsh|ksh|csh|tcsh|python|python2|python3|perl|ruby|php|lua|node|nodejs|find|vim|vi|nano|less|more|man|cp|mv|dd|tar|zip|unzip|gzip|bzip2|awk|gawk|sed|env|nice|socat|nc|ncat|netcat|nmap|docker|git|make|xargs|script|screen|tmux|ed|tee|timeout|base32|base64|fold|expand|install|chmod|chown|busybox|ionice|taskset|watch|setsid|flock|date|sleep|printf|cut|head|tail|sort|uniq|od|xz|lzma|unshare|runc|gcc|cc"
while IFS= read -r f; do
  b=$(basename "$f")
  echo "$b" | grep -Eq "^($DANGEROUS)([0-9.]+)?$" && add HIGH "SUID on privesc-capable binary: $f"
done <<< "$SUID"
echo "NOTE: 'find -xdev' does not cross filesystem/mount boundaries — if /opt, /home,"
echo "or /var are separate mounts, re-run the SUID/SGID/world-writable checks against"
echo "each of them individually (e.g. find /opt -xdev -perm -4000 ...) or they're skipped."

# ============================================================================
sec "FILE CAPABILITIES"
CAPOUT=$(getcap -r / 2>/dev/null)
echo "$CAPOUT"
while IFS= read -r line; do
  echo "$line" | grep -Eq 'cap_(setuid|setgid|chown|dac_read_search|dac_override|sys_admin|sys_ptrace|sys_module|sys_chroot|net_admin|net_raw)' \
    && add HIGH "Dangerous file capability: $line"
done <<< "$CAPOUT"

# ============================================================================
sec "CONTAINER ESCAPE VECTORS"
echo "[docker socket]"; ls -l /var/run/docker.sock 2>/dev/null
[ -r /var/run/docker.sock ] && add CRITICAL "Docker socket readable (container escape to root)"
[ -e /var/run/docker.sock ] && [ ! -r /var/run/docker.sock ] && add HIGH "Docker socket present"
echo "[current user's groups]"; id -Gn 2>/dev/null
id -Gn 2>/dev/null | grep -qwE 'docker' && \
  add CRITICAL "Current unprivileged user is in the 'docker' group — root-equivalent via 'docker run -v /:/host ... chroot /host', even without the socket itself being world-readable"
id -Gn 2>/dev/null | grep -qwE 'lxd' && \
  add CRITICAL "Current user is in the 'lxd' group — root-equivalent via a privileged LXD container mount, same class of issue as the docker group"

# ============================================================================
sec "WORLD-WRITABLE / ORPHANED / UNSAFE DIRS"
echo "-- world-writable dirs --"; find / -xdev -type d -perm -0002 2>/dev/null
echo "-- world-writable files --"; find / -xdev -type f -perm -0002 2>/dev/null
echo "-- world-writable dirs WITHOUT sticky bit --"
WWNOSTICKY=$(find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null)
echo "$WWNOSTICKY"
while IFS= read -r d; do add HIGH "World-writable dir without sticky bit: $d"; done <<< "$WWNOSTICKY"
echo "-- orphaned (no-owner) files --"; NOOWNER=$(find / -xdev \( -nouser -o -nogroup \) 2>/dev/null); echo "$NOOWNER"
[ -n "$NOOWNER" ] && add MEDIUM "Orphaned no-owner files present (possible privesc via uid reuse)"

# ============================================================================
sec "WRITABLE PATH DIRS"
echo "$PATH" | tr ':' '\n' | while read -r d; do
  [ -n "$d" ] && [ -w "$d" ] && add HIGH "Writable dir in \$PATH: $d"
done

# ============================================================================
sec "CRON JOBS"
for f in /etc/crontab /etc/anacrontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
  if [ -r "$f" ]; then echo "== $f =="; cat "$f" 2>/dev/null; else [ -e "$f" ] && skip "$f" "cron file"; fi
done
ls -la /var/spool/cron /var/spool/anacron 2>/dev/null
CRONWW=$(find /etc/cron* /var/spool/cron /var/spool/anacron -type f -perm -0002 2>/dev/null)
CRONGW=$(find /etc/cron* /var/spool/cron /var/spool/anacron -type f -perm -0020 2>/dev/null)
while IFS= read -r f; do add CRITICAL "World-writable cron script (root executes): $f"; done <<< "$CRONWW"
while IFS= read -r f; do add HIGH "Group-writable cron script: $f"; done <<< "$CRONGW"

# ============================================================================
sec "ACCOUNT & /etc/passwd ANALYSIS"
echo "[UID 0 accounts]"; UID0=$(awk -F: '$3==0{print $1}' /etc/passwd); echo "$UID0"
[ "$(echo "$UID0" | grep -c .)" -gt 1 ] && add MEDIUM "Multiple UID 0 accounts (should be root only)"
echo "[login-shell accounts]"; awk -F: '$7!~/nologin|false/{print $1" -> "$7}' /etc/passwd
echo "[passwd file perms]"; ls -l /etc/passwd
[ -w /etc/passwd ] && add CRITICAL "/etc/passwd is writable (append a UID 0 user)"
if [ -r /etc/shadow ]; then add HIGH "/etc/shadow is readable (offline hash cracking)"; else skip /etc/shadow "/etc/shadow"; fi

# ============================================================================
sec "CREDENTIALS / SECRETS IN FILES (filenames only)"
grep -rIlE 'password|passwd|secret|api[_-]?key|token|BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE' \
  /etc /home /opt /var/www /usr/local /tmp 2>/dev/null

# ============================================================================
sec "SSH KEYS & TRUST (credential-access — optional if host EDR watches this)"
find / -xdev \( -name 'id_rsa' -o -name 'id_dsa' -o -name '*.pem' -o -name '*.key' -o -name 'authorized_keys' \) 2>/dev/null
echo "[ssh config]"
if [ -r /etc/ssh/sshd_config ]; then
  grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|X11Forwarding|AllowUsers|AllowGroups)' /etc/ssh/sshd_config 2>/dev/null
  grep -qE '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config 2>/dev/null && add HIGH "SSH PermitRootLogin is yes"
  grep -qE '^\s*PasswordAuthentication\s+yes' /etc/ssh/sshd_config 2>/dev/null && add MEDIUM "SSH PasswordAuthentication enabled (weak-password risk)"
  grep -qE '^\s*PermitEmptyPasswords\s+yes' /etc/ssh/sshd_config 2>/dev/null && add CRITICAL "SSH PermitEmptyPasswords is yes"
  grep -qE '^\s*X11Forwarding\s+yes' /etc/ssh/sshd_config 2>/dev/null && add LOW "SSH X11Forwarding enabled"
else
  skip /etc/ssh/sshd_config "sshd_config (often root-only mode 600)"
fi
echo "[trust files]"; cat /etc/hosts.equiv /etc/hosts.allow /etc/hosts.deny 2>/dev/null
RHOSTS=$(find / -xdev -name '.rhosts' 2>/dev/null)
echo "$RHOSTS"
{ [ -s /etc/hosts.equiv ] || [ -n "$RHOSTS" ]; } && add HIGH ".rhosts / hosts.equiv trust present (legacy r-command trust)"

# ============================================================================
sec "LISTENING PORTS & PROCESSES"
ss -tulnp 2>/dev/null
[ "$PRIV" = "unprivileged" ] && echo "(note: 'ss -p'/'ps auxww' process-owner columns may be blank for sockets/processes owned by other users when run unprivileged)"
ps auxww 2>/dev/null

# ============================================================================
sec "KERNEL HARDENING (/proc/sys)"
ASLR=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
KREST=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)
DREST=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)
PTS=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
IPFWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
echo "randomize_va_space (want 2): $ASLR"
echo "kptr_restrict (want !=0):   $KREST"
echo "dmesg_restrict (want 1):    $DREST"
echo "ptrace_scope (want >=1):    $PTS"
echo "ip_forward (want 0):        $IPFWD"
[ "$ASLR" = "0" ] && add HIGH "ASLR disabled (randomize_va_space=0)"
[ "$ASLR" = "1" ] && add MEDIUM "ASLR partial (randomize_va_space=1)"
[ "$KREST" = "0" ] && add MEDIUM "kptr_restrict=0 (kernel pointers readable)"
[ "$DREST" = "0" ] && add MEDIUM "dmesg_restrict=0 (kernel log readable by user)"
[ "$PTS" = "0" ] && add LOW "ptrace_scope=0 (can ptrace other users' processes)"
[ "$IPFWD" = "1" ] && add MEDIUM "IPv4 forwarding enabled (ip_forward=1)"

# ============================================================================
sec "SELINUX / FIREWALL"
SE=$(getenforce 2>/dev/null); echo "[selinux] $SE"; sestatus 2>/dev/null
case "$SE" in
  Enforcing) : ;;
  Permissive) add HIGH "SELinux is Permissive (enforcement off)";;
  Disabled)   add HIGH "SELinux is Disabled";;
  *)          add MEDIUM "SELinux status unknown: $SE";;
esac
FW=$(firewall-cmd --state 2>/dev/null); echo "[firewalld state] ${FW:-unknown}"
{ [ "$FW" = "not running" ] || [ -z "$FW" ]; } && add MEDIUM "firewalld not running"
echo "[iptables]"; iptables -L -n 2>/dev/null || skip "iptables -L" "iptables ruleset (often root-only)"

# ============================================================================
sec "NETWORK & MOUNTS"
ip addr 2>/dev/null; ip route 2>/dev/null
cat /etc/resolv.conf 2>/dev/null
ip neigh 2>/dev/null
echo "[remote mounts]"; mount 2>/dev/null | grep -E 'nfs|cifs|smbfs'
echo "[NFS export root-squash]"
if [ -r /etc/exports ]; then
  grep -vE '^\s*(#|$)' /etc/exports
  grep -q 'no_root_squash' /etc/exports && add CRITICAL "/etc/exports uses no_root_squash — an NFS client gets root over the exported data"
else
  [ -e /etc/exports ] && skip /etc/exports "/etc/exports"
fi

# ============================================================================
sec "WRITABLE FILES IN /etc"
ETCWW=$(find /etc -xdev -type f -perm -0002 2>/dev/null); echo "$ETCWW"
while IFS= read -r f; do add HIGH "World-writable file in /etc: $f"; done <<< "$ETCWW"
ETCW=$(find /etc -xdev -type f -writable 2>/dev/null)
while IFS= read -r f; do add MEDIUM "User-writable file in /etc: $f"; done <<< "$ETCW"

# ============================================================================
sec "INSTALLED PACKAGES (for offline CVE diff)"
rpm -qa 2>/dev/null

# ============================================================================
#                             FINDINGS SUMMARY
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
  echo
  echo "  Unique issues flagged: $(printf '%s' "$FINDINGS" | sort -u | grep -c .)"
fi
echo
echo "NOTE: version-based CVE flags are 'possible' only — RHEL backports patches"
echo "without bumping upstream versions. Confirm each against the RHEL errata."
echo "If run unprivileged, re-run as (or diff against) an admin-level pass before"
echo "concluding any INFO 'not readable' section is actually clean."
echo "Enumeration complete. No files modified, no network egress."
