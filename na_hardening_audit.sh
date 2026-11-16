#!/bin/bash
# ============================================================================
#  OpenText Network Automation CE 25.2 — CIS-lite Hardening Audit (read-only)
#
#  This is the companion script that na_enum.sh, na_db_enum.sh and
#  na_webapp_surface.sh all tell you to run ("Also run na_hardening_audit.sh
#  on this host") but was not part of the original upload. It fills the gap:
#  instead of hunting for NA-specific misconfigs (the other scripts' job),
#  this one checks baseline OS/account hardening against a CIS-Benchmark-
#  style checklist. Run it on BOTH the app/web server and the DB server.
#
#  Design : NO writes, NO outbound network, NO persistence. Built-ins only.
#  Usage  : bash na_hardening_audit.sh
#
#  Covers (CIS RHEL-flavoured, trimmed to what's checkable without a
#  dedicated CIS tool and without modifying anything):
#    - privilege level this run has (so "clean" vs "couldn't check" is explicit)
#    - password quality policy (pwquality/login.defs)
#    - account lockout (faillock/pam_faillock)
#    - PAM stack sanity (pam_unix, pam_deny ordering) — read-only inspection
#    - auditd rule coverage for security-relevant syscalls/files
#    - SELinux booleans relevant to a Tomcat+DB app
#    - umask defaults
#    - login/SSH banners (legal warning banner present or not)
#    - inactive/disabled-account hygiene
#    - core dump / ptrace restrictions
#    - time sync (duplicated lightly from na_db_enum.sh since it matters
#      app-side too, for audit-log correlation)
#    - unnecessary services listening
# ============================================================================
usage() {
  cat <<'EOF'
Usage: bash na_hardening_audit.sh [-h|--help]

Read-only CIS-lite OS/account hardening audit — the companion script the
other scripts reference ("Also run na_hardening_audit.sh on this host").
Checks password policy, account lockout, PAM stack, auditd rule coverage,
SELinux booleans, banners, umask, account hygiene, and unnecessary
listening services. No arguments or environment variables needed.

Options:
  -h, --help    Show this help and exit

Run this on BOTH the app/web server and the DB server. Most checks need
root to read their config files — if run unprivileged, most sections
will show as INFO "not readable" rather than a real pass/fail; that's a
signal to re-run with elevated access, not a clean result.

This is a CIS-lite checklist, not a scored CIS Benchmark scan. For formal
compliance scoring, run a dedicated tool (e.g. OpenSCAP with the RHEL CIS
profile) separately.
EOF
}
case "${1:-}" in -h|--help) usage; exit 0;; esac

export LC_ALL=C

B="==================================================================="
sec() { printf '\n%s\n[ %s ]\n%s\n' "$B" "$1" "$B"; }

FINDINGS=""
add() {
  local k
  [ -n "${2:-}" ] || return 0
  case "$1" in CRITICAL) k=0;; HIGH) k=1;; MEDIUM) k=2;; LOW) k=3;; *) k=4;; esac
  FINDINGS="${FINDINGS}${k}|$1|$2"$'\n'
}
skip() { add INFO "Not readable/runnable as $(id -un) (needs root): $2 — $1"; }

# ============================================================================
sec "SYSTEM & PRIVILEGE LEVEL (read this first)"
hostname 2>/dev/null; id
cat /etc/redhat-release 2>/dev/null
CUR_USER=$(id -un); CUR_UID=$(id -u)
if [ "$CUR_UID" -eq 0 ]; then
  PRIV="root"
elif sudo -n true 2>/dev/null; then
  PRIV="passwordless-sudo"
else
  PRIV="unprivileged"
fi
echo "privilege level: $PRIV"
echo "Most of this checklist (password policy files, auditd rules, PAM stack,"
echo "SELinux booleans) requires root to read. Run this once per server at"
echo "whatever access level you have; if unprivileged, most sections below"
echo "will show as INFO 'not readable' rather than a real pass/fail — treat"
echo "that as 'needs an admin-level run', not as 'compliant'."

# ============================================================================
sec "PASSWORD QUALITY POLICY"
PQ="/etc/security/pwquality.conf"
if [ -r "$PQ" ]; then
  grep -vE '^\s*(#|$)' "$PQ"
  v() { grep -E "^\s*$1\s*=" "$PQ" 2>/dev/null | tail -1 | sed -E "s/^[^=]*=\s*//"; }
  MINLEN=$(v minlen); DCREDIT=$(v dcredit); UCREDIT=$(v ucredit); LCREDIT=$(v lcredit); OCREDIT=$(v ocredit)
  [ -n "$MINLEN" ] && [ "$MINLEN" -lt 14 ] 2>/dev/null && add MEDIUM "pwquality minlen=$MINLEN (<14) — CIS recommends >=14 for a credential-vault product"
  [ -z "$MINLEN" ] && add MEDIUM "pwquality minlen not set (defaults to 8) — set >=14"
  { [ -z "$DCREDIT" ] && [ -z "$UCREDIT" ] && [ -z "$LCREDIT" ] && [ -z "$OCREDIT" ]; } && \
    add LOW "No character-class requirements (dcredit/ucredit/lcredit/ocredit) set in pwquality.conf"
else
  skip "$PQ" "pwquality.conf"
fi
echo "[login.defs password aging]"
if [ -r /etc/login.defs ]; then
  grep -E '^\s*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|PASS_MIN_LEN|ENCRYPT_METHOD)' /etc/login.defs
  PMAX=$(grep -E '^\s*PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}')
  [ -n "$PMAX" ] && [ "$PMAX" -gt 365 ] 2>/dev/null && add LOW "PASS_MAX_DAYS=$PMAX exceeds 365 days"
  grep -qE '^\s*ENCRYPT_METHOD\s+SHA512' /etc/login.defs || add MEDIUM "ENCRYPT_METHOD is not SHA512 in login.defs"
else
  skip /etc/login.defs "login.defs"
fi

# ============================================================================
sec "ACCOUNT LOCKOUT (faillock)"
FL="/etc/security/faillock.conf"
if [ -r "$FL" ]; then
  grep -vE '^\s*(#|$)' "$FL"
  DENY=$(grep -E '^\s*deny\s*=' "$FL" | tail -1 | sed -E 's/^[^=]*=\s*//')
  [ -z "$DENY" ] && add MEDIUM "faillock 'deny' not configured — no lockout threshold on repeated failed logins"
  [ -n "$DENY" ] && [ "$DENY" -gt 5 ] 2>/dev/null && add LOW "faillock deny=$DENY — CIS suggests <=5"
elif [ -r /etc/pam.d/system-auth ] || [ -r /etc/pam.d/password-auth ]; then
  grep -lE 'pam_faillock|pam_tally2' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null >/dev/null \
    || add MEDIUM "No pam_faillock/pam_tally2 reference found in system-auth/password-auth — account lockout may not be enforced"
else
  skip "$FL" "faillock.conf / pam.d auth stack"
fi

# ============================================================================
sec "PAM STACK SANITY (read-only — not modifying anything)"
for f in /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/sshd /etc/pam.d/su /etc/pam.d/login; do
  if [ -r "$f" ]; then
    echo "== $f =="; grep -vE '^\s*#' "$f" | grep -E '\S'
  else
    [ -e "$f" ] && skip "$f" "PAM config"
  fi
done

# ============================================================================
sec "AUDITD RULE COVERAGE (security-relevant syscalls/files)"
if systemctl is-active auditd >/dev/null 2>&1; then
  echo "[auditd active]"
  AR="/etc/audit/rules.d"
  if [ -r "$AR" ] || [ -d "$AR" ]; then
    FOUND=$(grep -rhsE '^\s*-w|^\s*-a' $AR /etc/audit/audit.rules 2>/dev/null)
    echo "$FOUND" | grep -q . || add MEDIUM "auditd running but no custom -w/-a rules found under $AR or audit.rules — likely stock/no rules"
    for watch in /etc/passwd /etc/shadow /etc/sudoers "execve" "identity" "logins"; do
      echo "$FOUND" | grep -qi "$watch" || add LOW "No auditd rule appears to watch '$watch' — consider adding (CIS 4.1.x)"
    done
  else
    skip "$AR" "audit rules directory"
  fi
else
  add HIGH "auditd is not active — no kernel-level audit trail on this host (STRIDE R1/R2/R4)"
fi

# ============================================================================
sec "SELINUX BOOLEANS (Tomcat/DB relevant)"
if command -v getsebool >/dev/null 2>&1; then
  for b in httpd_can_network_connect_db httpd_can_network_connect nis_enabled; do
    getsebool "$b" 2>/dev/null
  done
  getsebool httpd_can_network_connect_db 2>/dev/null | grep -q 'on$' || \
    echo "  (httpd_can_network_connect_db off/unset — fine if NA app isn't labeled httpd_t; re-check if it is)"
else
  echo "(getsebool not available — selinux-policy-utils not installed, or SELinux disabled)"
fi

# ============================================================================
sec "UMASK DEFAULTS"
echo "[current shell umask]"; umask
grep -rHE '^\s*umask\s+[0-9]+' /etc/bashrc /etc/profile /etc/profile.d/*.sh 2>/dev/null
grep -rHE '^\s*umask\s+0?0[0-2][0-2]' /etc/bashrc /etc/profile /etc/profile.d/*.sh 2>/dev/null | grep -q . && \
  echo "  (umask 022 or looser found — CIS prefers 027 for a server handling device credentials)" && \
  add LOW "Default umask looser than 027 found in global shell init files"

# ============================================================================
sec "LOGIN / SSH BANNERS (legal notice — CIS 1.8.x)"
for f in /etc/issue /etc/issue.net /etc/motd; do
  if [ -r "$f" ]; then
    echo "== $f =="; cat "$f"
    [ -s "$f" ] || add LOW "$f is empty — no legal/authorized-use banner configured"
  else
    skip "$f" "banner file"
  fi
done
if [ -r /etc/ssh/sshd_config ]; then
  grep -E '^\s*Banner' /etc/ssh/sshd_config || add LOW "sshd_config has no Banner directive configured"
else
  skip /etc/ssh/sshd_config "sshd_config"
fi

# ============================================================================
sec "ACCOUNT HYGIENE (inactive / disabled / duplicate)"
echo "[accounts with empty password field]"
if [ -r /etc/shadow ]; then
  awk -F: '($2==""){print $1}' /etc/shadow | while read -r u; do
    [ -n "$u" ] && add CRITICAL "Account '$u' has an empty password hash in /etc/shadow"
  done
else
  skip /etc/shadow "/etc/shadow (empty-password check)"
fi
echo "[duplicate UIDs]"
awk -F: '{print $3}' /etc/passwd | sort | uniq -d | while read -r dupuid; do
  [ -n "$dupuid" ] && add MEDIUM "Duplicate UID $dupuid in /etc/passwd — multiple accounts share one identity (breaks accountability/non-repudiation)"
done
echo "[duplicate usernames]"
awk -F: '{print $1}' /etc/passwd | sort | uniq -d | while read -r dupname; do
  [ -n "$dupname" ] && add MEDIUM "Duplicate username '$dupname' in /etc/passwd"
done
echo "[accounts with no expiry on an inactive password policy]"
if [ -r /etc/shadow ] && command -v chage >/dev/null 2>&1; then
  awk -F: '$7!~/nologin|false/{print $1}' /etc/passwd | while read -r u; do
    chage -l "$u" 2>/dev/null | grep -qi 'never' && echo "  $u: password/account never expires"
  done
fi

# ============================================================================
sec "CORE DUMP / PTRACE RESTRICTIONS"
echo "[fs.suid_dumpable] $(cat /proc/sys/fs/suid_dumpable 2>/dev/null)"
[ "$(cat /proc/sys/fs/suid_dumpable 2>/dev/null)" != "0" ] && \
  add MEDIUM "fs.suid_dumpable != 0 — setuid/root process memory (which may include decrypted device credentials) can be core-dumped"
echo "[kernel.core_pattern] $(cat /proc/sys/kernel/core_pattern 2>/dev/null)"
echo "[kernel.yama.ptrace_scope] $(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)"

# ============================================================================
sec "TIME SYNCHRONISATION (audit-log correlation across app + DB servers)"
systemctl is-active chronyd 2>/dev/null; systemctl is-active ntpd 2>/dev/null
timedatectl 2>/dev/null | grep -iE 'NTP service|synchronized|Time zone'
timedatectl 2>/dev/null | grep -qiE 'NTP service: active|synchronized: yes' || \
  add MEDIUM "Time sync not confirmed active on this host — correlating this host's logs with the other NA server's logs will be unreliable (STRIDE R1)"

# ============================================================================
sec "UNNECESSARY SERVICES LISTENING"
ss -tulnp 2>/dev/null
for svc in telnet rsh rlogin tftp xinetd nfs rpcbind avahi-daemon cups; do
  systemctl is-active "$svc" 2>/dev/null | grep -q active && \
    add MEDIUM "Legacy/unneeded service active: $svc — disable unless this host is specifically providing it to managed devices (e.g. tftp)"
done

# ============================================================================
echo
echo "########################################################################"
echo "#                  HARDENING AUDIT — FINDINGS SUMMARY                   #"
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
echo "This is a CIS-lite checklist, not a full CIS Benchmark scan (no profile"
echo "scoring, no remediation). For a formal compliance score, run a real"
echo "CIS-Benchmark scanner (e.g. OpenSCAP w/ the RHEL CIS profile) separately —"
echo "this script exists only to close the gap the other scripts referenced."
echo "Run this on BOTH the app/web server and the DB server."
echo "Nothing modified; no network egress."
