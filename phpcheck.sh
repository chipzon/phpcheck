#!/usr/bin/env bash
# phpcheck.sh — php2shell (CVE-2026-109618 / CVE-2026-109619) self-check
#
# Run this ON YOUR OWN SERVER. It inspects the PHP you control and tells you
# whether you're actually patched — including the distro-backport case where
# the version number does NOT change. It sends no exploit, touches no remote
# host, and only reads local package metadata + `php -v`.
#
# Usage:
#   bash phpcheck.sh            # human-readable report
#   bash phpcheck.sh --json     # machine-readable (one JSON object)
#
# Exit codes: 0 = patched, 1 = NOT patched, 2 = needs manual verification.

set -u

CVES="CVE-2026-109618 CVE-2026-109619"
# Upstream minimum fixed patch per branch (Oct 21 2026 release).
# Branches <= 8.1 are EOL upstream: no upstream fix, only distro/vendor backports.
declare -A FIXED=( [8.5]=12 [8.4]=27 [8.3]=36 [8.2]=35 )

JSON=0
[ "${1:-}" = "--json" ] && JSON=1

# ---------- helpers ----------
ver_ge() { # ver_ge A B  -> true if A >= B (dotted numeric)
  [ "$1" = "$2" ] && return 0
  local s; s=$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)
  [ "$s" = "$1" ]
}

emit_json() { # verdict code version sapi branch source detail
  printf '{"verdict":"%s","exit":%s,"php_version":"%s","sapi":"%s","branch":"%s","source":"%s","backport_cve_in_changelog":%s,"detail":"%s"}\n' \
    "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"
}

# ---------- 1. locate PHP ----------
if ! command -v php >/dev/null 2>&1; then
  if [ "$JSON" = 1 ]; then emit_json "no_php" 2 "" "" "" "" "false" "php CLI not found on PATH; run on the host that serves PHP"; else
    echo "php not found on PATH. Run this on the server that actually serves PHP,"
    echo "or point it at the right binary (e.g. /opt/php8.3/bin/php)."; fi
  exit 2
fi

PHP_VERSION=$(php -r 'echo PHP_VERSION;' 2>/dev/null)
PHP_SAPI_CLI=$(php -r 'echo PHP_SAPI;' 2>/dev/null)
BRANCH=$(printf '%s' "$PHP_VERSION" | cut -d. -f1,2)
PATCH=$(printf '%s' "$PHP_VERSION" | cut -d. -f3 | sed 's/[^0-9].*//')

# Note any separately-installed FPM binary (the one serving the web usually is FPM, not CLI).
FPM_NOTE=""
for b in php-fpm "php-fpm${BRANCH}" "php${BRANCH}-fpm"; do
  if command -v "$b" >/dev/null 2>&1; then
    FPM_NOTE=$("$b" -v 2>/dev/null | head -1)
    break
  fi
done

# ---------- 2. detect how PHP was installed + find its package ----------
SOURCE="unknown"; PKG=""; PKGVER=""; CHANGELOG=""
if command -v dpkg >/dev/null 2>&1; then
  PKG=$(dpkg -l 2>/dev/null | awk '/^ii/ && $2 ~ /^php.*(common|cli|fpm)/ {print $2; exit}')
  [ -n "$PKG" ] && { SOURCE="deb"; PKGVER=$(dpkg-query -W -f='${Version}' "$PKG" 2>/dev/null); }
  for f in /usr/share/doc/${PKG}/changelog.Debian.gz /usr/share/doc/${PKG}/changelog.gz; do
    [ -f "$f" ] && CHANGELOG="$CHANGELOG $(zcat "$f" 2>/dev/null)"
  done
elif command -v rpm >/dev/null 2>&1; then
  PKG=$(rpm -qa 2>/dev/null | grep -E '^php(-cli|-common|-fpm|[0-9])' | head -1)
  [ -n "$PKG" ] && { SOURCE="rpm"; PKGVER="$PKG"; CHANGELOG=$(rpm -q --changelog "$PKG" 2>/dev/null); }
fi
# Source builds / official Docker images often have no distro package.
[ -z "$PKG" ] && SOURCE="source-or-image"

# ---------- 3. backport check: is a CVE id in the installed package changelog? ----------
BACKPORT="false"
if [ -n "$CHANGELOG" ]; then
  for c in $CVES; do
    if printf '%s' "$CHANGELOG" | grep -q "$c"; then BACKPORT="true"; break; fi
  done
fi

# ---------- 4. verdict ----------
# Rule A: if the running version meets/exceeds the upstream fixed patch for its
#         branch, it's patched outright.
# Rule B: else, if the distro package changelog cites a php2shell CVE, the fix
#         was backported — patched, even though the number looks old.
# Rule C: else, on a supported branch below the fix -> NOT patched.
# Rule D: EOL branch with no backport evidence -> manual verification.
VERDICT=""; CODE=2; DETAIL=""
FIX_PATCH="${FIXED[$BRANCH]:-}"

if [ -n "$FIX_PATCH" ] && ver_ge "$BRANCH.$PATCH" "$BRANCH.$FIX_PATCH"; then
  VERDICT="PATCHED"; CODE=0
  DETAIL="$PHP_VERSION meets the upstream fixed $BRANCH.$FIX_PATCH."
elif [ "$BACKPORT" = "true" ]; then
  VERDICT="PATCHED"; CODE=0
  DETAIL="Version looks old ($PHP_VERSION) but the installed package ($PKGVER) backported the fix — a php2shell CVE id is in its changelog."
elif [ -n "$FIX_PATCH" ]; then
  VERDICT="NOT PATCHED"; CODE=1
  DETAIL="$PHP_VERSION is below the fixed $BRANCH.$FIX_PATCH and no backport is recorded. Update now."
else
  # EOL branch (<=8.1) or unknown branch
  if [ "$SOURCE" = "deb" ] || [ "$SOURCE" = "rpm" ]; then
    VERDICT="VERIFY"; CODE=2
    DETAIL="$PHP_VERSION is on an EOL branch ($BRANCH). No php2shell CVE found in the package changelog, but distros sometimes ship minimal backports. Confirm $PKGVER against your provider's advisory, then move off $BRANCH."
  else
    VERDICT="VERIFY"; CODE=2
    DETAIL="$PHP_VERSION on an EOL/unknown branch from a source or image build. No distro changelog to confirm a backport. Rebuild from a fixed upstream (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) or confirm your vendor's backport."
  fi
fi

# ---------- 5. output ----------
if [ "$JSON" = 1 ]; then
  emit_json "$VERDICT" "$CODE" "$PHP_VERSION" "$PHP_SAPI_CLI" "$BRANCH" "$SOURCE" "$BACKPORT" "$DETAIL"
  exit $CODE
fi

bar="----------------------------------------------------------------"
echo "$bar"
echo " php2shell self-check  (CVE-2026-109618 / CVE-2026-109619)"
echo "$bar"
printf " PHP version   : %s\n" "$PHP_VERSION"
printf " Checked SAPI  : %s (CLI)\n" "$PHP_SAPI_CLI"
[ -n "$FPM_NOTE" ] && printf " FPM present   : %s\n" "$FPM_NOTE"
printf " Install source: %s%s\n" "$SOURCE" "$([ -n "$PKGVER" ] && echo "  ($PKGVER)")"
printf " Backport in changelog: %s\n" "$BACKPORT"
echo "$bar"
case "$VERDICT" in
  "PATCHED")     printf "  \033[1;32m✓ PATCHED\033[0m\n" ;;
  "NOT PATCHED") printf "  \033[1;31m✗ NOT PATCHED\033[0m\n" ;;
  *)             printf "  \033[1;33m! NEEDS VERIFICATION\033[0m\n" ;;
esac
echo
echo " $DETAIL"
echo "$bar"
echo " Note: this checked the PHP binary above. Your site is served by the"
echo " FPM/Apache SAPI — run this on each serving instance (and inside the"
echo " container, if containerised), not just the CLI, to be sure."
echo "$bar"
exit $CODE
