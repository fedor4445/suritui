#!/bin/sh
# Install suritui for local mode (suritui running ON the Suricata router).
#
#     cargo build --release
#     sudo sh contrib/freebsd/install.sh ACCOUNT
#
# ACCOUNT is the unix account that will run suritui. Run this from the top of
# the source tree. The script changes nothing if a check fails, keeps the
# previous versions as *.prev, and puts the old sudoers file back if the
# combined sudoers files no longer parse. It does not start, stop or reload
# Suricata, and it does not change any Suricata file.
set -eu
cd "$(dirname "$0")/../.."

[ "$(id -u)" = 0 ] || { echo "run this as root: sudo sh contrib/freebsd/install.sh ACCOUNT"; exit 1; }
[ "$#" = 1 ] || { echo "usage: sudo sh contrib/freebsd/install.sh ACCOUNT"; exit 1; }
ACCOUNT=$1
[ "$ACCOUNT" != root ] || { echo "ACCOUNT must be the ordinary account that runs suritui, not root"; exit 1; }
id "$ACCOUNT" >/dev/null 2>&1 || { echo "no such account: $ACCOUNT"; exit 1; }
[ "$(uname -s)" = FreeBSD ] || { echo "this installer is for FreeBSD"; exit 1; }
for f in target/release/suritui target/release/suritui-admin; do
    [ -f "$f" ] && [ ! -L "$f" ] || { echo "$f is missing: run cargo build --release first"; exit 1; }
done
command -v visudo >/dev/null || { echo "visudo not found: install sudo first"; exit 1; }
[ -d /usr/local/etc/sudoers.d ] || { echo "/usr/local/etc/sudoers.d does not exist"; exit 1; }
grep -Eq '^[#@]includedir[[:space:]]+/usr/local/etc/sudoers.d' /usr/local/etc/sudoers \
    || { echo "/usr/local/etc/sudoers does not include sudoers.d; nothing changed"; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
# The file is made by the program you just built, so it always matches it.
target/release/suritui print-sudoers "$ACCOUNT" > "$TMP/suritui.sudoers"
visudo -cf "$TMP/suritui.sudoers" >/dev/null || { echo "the generated sudoers file is not valid; nothing changed"; exit 1; }
echo "checks passed"

mkdir -p /usr/local/bin /usr/local/sbin
if [ -f /usr/local/bin/suritui ]; then cp -p /usr/local/bin/suritui /usr/local/bin/suritui.prev; fi
if [ -f /usr/local/sbin/suritui-admin ]; then cp -p /usr/local/sbin/suritui-admin /usr/local/sbin/suritui-admin.prev; fi
install -m 755 -o root -g wheel target/release/suritui-admin /usr/local/sbin/suritui-admin
install -m 755 -o root -g wheel target/release/suritui /usr/local/bin/suritui

# The sudoers file goes in last, and is undone at once if the combined sudoers
# files do not parse (a broken sudoers could lock you out of sudo).
SD=/usr/local/etc/sudoers.d/suritui
if [ -f "$SD" ]; then cp -p "$SD" "$SD.rollback"; fi
install -m 440 -o root -g wheel "$TMP/suritui.sudoers" "$SD"
if ! visudo -c >/dev/null 2>&1; then
    echo "the sudoers files do not parse together; putting the old one back"
    if [ -f "$SD.rollback" ]; then mv -f "$SD.rollback" "$SD"; else rm -f "$SD"; fi
    visudo -c
    echo "the programs are installed, but the sudoers entries were NOT"
    exit 1
fi
rm -f "$SD.rollback"
echo "installed. Previous versions, if there were any: *.prev next to each program"
echo
echo "Optional, to let suritui switch rule sources and store keys (screen 3), once, as root:"
echo "    chown root:wheel /var/lib/suricata /var/lib/suricata/update"
echo "The helper refuses source and key changes while Suricata's own account owns those"
echo "folders (it could otherwise swap them). Suricata's rules folder stays as it is."
echo
echo "Then run, as $ACCOUNT:  suritui --local"
