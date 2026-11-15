#!/bin/sh
# Remove suritui's local mode from a router.
#
#     sudo sh contrib/freebsd/uninstall.sh [--and-prev]
#
# Removes only what install.sh put in: the two programs and the sudoers file. It
# does not touch Suricata, its rules or its config (suritui only ever changed
# Suricata's own disable.conf, enable.conf and threshold.config, and those stay
# as they are), does not stop or reload anything, and leaves your
# ~/.config/suritui alone. The *.prev copies of older versions are kept unless you
# pass --and-prev. Nothing on the router depends on suritui, so Suricata and the
# router keep running exactly as before.
#
# DESTDIR works as usual for packagers and for the tests: with it set, the paths
# live under that directory and the root, FreeBSD and visudo checks are skipped.
set -eu

AND_PREV=no
for a in "$@"; do
    case "$a" in
        --and-prev) AND_PREV=yes ;;
        *) echo "usage: sudo sh contrib/freebsd/uninstall.sh [--and-prev]"; exit 1 ;;
    esac
done

D=${DESTDIR:-}
if [ -z "$D" ]; then
    [ "$(id -u)" = 0 ] || { echo "run this as root: sudo sh contrib/freebsd/uninstall.sh"; exit 1; }
    [ "$(uname -s)" = FreeBSD ] || { echo "this script is for FreeBSD"; exit 1; }
fi

BIN=$D/usr/local/bin/suritui
ADMIN=$D/usr/local/sbin/suritui-admin
SD=$D/usr/local/etc/sudoers.d/suritui

found=no
for f in "$BIN" "$ADMIN" "$SD"; do
    if [ -e "$f" ] || [ -L "$f" ]; then found=yes; fi
done
if [ "$found" = no ]; then
    echo "suritui is not installed here (nothing at $BIN, $ADMIN or $SD); nothing changed"
    exit 0
fi

# The sudoers entry goes first, so the helper can no longer be run with sudo while
# the programs are being removed. A missing or odd sudoers.d is not an error.
if [ -e "$SD" ] || [ -L "$SD" ]; then
    cp -p "$SD" "$SD.uninstall-rollback"
    rm -f "$SD"
    if [ -z "$D" ] && command -v visudo >/dev/null && ! visudo -c >/dev/null 2>&1; then
        echo "the sudoers files do not parse after the removal; putting the entry back"
        mv -f "$SD.uninstall-rollback" "$SD"
        visudo -c
        echo "nothing was removed"
        exit 1
    fi
    rm -f "$SD.uninstall-rollback"
    echo "removed $SD"
fi

for f in "$ADMIN" "$BIN"; do
    if [ -e "$f" ] || [ -L "$f" ]; then
        rm -f "$f"
        echo "removed $f"
    fi
done

if [ "$AND_PREV" = yes ]; then
    for f in "$ADMIN.prev" "$BIN.prev"; do
        if [ -e "$f" ]; then
            rm -f "$f"
            echo "removed $f"
        fi
    done
fi

echo
echo "suritui is removed. Left alone on purpose:"
echo "  - Suricata and all its files, including any rules you switched off with suritui"
echo "    (disable.conf, enable.conf, threshold.config): they are ordinary Suricata files"
[ "$AND_PREV" = yes ] || echo "  - the *.prev copies of older versions (remove them with --and-prev)"
echo "  - your settings in ~/.config/suritui (delete the folder if you want it gone)"
echo "  - the ownership of /var/lib/suricata, if you ran the optional chown that install.sh"
echo "    mentions; root ownership there is harmless to Suricata"
