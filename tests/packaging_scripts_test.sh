#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT HUP INT TERM
mkdir -p "$test_root/bin"
: >"$test_root/state"
: >"$test_root/calls"

cat >"$test_root/bin/dpkg-divert" <<'MOCK'
#!/bin/sh
set -eu
if [ "$1" = "--listpackage" ]; then
    cat "$DIVERSION_STATE"
    exit 0
fi
printf '%s\n' "$*" >>"$DIVERSION_CALLS"
case " $* " in
    *" --add "*) printf 'ufw-guard' >"$DIVERSION_STATE" ;;
    *" --remove "*) : >"$DIVERSION_STATE" ;;
esac
MOCK
chmod +x "$test_root/bin/dpkg-divert"

export PATH="$test_root/bin:$PATH"
export DIVERSION_STATE="$test_root/state"
export DIVERSION_CALLS="$test_root/calls"

sh "$repo_root/debian/preinst" install
test "$(cat "$test_root/state")" = ufw-guard
test "$(wc -l <"$test_root/calls")" -eq 1

sh "$repo_root/debian/preinst" upgrade
sh "$repo_root/debian/postrm" upgrade
test "$(cat "$test_root/state")" = ufw-guard
test "$(wc -l <"$test_root/calls")" -eq 1

printf 'another-package' >"$test_root/state"
if sh "$repo_root/debian/preinst" install >/dev/null 2>&1; then
    echo "preinst accepted a diversion owned by another package" >&2
    exit 1
fi

printf 'ufw-guard' >"$test_root/state"
sh "$repo_root/debian/postrm" remove
test ! -s "$test_root/state"
test "$(wc -l <"$test_root/calls")" -eq 2
grep -Fq -- '--package ufw-guard --add --rename --divert /usr/sbin/ufw.real /usr/sbin/ufw' "$test_root/calls"
grep -Fq -- '--package ufw-guard --remove --rename --divert /usr/sbin/ufw.real /usr/sbin/ufw' "$test_root/calls"
