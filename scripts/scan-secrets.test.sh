#!/usr/bin/env bash
# Offline checks for scan-secrets.sh, in scratch git repos: one made-up key per pattern that must be reported, and
# lines that look close and must not be. Every made-up key is put together here at run time from pieces no pattern
# matches, so this file stays clean under the scan of its own repo (checked last).
#
# Usage: scripts/scan-secrets.test.sh [path/to/scan-secrets.sh]
# Exit 0 every check passed, 1 a check failed, 2 the checks could not run, which says nothing about the scanner.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
scan=${1:-$here/scan-secrets.sh}
setup() { echo "SETUP: $*" >&2; exit 2; }
for t in git bash mktemp; do command -v "$t" >/dev/null || setup "$t not on PATH"; done
[ -r "$scan" ] || setup "can't read $scan"
scan=$(cd "$(dirname "$scan")" && pwd)/$(basename "$scan")
T=$(mktemp -d "${TMPDIR:-/tmp}/scan-secrets-test.XXXXXX") || setup "can't create a scratch directory"
trap 'rm -rf "$T"' EXIT
# No global or system git config reaches the scratch repos: a hook or a signing setting there would change a commit.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=scan-test GIT_AUTHOR_EMAIL=scan-test@example.invalid
export GIT_COMMITTER_NAME=scan-test GIT_COMMITTER_EMAIL=scan-test@example.invalid

pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL $*"; }
# The made-up keys' secret part is this motif repeated, so "the text was never printed" is checked on every run.
m() { local n=$1 s=; while [ ${#s} -lt "$n" ]; do s=${s}F4keF4ke; done; printf '%s' "${s:0:n}"; }
# run REPO [ARGS]: sets out and rc.
run() {
  local repo=$1; shift; rc=0
  out=$(cd "$repo" && bash "$scan" "$@" 2>&1) || rc=$?
  ! command grep -q F4ke <<<"$out" || bad "a made-up key's text reached the output"
}
newrepo() { git init -q -b main "$1" && git -C "$1" commit -q --allow-empty -m root; }

# name TAB the line that must be reported under that name. ${q} is empty: it splits each prefix so no pattern
# matches this file.
q=
A21=AAAAAAAAAAAAAAAAAAAAA
hits=$(cat <<EOF2
hq-key	k=uhq${q}_abc123_$(m 20)
pem-private-key	-----BEGIN RSA PRIV${q}ATE KEY-----
github-token	k=gh${q}p_$(m 36)
github-pat	k=github${q}_pat_$(m 40)
aws-access-key-id	k=AKI${q}AABCDEFGHIJKLMNOP
sk-key	k=s${q}k-$(m 24)
anthropic-key	k=s${q}k-ant-api03-$(m 40)
openai-key	k=s${q}k-proj-$(m 40)
stripe-key	k=s${q}k_live_$(m 24)
slack-token	k=xo${q}xb-1234567890-$(m 24)
google-api-key	k=AI${q}za$(m 35)
telegram-bot-token	k=7123456789:A${q}A$(m 33)
google-oauth-token	k=ya${q}29.a0$(m 60)
google-refresh-token	k=1/${q}/0$(m 43)
x-bearer	k=$A21$(m 24)%3${q}D$(m 40)
x-bearer	k=$A21$(m 24)=$(m 40)
assigned-secret	MY_API_TO${q}KEN=$(m 40)
assigned-secret	export BOT_SEC${q}RET="$(m 32)"
jwk-private-d	"d": "$(m 43)"
EOF2
)
# Lines that must stay clean: what a loose pattern would wrongly report.
clean=$(cat <<EOF2
GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
API_TOKEN=\$OTHER_VARIABLE_WITH_A_LONG_NAME_INDEED
TOKEN_FILE=/home/someone/.config/some/long/path/to/a/token/file.txt
SECRET_URL=https://example.invalid/a/long/path/that/is/not/a/secret
PASSWORD=changeme
the task-list-of-things-that-go-on-and-on-for-a-while is kebab case
data:image/png;base64,iVBORw0KGgo${A21}${A21}ABAAEAAAICRAEAOw==
a token is a thing you hold and a secret is a thing you keep to yourself always
call 1234567890 at 10:30
Set \`TURNSTILE_SEC${q}RET_KEY=1x0000000000000000000000000000000AA\` (always passes) for local runs
const SEC${q}RET = 'S3cretS3cretS3cretS3cretS3cretS3cret01';
  SOME_TO${q}KEN: $(m 40)
EOF2
)

# 1. Each made-up key, alone in a tracked file, is reported under its pattern's name.
n=0
while IFS=$'\t' read -r name line; do
  n=$((n + 1)); r=$T/hit$n; newrepo "$r"; printf '%s\n' "$line" > "$r/f.txt"; git -C "$r" add f.txt
  run "$r"
  if [ "$rc" = 1 ] && command grep -qF "f.txt:1: $name" <<<"$out"; then ok; else bad "$name not reported (rc=$rc)"; fi
done <<<"$hits"

# 2. The near misses are clean.
r=$T/clean; newrepo "$r"; printf '%s\n' "$clean" > "$r/f.txt"; git -C "$r" add f.txt
run "$r"; if [ "$rc" = 0 ]; then ok; else bad "a clean line was reported: $out"; fi

# 3. A key after a NUL byte, in the tree and in the history.
r=$T/bin; newrepo "$r"; printf 'x\0y gh''p_%s\n' "$(m 36)" > "$r/blob.bin"; git -C "$r" add blob.bin
run "$r"; if [ "$rc" = 1 ] && command grep -qF 'blob.bin:1: github-token' <<<"$out"; then ok; else bad "a key in a binary file's tree was missed (rc=$rc)"; fi
git -C "$r" commit -q -m add; git -C "$r" rm -q blob.bin; git -C "$r" commit -q -m remove
run "$r"; if [ "$rc" = 0 ]; then ok; else bad "a removed file still fails the tree scan"; fi
run "$r" --history; if [ "$rc" = 1 ] && command grep -q 'commit [0-9a-f]* blob.bin:1: github-token' <<<"$out"; then ok; else bad "a key in a binary file's history was missed (rc=$rc)"; fi

# 4. A key committed and then removed: the tree is clean, the base and the whole history are not.
r=$T/hist; newrepo "$r"; base=$(git -C "$r" rev-parse HEAD)
printf 'k=gh''p_%s\n' "$(m 36)" > "$r/k.txt"; git -C "$r" add k.txt; git -C "$r" commit -q -m add
git -C "$r" rm -q k.txt; git -C "$r" commit -q -m remove
run "$r"; if [ "$rc" = 0 ]; then ok; else bad "removed key: the tree should be clean"; fi
run "$r" "$base"; if [ "$rc" = 1 ]; then ok; else bad "removed key: BASE..HEAD missed it (rc=$rc)"; fi
run "$r" --history; if [ "$rc" = 1 ]; then ok; else bad "removed key: --history missed it (rc=$rc)"; fi

# 5. What can't be scanned is exit 2, never clean.
run "$r" no-such-commit; if [ "$rc" = 2 ]; then ok; else bad "an unknown BASE gave rc=$rc, wanted 2"; fi
mkdir "$T/norepo"; run "$T/norepo"; if [ "$rc" = 2 ]; then ok; else bad "outside a repo gave rc=$rc, wanted 2"; fi

# 6. This file and the scanner are clean under the scan themselves.
r=$T/self; newrepo "$r"; mkdir "$r/scripts"; cp "$scan" "${BASH_SOURCE[0]}" "$r/scripts/"; git -C "$r" add -A
run "$r"; if [ "$rc" = 0 ]; then ok; else bad "the scanner or its test trips the scan: $out"; fi

# A positive control on the checks themselves: with no made-up key ever reported, sections 1 to 4 proved nothing.
[ "$n" -ge 19 ] || setup "the list of made-up keys came through short ($n)"
echo "scan-secrets.test.sh: $pass passed, $fail failed"
[ "$fail" = 0 ]
