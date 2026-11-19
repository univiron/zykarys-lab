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
for t in git bash mktemp perl sed seq; do command -v "$t" >/dev/null || setup "$t not on PATH"; done
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
aws-access-key-id	aws_access_key_id = ASI${q}AABCDEFGHIJKLMNOP
aws-secret-access-key	aws_sec${q}ret_access_key = $(m 40)
aws-secret-access-key	AWS_SEC${q}RET_ACCESS_KEY="$(m 20)/$(m 19)"
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
assigned-secret	    INDENTED_TO${q}KEN=$(m 40)
jwk-private-d	"d": "$(m 43)"
EOF2
)
# Lines that must stay clean: what a loose pattern would wrongly report.
clean=$(cat <<EOF2
GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
API_TOKEN=\$OTHER_VARIABLE_WITH_A_LONG_NAME_INDEED
TOKEN_FILE=/opt/app/.config/some/long/path/to/a/token/file.txt
SECRET_URL=https://example.invalid/a/long/path/that/is/not/a/secret
PASSWORD=changeme
the task-list-of-things-that-go-on-and-on-for-a-while is kebab case
job tas${q}k-0123456789abcdef0123456789abcdef finished
CACHE_TO${q}KEN=$(m 32)/and/then/a/path
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

# 3b. A NUL that is the only byte between a word and a key: taking the NULs out closes that gap, so the history must
# be read as it is as well. (univiron-mcp's repro, 2026-11-18.)
r=$T/nulb; newrepo "$r"
printf 'Z\0s''k-ant-api03-%s\nZ\0s''k-%s\n' "$(m 48)" "$(m 48)" > "$r/rec.bin"; git -C "$r" add rec.bin
run "$r"; if [ "$rc" = 1 ] && command grep -qF 'rec.bin:1: anthropic-key' <<<"$out" && command grep -qF 'rec.bin:2: sk-key' <<<"$out"; then ok; else bad "a key right after a NUL was missed in the tree (rc=$rc)"; fi
git -C "$r" commit -q -m add; git -C "$r" rm -q rec.bin; git -C "$r" commit -q -m remove
run "$r" --history; if [ "$rc" = 1 ] && command grep -q 'commit [0-9a-f]* rec.bin:1: anthropic-key' <<<"$out" && command grep -q 'commit [0-9a-f]* rec.bin:2: sk-key' <<<"$out"; then ok; else bad "a key right after a NUL was missed in the history (rc=$rc)"; fi

# 4. A key committed and then removed: the tree is clean, the base and the whole history are not.
r=$T/hist; newrepo "$r"; base=$(git -C "$r" rev-parse HEAD)
printf 'k=gh''p_%s\n' "$(m 36)" > "$r/k.txt"; git -C "$r" add k.txt; git -C "$r" commit -q -m add
git -C "$r" rm -q k.txt; git -C "$r" commit -q -m remove
run "$r"; if [ "$rc" = 0 ]; then ok; else bad "removed key: the tree should be clean"; fi
run "$r" "$base"; if [ "$rc" = 1 ]; then ok; else bad "removed key: BASE..HEAD missed it (rc=$rc)"; fi
run "$r" --history; if [ "$rc" = 1 ]; then ok; else bad "removed key: --history missed it (rc=$rc)"; fi

# 4b. A line a commit adds that itself starts with a space or a "+", then is removed: the history still reports it.
r=$T/lead; newrepo "$r"; base=$(git -C "$r" rev-parse HEAD)
printf '  MY_API_TO''KEN=%s\n+OTHER_SEC''RET=%s\n' "$(m 40)" "$(m 40)" > "$r/e.env"; git -C "$r" add e.env; git -C "$r" commit -q -m add
git -C "$r" rm -q e.env; git -C "$r" commit -q -m remove
run "$r" "$base"; if [ "$rc" = 1 ] && command grep -q 'e.env:1: assigned-secret' <<<"$out" && command grep -q 'e.env:2: assigned-secret' <<<"$out"; then ok; else bad "an added line starting with a space or + was missed in the history (rc=$rc)"; fi

# 4c. UTF-16 text (a NUL beside every character): in the tree, and in the history after it is removed.
r=$T/u16; newrepo "$r"
{ printf 'first line\nk=gh''p_%s\n' "$(m 36)" | sed 's/./&\x00/g; s/$/\x00/' | sed '1s/^/\xff\xfe/'; } > "$r/env.txt"; git -C "$r" add env.txt
run "$r"; if [ "$rc" = 1 ] && command grep -qF 'env.txt:2: github-token' <<<"$out"; then ok; else bad "a key in UTF-16 text was missed in the tree (rc=$rc)"; fi
git -C "$r" commit -q -m add; git -C "$r" rm -q env.txt; git -C "$r" commit -q -m remove
run "$r" --history; if [ "$rc" = 1 ] && command grep -q 'commit [0-9a-f]* env.txt:2: github-token' <<<"$out"; then ok; else bad "a key in UTF-16 text was missed in the history (rc=$rc)"; fi

# 4d. UTF-16 text where a character that is not ASCII stands right before the key: キーは in front of it. Taking the
# NULs out leaves that character's other byte against the key ("0sk-ant..."), so only decoding the text finds it.
# Little and big endian, with and without a byte-order mark, at an odd byte offset, and after 《 (U+300A, whose low
# byte is a newline, so the line is split inside it), each in the tree and in the history after it is removed.
le() { printf '%s' "$1" | sed 's/./&\x00/g'; }
be() { printf '%s' "$1" | sed 's/./\x00&/g'; }
key="s${q}k-ant-api03-$(m 48)"
u16() { # NAME LINE [PATTERN]: the file comes from stdin; the key is reported at LINE in the tree and the history.
  local name=$1 line=$2 pat=${3:-anthropic-key}; r=$T/u16-$name; newrepo "$r"; cat > "$r/$name.txt"; git -C "$r" add -- "$name.txt"
  run "$r"; if [ "$rc" = 1 ] && command grep -qF -e "$name.txt:$line: $pat" <<<"$out"; then ok; else bad "UTF-16 $name: the key was missed in the tree (rc=$rc)"; fi
  git -C "$r" commit -q -m add; git -C "$r" rm -q -- "$name.txt"; git -C "$r" commit -q -m remove
  run "$r" --history; if [ "$rc" = 1 ] && command grep -q "commit [0-9a-f]* $name.txt:$line: $pat" <<<"$out"; then ok; else bad "UTF-16 $name: the key was missed in the history (rc=$rc)"; fi
}
u16 le-bom 2 < <(printf '\xff\xfe'; le 'first line'; printf '\n\0\xad\x30\xfc\x30\x6f\x30'; le "$key"; printf '\n\0')
u16 le 2 < <(le 'first line'; printf '\n\0\xad\x30\xfc\x30\x6f\x30'; le "$key"; printf '\n\0')
u16 be-bom 2 < <(printf '\xfe\xff'; be 'first line'; printf '\0\n\x30\xad\x30\xfc\x30\x6f'; be "$key"; printf '\0\n')
u16 be 2 < <(be 'first line'; printf '\0\n\x30\xad\x30\xfc\x30\x6f'; be "$key"; printf '\0\n')
u16 odd-offset 1 < <(printf '\x7f\xad\x30\xfc\x30\x6f\x30'; le "$key")
u16 bracket 2 < <(printf '\xff\xfe\x0a\x30'; le "$key"; printf '\x0b\x30')
u16 odd-length 1 < <(printf '\xff\xfe\xad\x30\xfc\x30\x6f\x30'; le "$key"; printf 'Z')
# A .env written by PowerShell's ">": the byte-order mark stands before the name on the first line, and the pattern
# reads a name only from the line's start, so only the decoded reading, which drops the mark, finds it.
u16 env-bom 1 assigned-secret < <(printf '\xff\xfe'; le "MY_API_TO${q}KEN=$(m 40)"; printf '\n\0')
# The same with a tab after "export": a tab is kept, as the pattern reads it as a space.
u16 env-tab 1 assigned-secret < <(printf '\xff\xfe'; le "export	MY_API_TO${q}KEN=$(m 40)"; printf '\n\0')
# Letters before the kana: the kana must still end a word, not vanish ("ab" then the key would read "absk-ant").
u16 word-kana 1 < <(printf '\xff\xfe'; le 'ab'; printf '\xad\x30'; le "$key")
# Big endian at an odd offset, は right before the key.
u16 be-odd-offset 1 < <(printf '\x7f\x30\xad\x30\x6f'; be "$key")
# One long line, decoded in 64 KiB pieces: the key starts at byte 65530 and runs across the first piece's end, so
# it is found only if the pieces join up in order.
u16 long 1 < <(printf '\xff\xfe'; le "$(printf '%32763s' '')"; printf '\xad\x30'; le "$key")
# 2,000 lines of plain text, then the UTF-16 key: the first NUL is 124 KB in, past the buffer grep judges a file
# by, so the file is read whole to learn that it holds one.
u16 late 2001 < <(for i in $(seq 1 2000); do echo "an ordinary line of plain text number $i padded out a little"; done; printf '\xad\x30'; le "$key"; printf '\n\0')
# A file whose name starts with "-": decoding it must not read its name as a switch ("-v" would skip it, "-e..."
# would run the name as code).
u16 -v 2 < <(printf '\xff\xfe'; le 'first line'; printf '\n\0\xad\x30\xfc\x30\x6f\x30'; le "$key"; printf '\n\0')

# 4e. Bytes that are not valid UTF-16 neither stop the scan nor hide a key another reading finds: a lone surrogate
# right before a key (taking the NULs out finds it), and a blob of every byte value, which is clean.
u16 surrogate 1 < <(printf '\xff\xfe\x00\xd8'; le "$key")
r=$T/blob; newrepo "$r"
every=$(for b in $(seq 0 255); do printf '\\%03o' "$b"; done)
printf "$every$every$every$every" > "$r/all.bin"; git -C "$r" add all.bin
run "$r"; if [ "$rc" = 0 ]; then ok; else bad "a blob of every byte value was not clean (rc=$rc): $out"; fi

# 5. What can't be scanned is exit 2, never clean.
run "$r" no-such-commit; if [ "$rc" = 2 ]; then ok; else bad "an unknown BASE gave rc=$rc, wanted 2"; fi
mkdir "$T/norepo"; run "$T/norepo"; if [ "$rc" = 2 ]; then ok; else bad "outside a repo gave rc=$rc, wanted 2"; fi
r=$T/gone; newrepo "$r"; printf 'x\n' > "$r/a.txt"; printf 'y\n' > "$r/b.txt"; git -C "$r" add -A; rm "$r/b.txt"
run "$r"; if [ "$rc" = 2 ]; then ok; else bad "a tracked file missing from the tree gave rc=$rc, wanted 2"; fi
# Root reads any file, so the unreadable case can only be checked as another user.
if [ "$(id -u)" != 0 ]; then
  printf 'y\n' > "$r/b.txt"; chmod 000 "$r/b.txt"
  run "$r"; if [ "$rc" = 2 ]; then ok; else bad "a tracked file that can't be read gave rc=$rc, wanted 2"; fi
  chmod 644 "$r/b.txt"
fi

# 6. This file and the scanner are clean under the scan themselves.
r=$T/self; newrepo "$r"; mkdir "$r/scripts"; cp "$scan" "${BASH_SOURCE[0]}" "$r/scripts/"; git -C "$r" add -A
run "$r"; if [ "$rc" = 0 ]; then ok; else bad "the scanner or its test trips the scan: $out"; fi

# A positive control on the checks themselves: with no made-up key ever reported, sections 1 to 4 proved nothing.
[ "$n" -ge 23 ] || setup "the list of made-up keys came through short ($n)"
echo "scan-secrets.test.sh: $pass passed, $fail failed"
[ "$fail" = 0 ]
