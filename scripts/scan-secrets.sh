#!/usr/bin/env bash
# Refuse a tree that carries a credential, and with a base, the commits since it. Patterns, not a vendor tool: readable
# by every agent here.
#
#   scripts/scan-secrets.sh          the tracked files (the index's list, the working tree's bytes)
#   scripts/scan-secrets.sh BASE     those, and every line a commit in BASE..HEAD adds: a key committed and then
#                                    removed inside a pull request leaves its tree clean and stays in its history
#   scripts/scan-secrets.sh --history   those, and every line any commit behind HEAD adds, the first commit included
#
# A hit names the file, the line and the pattern, never the text: that line holds the credential, and printing it
# would put the key into the CI log or the session transcript that the scan just kept it out of git for.
# Exit 0 clean, 1 a hit, 2 the scan could not run (no repo, BASE not a commit here, a shallow history that cuts
# the range short, or a grep that does not behave as the scan reads it), which says nothing about the tree.
# scripts/scan-secrets.test.sh checks it offline, one made-up key per pattern: run it after any change here.
# `command grep` bypasses any shell function named grep (Claude Code defines one that honours .gitignore).
set -u
# Bytes, not characters, and every file as text (grep -a): a key inside a file that holds a NUL byte is still a key,
# and under a UTF-8 locale grep takes a line with one invalid byte for binary and prints nothing, though it matched.
export LC_ALL=C
setup() { echo "scan-secrets: $*: nothing was scanned" >&2; exit 2; }
[ $# -le 1 ] || setup "usage: scan-secrets.sh [BASE]"
top=$(git rev-parse --show-toplevel 2>/dev/null) || setup "not inside a git repository"
cd "$top" || setup "can't enter $top"

# A private JWK's "d" member in any spelling: JSON with any whitespace, an escaped JSON string inside JSON,
# a JS/TS object literal, single quotes. Read from a quoted heredoc so no quote needs escaping here.
jwk=$(cat <<'EOF'
(\\?["']d\\?["']|\bd)[[:space:]]*:[[:space:]]*\\?["'][A-Za-z0-9_-]{40,}
EOF
)
# Each pattern by the name a hit reports. GitHub's token prefixes: ghp_ classic, gho_ OAuth (what `gh auth login`
# stores), ghu_ user-to-server, ghs_ server-to-server, ghr_ refresh; github_pat_ fine-grained.
# sk-key alone misses today's vendor keys: a hyphen follows their prefix (sk-ant-api03-, sk-proj-), and that
# breaks its run of 20. Their own patterns are tied to the prefix, since a bare sk- that allowed hyphens would match
# any kebab-case word ending in sk (task-list-...).
# x-bearer: an app's bearer token is 21 A's, then text with a URL-encoded or plain "=" in its middle. The "=" is what
# tells it from base64 of zero bytes (AAAA... in any embedded image), where "=" only ever ends the text.
# assigned-secret: a line shaped like an env file's, NAME=value from the line's start (or after "export"), where the
# UPPER_CASE name holds TOKEN, SECRET, PASSWORD, API_KEY or PRIVATE_KEY and the value is 32 or more characters with
# no dot, slash, space or "$". Narrow on purpose: prose, code, a quoted example in a README, a path, a URL, another
# variable or a short placeholder is not reported, so a hit is worth reading. The optional "+" is how the line
# reads in a commit's diff.
names=(hq-key pem-private-key github-token github-pat aws-access-key-id sk-key anthropic-key openai-key stripe-key
  slack-token google-api-key telegram-bot-token google-oauth-token google-refresh-token x-bearer assigned-secret
  jwk-private-d)
res=(
  'uhq_[A-Za-z0-9]{6,}_[A-Za-z0-9]{16,}'
  '-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----'
  'gh[pousr]_[A-Za-z0-9]{30,}'
  'github_pat_[A-Za-z0-9_]{30,}'
  'AKIA[0-9A-Z]{16}'
  'sk-[A-Za-z0-9]{20,}'
  '\bsk-ant-[A-Za-z0-9_-]{20,}'
  '\bsk-(proj|svcacct|admin)-[A-Za-z0-9_-]{20,}'
  '\bsk_(live|test)_[A-Za-z0-9]{16,}'
  '\bxox[abprs]-[A-Za-z0-9-]{10,}'
  'AIza[0-9A-Za-z_-]{30,}'
  '\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}'
  '\bya29\.[A-Za-z0-9_-]{30,}'
  '\b1//0[A-Za-z0-9_-]{40,}'
  'AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%+/]{15,}(%3D|=)[A-Za-z0-9%]{20,}'
  '^[+ ]?(export[[:space:]]+)?[A-Z0-9_]*(TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*=["'"'"']?[A-Za-z0-9_+=-]{32,}'
  "$jwk"
)

# range: what git log reads. "BASE..HEAD" for a base, "HEAD" for the whole history (git log shows the first commit's
# files as added, so a key in a rewritten first commit is read too).
base= range=
if [ $# = 1 ]; then
  if [ "$1" = --history ]; then
    git rev-parse --verify --quiet 'HEAD^{commit}' >/dev/null || setup "no commit to read a history from"
    base=the-first-commit range=HEAD
  else
    case $1 in -*) setup "BASE '$1' looks like an option, not a commit" ;; esac
    base=$(git rev-parse --verify --quiet "$1^{commit}") || setup "BASE '$1' is not a commit in this repository (fetch it first)"
    range=$base..HEAD
  fi
  # A shallow commit inside the range stands in for history that is not here, and its diff would read as the whole
  # tree's; CI's default checkout is one commit deep.
  revs=$(git rev-list "$range") || setup "can't list the commits in $range"
  shallow=$(git rev-parse --git-path shallow)
  if [ -s "$shallow" ] && command grep -qFxf "$shallow" <<<"$revs"; then
    setup "the history is shallow inside $range: fetch it whole (actions/checkout fetch-depth: 0) and rerun"
  fi
fi
work=$(mktemp -d "${TMPDIR:-/tmp}/scan-secrets.XXXXXX") || setup "can't create a scratch directory"
trap 'rm -rf "$work"' EXIT
: > "$work/hits"

# The loops below can't tell "grep found nothing" from "grep did not run": they read its output and drop its status.
# So grep is shown to work first, through the same two calls, on a line it must find; and to take every pattern.
printf 'probe\n' > "$work/probe"
got=$(printf '%s\0' "$work/probe" | xargs -0 -r grep -HanZE -e 'pro+be' -- 2>/dev/null | tr '\0' '|')
[ "$got" = "$work/probe|1:probe" ] || setup "this grep does not answer -HanZE the way the scan reads it (GNU grep is needed)"
[ "$(command grep -anE -e 'pro+be' "$work/probe" 2>/dev/null | cut -d: -f1)" = 1 ] || setup "this grep does not answer -anE the way the scan reads it"
for i in "${!res[@]}"; do
  command grep -qE -e "${res[$i]}" "$work/probe" 2>/dev/null; [ $? -le 1 ] || setup "this grep rejects the ${names[$i]} pattern"
done

# The tree: grep -Z ends each file name with a NUL, so a name holding a colon or a newline comes through whole, and
# only the line number is kept from what follows it. xargs runs grep the program, never a shell function.
for i in "${!res[@]}"; do
  while IFS= read -r -d '' file && IFS= read -r rest; do
    printf '  %s:%s: %s\n' "$file" "${rest%%:*}" "${names[$i]}" >> "$work/hits"
  done < <(git ls-files -z | xargs -0 -r grep -HanZE -e "${res[$i]}" -- 2>/dev/null)
done

# The range: each line a commit adds, as "<log line> TAB <commit> TAB <file> TAB <line in the new file>", from the
# hunk headers and their counts (git quotes a path holding a tab). A content line is told from a file header by the
# hunk's remaining counts, so an added line reading "++ b/x" (shown as "+++ b/x") stays content, and an empty line
# is context (diff.suppressBlankEmpty prints one so). A merge is read as its diff against its first parent.
# --text: a binary file's change is printed as lines too, not as "Binary files differ".
if [ -n "$base" ]; then
  git log -p --text --no-color --no-ext-diff --no-textconv --no-renames --diff-merges=first-parent \
    --src-prefix=a/ --dst-prefix=b/ --format='commit %H' "$range" > "$work/log" || setup "git log failed on $range"
  awk 'BEGIN { OFS = "\t" }
    old <= 0 && new <= 0 && /^commit [0-9a-f]+$/ { sha = substr($2, 1, 12); next }
    old <= 0 && new <= 0 && /^\+\+\+ / {
      path = substr($0, 5)
      if (path ~ /^b\//) path = substr(path, 3); else if (path ~ /^"b\//) path = "\"" substr(path, 4)
      next
    }
    old <= 0 && new <= 0 && /^@@ / {
      k = split($2, o, ","); old = (k > 1) ? o[2] + 0 : 1
      k = split($3, w, ","); line = substr(w[1], 2) + 0; new = (k > 1) ? w[2] + 0 : 1
      next
    }
    old > 0 || new > 0 {
      c = substr($0, 1, 1)
      if (c == "+") { print NR, sha, path, line; line++; new-- }
      else if (c == "-") old--
      else if (c == " " || $0 == "") { line++; old--; new-- }
    }' "$work/log" > "$work/added"
  for i in "${!res[@]}"; do
    command grep -anE -e "${res[$i]}" "$work/log" | cut -d: -f1 > "$work/at"
    [ -s "$work/at" ] || continue
    awk -F '\t' -v name="${names[$i]}" 'FILENAME == ARGV[1] { hit[$1] = 1; next } $1 in hit { print "  commit " $2 " " $3 ":" $4 ": " name }' \
      "$work/at" "$work/added" >> "$work/hits"
  done
fi

if [ -s "$work/hits" ]; then
  {
    echo "scan-secrets: credential-shaped text at these places (file:line: pattern; never the text itself):"
    sort -u "$work/hits"
  } >&2
  exit 1
fi
if [ "$range" = HEAD ]; then echo "scan-secrets: clean (the tracked files, and every line any commit in the history adds)"
elif [ -n "$base" ]; then echo "scan-secrets: clean (the tracked files, and every line the commits since $base add)"
else echo "scan-secrets: clean"; fi
