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
# the range short, a tracked file that is missing or can't be read, a grep that does not behave as the scan reads
# it, or no perl to decode UTF-16), which says nothing about the tree.
# scripts/scan-secrets.test.sh checks it offline, one made-up key per pattern: run it after any change here.
# `command grep` bypasses any shell function named grep (Claude Code defines one that honours .gitignore).
set -u
# Bytes, not characters, and every file as text (grep -a): a key inside a file that holds a NUL byte is still a key,
# and under a UTF-8 locale grep takes a line with one invalid byte for binary and prints nothing, though it matched.
# Text saved as UTF-16 (what PowerShell 5's ">" writes) has a NUL byte beside every character, so no pattern matches
# its bytes as they are: a file that holds NUL bytes is read a second time with them taken out, and so is the history.
# Taking them out is not enough when a character that is not ASCII stands right before a key: its other byte is left
# against the key (キーは then "sk-ant..." reads "...0sk-ant..."). So such a file, and the history, is read a third time,
# decoded (u16 below). Each reading only adds what it finds; none replaces another.
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
# any kebab-case word ending in sk (task-list-...). sk-key itself starts at the line's start or after a character
# that is not a letter, digit, "_" or "-", so a name like task-<32 hex digits> is not a key.
# aws-access-key-id: AKIA is a long-lived key's id, ASIA a temporary one's (STS, an assumed role).
# aws-secret-access-key: the line an AWS credentials file or env file gives the secret on, in either case, with or
# without spaces around its "=" or ":"; assigned-secret can't see it (lower case, and the value holds "/").
# x-bearer: an app's bearer token is 21 A's, then text with a URL-encoded or plain "=" in its middle. The "=" is what
# tells it from base64 of zero bytes (AAAA... in any embedded image), where "=" only ever ends the text.
# assigned-secret: a line shaped like an env file's, NAME=value from the line's start (or after "export"), where the
# UPPER_CASE name holds TOKEN, SECRET, PASSWORD, API_KEY or PRIVATE_KEY and the value starts with 32 or more
# characters that are not a slash, space or "$", and no "/" or "$" follows them. Narrow on purpose: prose, code, a
# quoted example in a README, a path, a URL, another variable or a short placeholder is not reported, so a hit is
# worth reading. Any run of spaces, tabs and "+" may come first: an indented line, and the "+" a commit's diff puts
# before each line it adds, whatever that line itself starts with.
names=(hq-key pem-private-key github-token github-pat aws-access-key-id aws-secret-access-key sk-key anthropic-key openai-key stripe-key
  slack-token google-api-key telegram-bot-token google-oauth-token google-refresh-token x-bearer assigned-secret
  jwk-private-d)
res=(
  'uhq_[A-Za-z0-9]{6,}_[A-Za-z0-9]{16,}'
  '-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----'
  'gh[pousr]_[A-Za-z0-9]{30,}'
  'github_pat_[A-Za-z0-9_]{30,}'
  '(AKIA|ASIA)[0-9A-Z]{16}'
  '[Aa][Ww][Ss]_[Ss][Ee][Cc][Rr][Ee][Tt]_[Aa][Cc][Cc][Ee][Ss][Ss]_[Kk][Ee][Yy]["'"'"']?[[:space:]]*[=:][[:space:]]*["'"'"']?[A-Za-z0-9/+]{40}'
  '(^|[^A-Za-z0-9_-])sk-[A-Za-z0-9]{20,}'
  '\bsk-ant-[A-Za-z0-9_-]{20,}'
  '\bsk-(proj|svcacct|admin)-[A-Za-z0-9_-]{20,}'
  '\bsk_(live|test)_[A-Za-z0-9]{16,}'
  '\bxox[abprs]-[A-Za-z0-9-]{10,}'
  'AIza[0-9A-Za-z_-]{30,}'
  '\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}'
  '\bya29\.[A-Za-z0-9_-]{30,}'
  '\b1//0[A-Za-z0-9_-]{40,}'
  'AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%+/]{15,}(%3D|=)[A-Za-z0-9%]{20,}'
  '^[+[:space:]]*(export[[:space:]]+)?[A-Z0-9_]*(TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*=["'"'"']?[A-Za-z0-9_+=-]{32,}([^A-Za-z0-9_+=/$-]|$)'
  "$jwk"
)

# u16 IN OUT: IN read as UTF-16, written to OUT.0 to OUT.3, one line out for each line in, so a line number in any of
# them is that line of IN. The lines are IN's own, split at each newline byte as grep splits them; in UTF-16 text a
# character whose code holds that byte (《 is U+300A) splits a line too, in every reading alike.
# Four readings of each line, because which bytes pair up is not known: little endian (OUT.0, OUT.1) and big endian
# (OUT.2, OUT.3), each from the line's first byte and from its second. A byte-order mark says nothing about a line
# after the first; the newline's other byte starts the next line; a diff puts "+" before each line it adds; and text
# can start at an odd offset inside a binary file.
# Keys are ASCII, so only ASCII needs to survive: a printable character or a tab is kept, a byte-order mark is
# dropped, and anything else (kana, a surrogate, a control character) becomes one \x01 byte, which no pattern takes
# into a key and which ends a word as the character it stands for does. A last odd byte is left out. Nothing here can
# fail on the bytes it is given; a read or write that fails is an error, never an early end.
# The cost, accepted: a reading with the wrong pairing can fold the letter after a character that is not ASCII into
# its \x01, so contrived text ("キask-" and 32 hex digits) can read as a key there. None did in the org's 35 repos or in
# 4,800 real binaries (fonts, images, libraries, firmware); a false hit is reported, never a key hidden.
# A line is decoded only if it holds 8 ASCII characters in a row as UTF-16 does (each beside a NUL): every pattern
# needs at least that many, and most binary data has none, so its lines come out empty. perl-base is enough (unpack).
# A line is decoded in 64 KiB pieces, each written out at once: unpack makes a list of every code unit, and one long
# line passing that test would otherwise cost some 65 bytes of memory per byte of it (a 16 MB line took 1 GB).
# Every call passes "--" first: a tracked file's name can start with "-", and perl would take it for a switch (one
# named "-e..." runs code).
u16=$(cat <<'EOF'
my ($in, $out) = @ARGV;
open(my $fh, '<:raw', $in) or die "can't read $in\n";
my @o;
for my $i (0 .. 3) { open($o[$i], '>:raw', "$out.$i") or die "can't write $out.$i\n" }
$/ = "\n";
my $piece = 65536;
while (my $line = <$fh>) {
  chomp $line;
  if ($line =~ /(?:[\t\x20-\x7e]\x00){8}|(?:\x00[\t\x20-\x7e]){8}/) {
    my $i = 0;
    for my $order ('v', 'n') {
      for my $at (0, 1) {
        for (my $k = $at; $k < length($line); $k += $piece) {
          print { $o[$i] } join '', map { $_ == 0xfeff ? '' : ($_ == 9 || ($_ >= 0x20 && $_ < 0x7f)) ? chr($_) : "\x01" }
            unpack("$order*", substr($line, $k, $piece));
        }
        $i++;
      }
    }
  }
  print { $o[$_] } "\n" for 0 .. 3;
}
close($fh) or die "can't read $in\n";
for (@o) { close($_) or die "can't write $out\n" }
EOF
)
# nul: of the NUL-ended file names on stdin, print those whose file holds a NUL byte anywhere, read whole. grep -L -I
# judges a file by its first buffer (some 96 KB), so text that starts plain and holds UTF-16 further on was never
# read a second or third time (a review measured a key at line 2001 of a 125 KB file reading clean). A symlink or a
# directory is skipped; a file that can't be opened or read is printed, so the read that follows fails loudly.
nul=$(cat <<'EOF'
$/ = "\0";
while (my $f = <STDIN>) {
  chomp $f;
  next if -l $f || -d _;
  my $has = 1;
  if (open(my $fh, '<:raw', $f)) {
    my ($n, $buf);
    $has = 0;
    while ($n = read($fh, $buf, 1 << 20)) { if (index($buf, "\0") >= 0) { $has = 1; last } }
    $has = 1 unless defined $n;
    close($fh);
  }
  print "$f\0" if $has;
}
EOF
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
[ "$(command grep -ahnE -e 'pro+be' "$work/probe" "$work/probe" 2>/dev/null | cut -d: -f1 | tr '\n' ' ')" = '1 1 ' ] ||
  setup "this grep does not answer -ahnE over two files the way the scan reads it"
for i in "${!res[@]}"; do
  command grep -qE -e "${res[$i]}" "$work/probe" 2>/dev/null; [ $? -le 1 ] || setup "this grep rejects the ${names[$i]} pattern"
done
# And nul is shown to tell a file that holds a NUL byte from one that does not, the NUL early or 200 KB in.
printf 'a\0b\n' > "$work/probe0"
{ head -c 200000 /dev/zero | tr '\0' 'a'; printf '\n\0\n'; } > "$work/probe0late"
got=$(printf '%s\0' "$work/probe" "$work/probe0" "$work/probe0late" | perl -e "$nul" 2>/dev/null | tr '\0' '|')
[ "$got" = "$work/probe0|$work/probe0late|" ] || setup "perl did not tell the files holding a NUL byte (perl is needed)"
# And u16 is shown to decode: "probeprobe" as UTF-16 on a second line, which starts with the first line's NUL, as
# every line after the first of little-endian text does. Two of its four readings carry it, at line 2.
printf 'x\n\0p\0r\0o\0b\0e\0p\0r\0o\0b\0e\0\n' > "$work/probe16"
perl -e "$u16" -- "$work/probe16" "$work/probe16.out" 2>/dev/null || setup "perl did not run the UTF-16 reading (perl is needed)"
got=$(command grep -ahn -e 'probeprobe' "$work/probe16.out".{0..3} 2>/dev/null | cut -d: -f1 | tr '\n' ' ')
[ "$got" = '2 2 ' ] || setup "the UTF-16 reading did not decode its probe"

# Every tracked file must be there to read: grep's own complaint about one it can't open is not seen below, and a
# file skipped is not a file found clean. A symlink is its target's name, not text, and a submodule is a directory.
while IFS= read -r -d '' file; do
  if [ -L "$file" ] || [ -d "$file" ]; then continue; fi
  [ -f "$file" ] || setup "tracked file '$file' is missing from the working tree"
  [ -r "$file" ] || setup "tracked file '$file' can't be read"
done < <(git ls-files -z)

# The tree: grep -Z ends each file name with a NUL, so a name holding a colon or a newline comes through whole, and
# only the line number is kept from what follows it. xargs runs grep the program, never a shell function.
for i in "${!res[@]}"; do
  while IFS= read -r -d '' file && IFS= read -r rest; do
    printf '  %s:%s: %s\n' "$file" "${rest%%:*}" "${names[$i]}" >> "$work/hits"
  done < <(git ls-files -z | xargs -0 -r grep -HanZE -e "${res[$i]}" -- 2>/dev/null)
done
# The tree again, for each file that holds a NUL byte, with the NULs taken out (UTF-16 text then reads as plain text,
# line for line) and decoded (u16), both searched at once: every one keeps the file's line numbers. Which files hold a
# NUL is read whole (nul), not judged by grep's first buffer.
while IFS= read -r -d '' file; do
  if [ -L "$file" ] || [ ! -s "$file" ]; then continue; fi
  tr -d '\000' < "$file" > "$work/flat" || setup "can't read '$file'"
  perl -e "$u16" -- "$file" "$work/flat16" || setup "can't decode '$file'"
  for i in "${!res[@]}"; do
    while IFS= read -r n; do
      printf '  %s:%s: %s\n' "$file" "$n" "${names[$i]}" >> "$work/hits"
    done < <(command grep -ahnE -e "${res[$i]}" "$work/flat" "$work/flat16".{0..3} | cut -d: -f1)
  done
done < <(git ls-files -z | perl -e "$nul")

# The range: each line a commit adds, as "<log line> TAB <commit> TAB <file> TAB <line in the new file>", from the
# hunk headers and their counts (git quotes a path holding a tab). A content line is told from a file header by the
# hunk's remaining counts, so an added line reading "++ b/x" (shown as "+++ b/x") stays content, and an empty line
# is context (diff.suppressBlankEmpty prints one so). A merge is read as its diff against its first parent.
# --text: a binary file's change is printed as lines too, not as "Binary files differ". The NUL bytes are taken out
# of the whole log, so a line of UTF-16 text reads as plain text here as well; the line count is unchanged. Both logs
# are searched, as the tree's files are: a NUL can be the byte that ends the word before a key, and taking it out
# closes the gap the pattern needs ("Z", NUL, "sk-..." reads "Zsk-..."). The log decoded (u16) is searched as well,
# for UTF-16 text where a character that is not ASCII stands before the key; it keeps the log's line numbers too.
if [ -n "$base" ]; then
  git log -p --text --no-color --no-ext-diff --no-textconv --no-renames --diff-merges=first-parent \
    --src-prefix=a/ --dst-prefix=b/ --format='commit %H' "$range" > "$work/log.raw" || setup "git log failed on $range"
  tr -d '\000' < "$work/log.raw" > "$work/log" || setup "can't read the log of $range"
  perl -e "$u16" -- "$work/log.raw" "$work/log16" || setup "can't decode the log of $range"
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
    command grep -ahnE -e "${res[$i]}" "$work/log.raw" "$work/log" "$work/log16".{0..3} | cut -d: -f1 > "$work/at"
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
