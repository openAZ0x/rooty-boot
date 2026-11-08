# shellcheck shell=bash
# tests/lib.sh - tiny assertion helpers for run-tests.sh (sourced).
# Usage: ok NAME / fail NAME DETAIL / skip NAME REASON, then finish.

TESTS_RUN=0
TESTS_FAILED=0
TESTS_SKIPPED=0
_FAILURES=()

ok() {
  TESTS_RUN=$((TESTS_RUN + 1))
  printf 'ok   %s\n' "$1"
}

fail() {
  TESTS_RUN=$((TESTS_RUN + 1))
  TESTS_FAILED=$((TESTS_FAILED + 1))
  _FAILURES+=("$1")
  printf 'FAIL %s: %s\n' "$1" "${2:-no detail}"
}

skip() {
  TESTS_RUN=$((TESTS_RUN + 1))
  TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
  printf 'skip %s (%s)\n' "$1" "${2:-unavailable}"
}

finish() {
  printf -- '\n%d run, %d failed, %d skipped\n' \
    "$TESTS_RUN" "$TESTS_FAILED" "$TESTS_SKIPPED"
  if (( TESTS_FAILED > 0 )); then
    printf 'failed: %s\n' "${_FAILURES[*]}"
    exit 1
  fi
  exit 0
}

# want_file NAME PATH  - assert a regular file exists and is non-empty
want_file() {
  if [[ -s "$2" ]]; then ok "$1"; else fail "$1" "missing or empty: $2"; fi
}

# want_no_file NAME PATH - assert absence
want_no_file() {
  if [[ -e "$2" ]]; then fail "$1" "unexpectedly present: $2"; else ok "$1"; fi
}

# want_contains NAME NEEDLE FILE...
want_contains() {
  local n="$1" s="$2"; shift 2
  if grep -qF -- "$s" "$@" 2>/dev/null; then ok "$n"; else fail "$n" "'$s' not found in $*"; fi
}
