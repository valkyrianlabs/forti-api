#!/usr/bin/env bash
# Compiles every public header on its own (-Wall -Wextra -Wpedantic -Werror), so a header that is
# never included elsewhere cannot rot unnoticed. In parallel (JOBS, default: CPU count).
#   ci/check-headers.sh [header-or-dir...]
set -euo pipefail
cd "$(dirname "$0")/.."
export CXX=${CXX:-c++}
export CURL_CFLAGS=$(pkg-config --cflags libcurl 2>/dev/null || true)
jobs=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}
targets=("$@")
[ ${#targets[@]} -gt 0 ] || targets=(include)
check_one() {
  local rel=${1#include/}
  printf '#include <%s>\nint main() {}\n' "$rel" |
    "$CXX" -std=c++23 -Wall -Wextra -Wpedantic -Werror -fsyntax-only \
      -Iinclude -Ithird_party/nlohmann/include $CURL_CFLAGS -x c++ - || { echo "FAIL: $rel" >&2; return 1; }
}
export -f check_one
list=$(find "${targets[@]}" \( -name '*.hpp' -o -name '*.h' \) | sort)
count=$(printf '%s\n' "$list" | grep -c . || true)
printf '%s\n' "$list" | xargs -P "$jobs" -I{} bash -c 'check_one "$@"' _ {}
echo "checked $count headers"
