#!/usr/bin/env bash
# Compiles every hand-written public header on its own (-Wall -Wextra -Wpedantic -Werror), so a
# header that is never included elsewhere cannot rot unnoticed. In parallel (JOBS, default: CPU count).
#   ci/check-headers.sh            the hand-written headers (what CI runs)
#   ci/check-headers.sh --all      every header, generated ones included (~600 compiler runs)
#   ci/check-headers.sh PATH...    the given headers or directories
# The generated headers (include/forti_api/gen) come from one template: `tools/fortios/fortios.py check`
# proves they are exactly what the generator writes, and the build compiles all of them (gen/all.hpp,
# gen/schema.hpp), so checking each alone in CI would only repeat that ~600 times.
set -euo pipefail
cd "$(dirname "$0")/.."
export CXX=${CXX:-c++}
export CURL_CFLAGS=$(pkg-config --cflags libcurl 2>/dev/null || true)
jobs=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}
check_one() {
  local rel=${1#include/}
  printf '#include <%s>\nint main() {}\n' "$rel" |
    "$CXX" -std=c++23 -Wall -Wextra -Wpedantic -Werror -fsyntax-only \
      -Iinclude -Ithird_party/nlohmann/include $CURL_CFLAGS -x c++ - || { echo "FAIL: $rel" >&2; return 1; }
}
export -f check_one
if [ "${1:-}" = --all ]; then
  list=$(find include \( -name '*.hpp' -o -name '*.h' \) | sort)
elif [ $# -gt 0 ]; then
  list=$(find "$@" \( -name '*.hpp' -o -name '*.h' \) | sort)
else
  list=$(find include -path include/forti_api/gen -prune -o \( -name '*.hpp' -o -name '*.h' \) -print | sort)
fi
count=$(printf '%s\n' "$list" | grep -c . || true)
printf '%s\n' "$list" | xargs -P "$jobs" -I{} bash -c 'check_one "$@"' _ {}
echo "checked $count headers"
