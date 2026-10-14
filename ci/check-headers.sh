#!/usr/bin/env bash
# Compiles every public header on its own (-Wall -Wextra -Wpedantic -Werror), so a header that is
# never included elsewhere cannot rot unnoticed.  Usage: ci/check-headers.sh [header-or-dir...]
set -euo pipefail
cd "$(dirname "$0")/.."
CXX=${CXX:-c++}
targets=("$@")
[ ${#targets[@]} -gt 0 ] || targets=(include)
failed=0
count=0
while IFS= read -r header; do
  count=$((count + 1))
  rel=${header#include/}
  if ! printf '#include <%s>\nint main() {}\n' "$rel" |
       "$CXX" -std=c++23 -Wall -Wextra -Wpedantic -Werror -fsyntax-only \
         -Iinclude -Ithird_party/nlohmann/include $(pkg-config --cflags libcurl 2>/dev/null) -x c++ -; then
    echo "FAIL: $rel" >&2
    failed=1
  fi
done < <(find "${targets[@]}" \( -name '*.hpp' -o -name '*.h' \) | sort)
echo "checked $count headers"
exit $failed
