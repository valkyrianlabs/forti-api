#!/usr/bin/env bash
# Install the release formula from a throwaway local tap, pointing it at the locally built source
# archive (file://), then run `brew test`. Proves the formula installs and works before it ever
# reaches valkyrianlabs/homebrew-tap. Expects `vlr` on PATH; run it in a disposable checkout:
# `vlr prepare` rewrites the release documents (bumping the version first when unreleased).
set -euo pipefail

phase="$(vlr status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["phase"])')"
if [ "$phase" = unbumped ]; then vlr version bump minor >/dev/null; fi
vlr prepare >/dev/null
vlr source-archive
formula="$(vlr homebrew formula --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["path"])')"
version="$(vlr version show)"
archive="$PWD/release/forti-api-${version}.tar.gz"

tap="forti-api-ci/local"
brew untap "$tap" >/dev/null 2>&1 || true
brew tap-new --no-git "$tap"
tap_formula="$(brew --repository "$tap")/Formula/forti-api.rb"
trap 'brew uninstall --formula "$tap/forti-api" >/dev/null 2>&1 || true; brew untap "$tap" >/dev/null 2>&1 || true' EXIT

# Style-check the exact formula that will be published, as a tap formula.
cp "$formula" "$tap_formula"
brew style "$tap/forti-api"

# Then install it from the locally built archive and run its test block.
sed -E "s#^  url \".*\"#  url \"file://${archive}\"#" "$formula" > "$tap_formula"
export HOMEBREW_NO_AUTO_UPDATE=1
brew install --build-from-source "$tap/forti-api"
brew test "$tap/forti-api"
ls "$(brew --prefix)/include/forti_api/client.hpp" "$(brew --prefix)/share/pkgconfig/forti-api.pc"
