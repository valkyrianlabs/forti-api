# CI container

forti-api's Linux CI and release jobs run on the self-hosted VPS runner, every step inside a
disposable, rootless Podman container: the runner needs no host sudo, host packages or Docker.
The conventions are shared with the other ValkyrianLabs repositories on the runner; the full
description is in [payload-markdown's `ci/README.md`](https://github.com/valkyrianlabs/payload-markdown/blob/main/ci/README.md).

- `ci/run-ci` is copied **verbatim** from payload-markdown (it is repository-agnostic); update it
  there and copy it back.
- `ci/Containerfile`: Ubuntu 24.04 (pinned by digest) with meson, ninja, g++, libcurl,
  GoogleTest, dpkg-dev, debhelper, gh and vl-release.
- Workflows set `defaults.run.shell: bash ./ci/run-ci bash -euo pipefail {0}` on their Linux jobs.
  Clean-install checks of the `.deb` use a stock image instead:
  `./ci/run-ci --image "$UBUNTU_IMAGE" --root bash -c 'apt-get install -y ./release/…'`.
- `ci/consumer.cpp` is compiled against the *installed* package to prove the headers, the
  vendored nlohmann/json and `forti-api.pc` work outside the source tree.

Build locally the way CI does (needs Podman):

```sh
./ci/run-ci bash -c 'meson setup build/ci -Dtests=enabled -Dwerror=true && meson compile -C build/ci'
```
