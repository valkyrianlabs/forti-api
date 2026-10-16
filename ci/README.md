# CI container

forti-api's Linux CI and release jobs run on the self-hosted VPS runner, every step inside a
disposable, rootless Podman container: the runner needs no host sudo, host packages or Docker.
The conventions are shared with the other ValkyrianLabs repositories on the runner; the full
description is in [payload-markdown's `ci/README.md`](https://github.com/valkyrianlabs/payload-markdown/blob/main/ci/README.md).

- `ci/run-ci` is copied from payload-markdown (it is repository-agnostic); update it there and copy
  it back. Its container memory limit is the tightest cgroup limit above the runner minus 1 GiB (as in
  forti-cli's copy): a container sized past the CI slice's `MemoryHigh` makes the kernel reclaim
  instead of OOM-killing, and the whole slice thrashes.
- `ci/build-jobs` prints how many compile jobs fit: every core the container memory allows, at
  1.2 GB per job (the largest unit-suite TU with GCC and ASan), or the budget given in MB
  (`ci/build-jobs 2400` for the exhaustive build's shards of typed models). Builds use
  `-j "$(ci/build-jobs)"`.
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
