---
title: Installation
description: Install forti-api from the APT repository, vendor it, or build it from source.
order: 10
status: published
tags:
  - getting-started
---

# Installation

forti-api is header-only. nlohmann/json 3.12.0 ships with it (installed under
`forti_api/third_party`, so it never conflicts with a system nlohmann-json); libcurl is the only
system dependency. A C++23 compiler is required; forti-api is tested with GCC 13 and 14 and with Apple Clang.

## Debian and Ubuntu

`libforti-api-dev` is published to the ValkyrianLabs APT repository:

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL https://apt.valkyrianlabs.com/pubkey.gpg \
  -o /etc/apt/keyrings/valkyrianlabs.gpg
sudo chmod 0644 /etc/apt/keyrings/valkyrianlabs.gpg

echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/valkyrianlabs.gpg] https://apt.valkyrianlabs.com stable main" | \
  sudo tee /etc/apt/sources.list.d/valkyrianlabs.list > /dev/null

sudo apt update
sudo apt install -y libforti-api-dev
```

The package installs the headers to `/usr/include/forti_api` and a pkg-config file:

```bash
c++ -std=c++23 app.cpp $(pkg-config --cflags --libs forti-api)
```

With Meson, `dependency('forti-api')` finds it through pkg-config.

## Homebrew (macOS and Linux)

```bash
brew install valkyrianlabs/tap/forti-api
```

Recent Homebrew versions ask you to trust a third-party tap first (`brew trust valkyrianlabs/tap`).
The formula installs the headers and `forti-api.pc` into the Homebrew prefix; libcurl comes from the
system. Build with `c++ -std=c++23 app.cpp $(pkg-config --cflags --libs forti-api)`.

## Vendoring

Copy `include/` and `third_party/nlohmann/include/` from the repository into your project, add
both to the include path and link libcurl (`-lcurl`). Meson projects can also use forti-api as a
subproject: `dependency('forti-api')` resolves to it.

## From source

```bash
# Ubuntu: sudo apt install meson ninja-build g++ pkgconf libcurl4-openssl-dev
# macOS:  brew install meson ninja       (libcurl comes with the SDK)
meson setup build
meson install -C build
```

The headers install to `<prefix>/include/forti_api` and `forti-api.pc` to
`<prefix>/share/pkgconfig`.
