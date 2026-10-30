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
system dependency.

:::callout[Requirements]{variant="info"}
A C++23 compiler is required; forti-api is tested with GCC 13 and 14 and with Apple Clang. Link
libcurl.
:::

## Install forti-api

Pick the method that fits your project: the APT package (Debian and Ubuntu), the Homebrew formula
(macOS and Linux), vendored headers, or a build from source.

:::tabs{
  default="apt"
  theme="glass"
  tabTheme="muted"
}

:::tab[APT (Debian, Ubuntu)]{value="apt"}
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

The packages depend on `valkyrianlabs-archive-keyring`, which installs the repository key at
`/usr/share/keyrings/valkyrianlabs.gpg` and keeps it current through normal upgrades (for example when its
expiry changes). When the key downloaded above is unmodified, the package replaces it with a symlink to the
packaged key, so the source line above keeps working and you never need to download the key again. Removing
the package turns the symlink back into a plain copy. Signing key fingerprint:
`494D 71A1 EEDD F87B D48E  5048 6D64 CB7B DFC3 0EC6`.

The package installs the headers to `/usr/include/forti_api` and a pkg-config file:

```bash
c++ -std=c++23 app.cpp $(pkg-config --cflags --libs forti-api)
```

With Meson, `dependency('forti-api')` finds it through pkg-config.
:::

:::tab[Homebrew (macOS, Linux)]{value="homebrew"}
```bash
brew install valkyrianlabs/tap/forti-api
```

The formula installs the headers and `forti-api.pc` into the Homebrew prefix; libcurl comes from the
system. Build with:

```bash
c++ -std=c++23 app.cpp $(pkg-config --cflags --libs forti-api)
```

:::callout[No tap or trust step]{variant="note"}
No `brew tap` or `brew trust` step: Homebrew trusts the formulae named in full on the command line.
:::
:::

:::tab[Vendoring]{value="vendoring"}
Copy `include/` and `third_party/nlohmann/include/` from the repository into your project, add
both to the include path and link libcurl (`-lcurl`).

Meson projects can also use forti-api as a subproject: `dependency('forti-api')` resolves to it.

:::callout[A subproject installs nothing]{variant="note"}
As a subproject, forti-api builds no example or tests and installs nothing, so `meson install` of
your project does not install forti-api's headers or `forti-api.pc`.
:::
:::

:::tab[From source]{value="source"}
```bash
# Ubuntu: sudo apt install meson ninja-build g++ pkgconf libcurl4-openssl-dev
# macOS:  brew install meson ninja       (libcurl comes with the SDK)
meson setup build
meson install -C build
```

The headers install to `<prefix>/include/forti_api` and `forti-api.pc` to
`<prefix>/share/pkgconfig`.
:::

:::

## Install locations

| Method | Headers | pkg-config file |
|---|---|---|
| APT | `/usr/include/forti_api` | installed; `pkg-config forti-api` |
| Homebrew | the Homebrew prefix | `forti-api.pc` in the Homebrew prefix |
| Vendoring | wherever you copy `include/` and `third_party/nlohmann/include/` | none |
| Meson subproject | not installed | not installed |
| From source | `<prefix>/include/forti_api` | `<prefix>/share/pkgconfig/forti-api.pc` |

## Next steps

:::cards{
  columns="2"
  cardTheme="muted"
}

:::card[Quick start]{href="/getting-started/quick-start"}
Connect to a FortiGate and read, change and create objects.
:::

:::card[Configuration]{href="/reference/configuration"}
Environment variables and `fortiapi::Config` fields.
:::

:::
