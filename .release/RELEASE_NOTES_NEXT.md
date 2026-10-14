# Native packages, no Conan

forti-api no longer uses Conan. It builds with Meson and ships as a Debian package from the
ValkyrianLabs APT repository.

- **Debian/Ubuntu:** `sudo apt install libforti-api-dev` (after adding
  `https://apt.valkyrianlabs.com`, see the README). It installs the headers to
  `/usr/include/forti_api` and `forti-api.pc`; build with
  `pkg-config --cflags --libs forti-api`.
- **Vendoring or from source (Linux or macOS):** copy `include/` and
  `third_party/nlohmann/include/`, or `meson setup build && meson install -C build`. libcurl is the
  only system dependency; nlohmann/json 3.12.0 ships with forti-api under
  `forti_api/third_party`, so it never conflicts with a system nlohmann-json.
- The headers include their siblings by relative path, so installed headers work from any include
  root, and compile cleanly with `-Wall -Wextra -Wpedantic -Werror` on GCC 13/14 and Apple Clang.
- New firewall VIP types (`types/firewall/vip.h`).
