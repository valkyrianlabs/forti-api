#!/usr/bin/env python3
"""FortiOS schema tooling for forti-api (Python 3.12+, standard library only).

  fortios.py pull [PATH...]   fetch cmdb schema snapshots (default: every path in codegen/api.toml)
  fortios.py crawl            discover cmdb paths by following datasource references from seeds
  fortios.py mine             catalog the API paths the device's web GUI uses (paths only, no code)
  fortios.py gen              regenerate include/forti_api/gen/** from the snapshots
  fortios.py check            fail if the generated headers differ from what gen would write

pull and crawl talk to a FortiGate with the same environment as the C++ client (FORTIGATE_HOST,
FORTIGATE_API_KEY, FORTIGATE_ADMIN_HTTPS_PORT, FORTIGATE_RESOLVE_IP, PATH_TO_FORTIGATE_CA_CERT);
`--env-file .env` loads them. They only ever send GET requests.
"""

from __future__ import annotations

import argparse
import gzip
import re
import http.client
import json
import os
import socket
import ssl
import sys
import time
import urllib.parse
from collections import deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import codegen  # noqa: E402

ROOT = codegen.ROOT


def load_env_file(path: str) -> None:
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


class FortiGate:
    """Read-only HTTPS access to /api/v2 with optional address pinning (like Config::resolve_ip)."""

    def __init__(self) -> None:
        env = os.environ
        self.host = env.get("FORTIGATE_HOST") or env.get("FORTIGATE_GATEWAY_IP") or ""
        self.key = env.get("FORTIGATE_API_KEY", "")
        if not self.host or not self.key:
            sys.exit("fortios.py: FORTIGATE_HOST and FORTIGATE_API_KEY are required (try --env-file .env)")
        self.port = int(env.get("FORTIGATE_ADMIN_HTTPS_PORT") or 443)
        self.address = env.get("FORTIGATE_RESOLVE_IP") or self.host
        self.context = ssl.create_default_context()
        if ca := env.get("PATH_TO_FORTIGATE_CA_CERT"):
            self.context.load_verify_locations(ca)
        elif Path("/etc/ssl/cert.pem").exists():   # python.org builds on macOS ship without a store
            self.context.load_verify_locations("/etc/ssl/cert.pem")
        self.connection: http.client.HTTPSConnection | None = None

    def _connect(self) -> http.client.HTTPSConnection:
        if self.connection is None:
            connection = http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=60)
            address, host, context = self.address, self.host, self.context

            def connect() -> None:
                sock = socket.create_connection((address, connection.port), connection.timeout)
                connection.sock = context.wrap_socket(sock, server_hostname=host)

            connection.connect = connect  # type: ignore[method-assign]
            self.connection = connection
        return self.connection

    def get(self, api_path: str, query: dict[str, str] | None = None) -> tuple[int, dict]:
        target = "/api/v2/" + api_path.lstrip("/")
        if query:
            target += "?" + urllib.parse.urlencode(query)
        headers = {"Authorization": f"Bearer {self.key}", "Accept": "application/json", "Accept-Encoding": "identity"}
        for attempt in range(3):
            try:
                connection = self._connect()
                connection.request("GET", target, headers=headers)
                response = connection.getresponse()
                body = response.read()
                if response.status in (429, 502, 503, 504) and attempt < 2:
                    time.sleep(1 + attempt * 2)
                    continue
                try:
                    return response.status, json.loads(body or b"{}")
                except json.JSONDecodeError:
                    return response.status, {"raw": body.decode(errors="replace")}
            except (OSError, http.client.HTTPException):
                self.connection = None
                if attempt == 2:
                    raise
                time.sleep(1)
        raise RuntimeError("unreachable")

    def static(self, name: str) -> tuple[int, str]:
        """A file of the web GUI bundle (/static/<name>), decompressed."""
        headers = {"Authorization": f"Bearer {self.key}", "Accept-Encoding": "gzip"}
        connection = self._connect()
        connection.request("GET", f"/static/{name}", headers=headers)
        response = connection.getresponse()
        body = response.read()
        if (response.getheader("Content-Encoding") or "").lower() == "gzip":
            body = gzip.decompress(body)
        return response.status, body.decode(errors="replace")

    def schema(self, api_path: str) -> dict | None:
        status, body = self.get(f"cmdb/{api_path}", {"action": "schema"})
        results = body.get("results") if isinstance(body, dict) else None
        return results if status == 200 and isinstance(results, dict) else None


def write_snapshot(version: str, api_path: str, schema: dict) -> Path:
    out = codegen.snapshot_path(version, api_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(schema, indent=1, ensure_ascii=False) + "\n")
    return out


def cmd_pull(args: argparse.Namespace) -> int:
    version, entries, _ = codegen.load_manifest()
    paths = args.paths or [e["path"] for e in entries]
    device = FortiGate()
    status, body = device.get("monitor/system/status")
    if status == 200 and body.get("version", "").lstrip("v") != version:
        print(f"warning: device runs {body.get('version')}, manifest targets {version}", file=sys.stderr)
    failed = 0
    for api_path in paths:
        schema = device.schema(api_path)
        if schema is None:
            print(f"missing: {api_path}", file=sys.stderr)
            failed += 1
            continue
        out = write_snapshot(version, api_path, schema)
        print(f"pulled {api_path} -> {out.relative_to(ROOT)} ({len(schema.get('children') or {})} fields)")
    return 1 if failed else 0


def datasource_candidates(reference: str) -> list[str]:
    """'firewall.schedule.onetime.name' -> cmdb paths it may live at."""
    parts = reference.split(".")[:-1]
    return [f"{'.'.join(parts[:i])}/{'.'.join(parts[i:])}" for i in range(1, len(parts))]


def references(node: dict, out: set[str]) -> None:
    for ref in node.get("datasource") or []:
        out.add(ref)
    for child in (node.get("children") or {}).values():
        references(child, out)


def cmd_crawl(args: argparse.Namespace) -> int:
    version, entries, _ = codegen.load_manifest()
    seeds_file = ROOT / "codegen" / "seeds.txt"
    seeds = [e["path"] for e in entries]
    if seeds_file.exists():
        seeds += [s.strip() for s in seeds_file.read_text().splitlines() if s.strip() and not s.startswith("#")]
    gui = ROOT / "codegen" / "catalog" / version / "gui-api.json"
    if gui.exists():   # cmdb paths the web GUI uses (fortios.py mine)
        seeds += [k[len("cmdb/"):] for k, v in json.loads(gui.read_text()).items()
                  if v["kind"] == "cmdb" and not v["templated"] and "/" in k[len("cmdb/"):]]
    device = FortiGate()
    queue, seen, found = deque(seeds), set(), {}
    while queue and len(found) < args.limit:
        api_path = queue.popleft()
        if api_path in seen:
            continue
        seen.add(api_path)
        schema = device.schema(api_path)
        if schema is None:
            continue
        found[api_path] = {"category": schema.get("category"), "mkey": schema.get("mkey"),
                           "fields": len(schema.get("children") or {}), "help": schema.get("help", "")}
        if args.snapshots:
            write_snapshot(version, api_path, schema)
        refs: set[str] = set()
        references(schema, refs)
        for ref in sorted(refs):
            queue.extend(c for c in datasource_candidates(ref) if c not in seen)
    catalog = ROOT / "codegen" / "catalog" / version / "cmdb.json"
    catalog.parent.mkdir(parents=True, exist_ok=True)
    catalog.write_text(json.dumps(dict(sorted(found.items())), indent=1, ensure_ascii=False) + "\n")
    print(f"{len(found)} cmdb paths ({len(seen) - len(found)} probes were not paths) -> {catalog.relative_to(ROOT)}")
    return 0


API_CALL = re.compile(r"(?:\b(get|post|put|delete|fetch|request)\s*\(\s*)?[\"'`]/api/v2/(monitor|log|cmdb|service)/([^\"'`?]+)")


def normalize_template(path: str) -> str:
    """'system/os/${this.powerType}' -> 'system/os/{powerType}'; unresolvable segments -> '{...}'."""
    def name(match: re.Match) -> str:
        identifiers = re.findall(r"[A-Za-z_]\w*", match.group(1))
        return "{" + (identifiers[-1] if identifiers else "...") + "}"
    path = re.sub(r"\$\{+([^}]*)\}?", name, path)
    path = re.sub(r"\{+", "{", path)
    return re.sub(r"[^\w./{}-].*$", "", path).rstrip("/")


def cmd_mine(args: argparse.Namespace) -> int:
    """Statically extracts API paths from the GUI bundle. Only path strings and the HTTP method of
    the call site (when visible) are kept; the bundle itself is never stored."""
    version, _, _ = codegen.load_manifest()
    device = FortiGate()
    status, main = device.static("main.js")
    if status != 200:
        sys.exit(f"fortios.py: /static/main.js returned HTTP {status}")
    sources = {"main.js": main}
    for name in ("runtime.js", "common.js"):
        status, text = device.static(name)
        if status == 200:
            sources[name] = text
    chunks = sorted({int(i) for i in re.findall(r"\b\w\.e\((\d{2,6})\)", main)})
    for chunk in chunks:
        status, text = device.static(f"{chunk}.js")
        if status == 200:
            sources[f"{chunk}.js"] = text
    found: dict[str, dict] = {}
    for source, text in sources.items():
        for method, kind, path in API_CALL.findall(text):
            path = normalize_template(path)
            if not path:
                continue
            entry = found.setdefault(f"{kind}/{path}", {"kind": kind, "methods": set(), "templated": "{" in path,
                                                         "files": set()})
            if method in ("get", "post", "put", "delete"):
                entry["methods"].add(method.upper())
            entry["files"].add(source)
    catalog = {key: {"kind": v["kind"], "methods": sorted(v["methods"]), "templated": v["templated"],
                     "seen_in": len(v["files"])} for key, v in sorted(found.items())}
    # GUI page routes (/ng/...), for the recon recorder to visit. View pages only: no editors,
    # wizards, creation dialogs, components or stylesheets.
    skip = re.compile(r"(\.css$|/components/|/directives/|/edit\b|/create\b|/new\b|wizard|/clone\b|/import\b)")
    routes = set()
    for text in sources.values():
        for route in re.findall(r"[\"'`](/ng/[\w./-]+)", text):
            route = route.rstrip("/.")
            if not skip.search(route):
                routes.add(route)
    routes_out = ROOT / "codegen" / "catalog" / version / "gui-routes.json"
    routes_out.parent.mkdir(parents=True, exist_ok=True)
    routes_out.write_text(json.dumps(sorted(routes), indent=1) + "\n")
    out = ROOT / "codegen" / "catalog" / version / "gui-api.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(catalog, indent=1) + "\n")
    kinds: dict[str, int] = {}
    for v in catalog.values():
        kinds[v["kind"]] = kinds.get(v["kind"], 0) + 1
    print(f"{len(sources)} bundle files ({len(chunks)} lazy chunks): {len(catalog)} API paths {kinds} "
          f"-> {out.relative_to(ROOT)}; {len(routes)} GUI page routes")
    return 0


def cmd_gen(args: argparse.Namespace) -> int:
    changed = codegen.generate(check=False)
    print("\n".join(changed) if changed else "generated headers are up to date")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    problems = codegen.generate(check=True)
    if problems:
        print("generated headers are out of date (run tools/fortios/fortios.py gen):", file=sys.stderr)
        print("\n".join("  " + p for p in problems), file=sys.stderr)
        return 1
    print("generated headers are up to date")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env-file", help="load FORTIGATE_* variables from this file first")
    sub = parser.add_subparsers(dest="command", required=True)
    pull = sub.add_parser("pull", help="fetch schema snapshots")
    pull.add_argument("paths", nargs="*")
    crawl = sub.add_parser("crawl", help="discover cmdb paths")
    crawl.add_argument("--limit", type=int, default=5000)
    crawl.add_argument("--snapshots", action="store_true", help="also write a snapshot per discovered path")
    sub.add_parser("mine", help="catalog the API paths the web GUI uses")
    sub.add_parser("gen", help="regenerate headers")
    sub.add_parser("check", help="verify generated headers")
    args = parser.parse_args()
    if args.env_file:
        load_env_file(args.env_file)
    try:
        return {"pull": cmd_pull, "crawl": cmd_crawl, "mine": cmd_mine, "gen": cmd_gen,
                "check": cmd_check}[args.command](args)
    except codegen.GenerationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
