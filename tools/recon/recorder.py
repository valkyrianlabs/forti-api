"""Read-only GUI reconnaissance: log into the FortiGate web GUI as a read-only administrator, visit
its pages, and record which API calls the GUI makes, under the safe-route policy in policy.py.

Run it through tools/recon/run.sh (a pinned Playwright container). Inputs (environment):
  FORTIGATE_HOST, FORTIGATE_ADMIN_HTTPS_PORT    the GUI origin
  FORTI_API_RECON_ADMIN_USER (forti-api-recon), FORTI_API_RECON_ADMIN_PASS
Output: codegen/catalog/<version>/gui-recon.json (sanitized: no values, see policy.py).
"""

from __future__ import annotations

import json
import os
import sys
import time
import tomllib
from collections import deque
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import Request, Route, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
from policy import Decision, classify, merge, query_names, shape, template_path  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
MAX_PAGES = int(os.environ.get("RECON_MAX_PAGES", "400"))
SETTLE_MS = int(os.environ.get("RECON_SETTLE_MS", "2500"))


def load_catalogs(version: str) -> tuple[set[str], set[str]]:
    catalog = ROOT / "codegen" / "catalog" / version
    gui = json.loads((catalog / "gui-api.json").read_text())
    monitor_get = {k[len("monitor/"):] for k, v in gui.items()
                   if v["kind"] == "monitor" and v["methods"] == ["GET"] and not v["templated"]}
    cmdb = set(json.loads((catalog / "cmdb.json").read_text()))
    reviewed = Path(__file__).resolve().parent / "reviewed-gets.txt"
    for line in reviewed.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            monitor_get.add(line.split()[0].strip("/"))
    return monitor_get, cmdb


class Recorder:
    def __init__(self, origin: str, monitor_get: set[str], cmdb: set[str]) -> None:
        self.origin, self.monitor_get, self.cmdb = origin, monitor_get, cmdb
        self.endpoints: dict[str, dict] = {}
        self.decisions: dict[str, int] = {}
        self.pages = 0

    def _entry(self, method: str, url: str, decision: Decision) -> dict | None:
        path = urlsplit(url).path
        if not path.startswith("/api/"):
            return None
        key = f"{method} {template_path(path, self.cmdb)}"
        entry = self.endpoints.setdefault(key, {"decision": decision.category, "reason": decision.reason,
                                                "query": set(), "status": set(), "response": None, "seen": 0})
        entry["seen"] += 1
        entry["query"].update(query_names(url))
        return entry

    def route(self, route: Route, request: Request) -> None:
        decision = classify(request.method, request.url, self.origin, self.monitor_get, request.resource_type)
        self.decisions[decision.category] = self.decisions.get(decision.category, 0) + 1
        self._entry(request.method, request.url, decision)
        if not decision.allow and os.environ.get("RECON_VERBOSE"):
            print(f"refused {request.method} {template_path(urlsplit(request.url).path, self.cmdb) if '/api/' in request.url else urlsplit(request.url).path}: {decision.reason}",
                  file=sys.stderr)
        if decision.allow:
            route.continue_()
        else:
            route.abort("blockedbyclient")

    def response(self, response) -> None:
        request = response.request
        path = urlsplit(request.url).path
        if not path.startswith("/api/") or request.method != "GET":
            return
        decision = classify(request.method, request.url, self.origin, self.monitor_get, request.resource_type)
        if not decision.allow:
            return
        entry = self.endpoints.get(f"GET {template_path(path, self.cmdb)}")
        if entry is None:
            return
        entry["status"].add(response.status)
        if "json" in (response.headers.get("content-type") or ""):
            try:
                entry["response"] = merge(entry["response"], shape(response.json()))
            except Exception:  # noqa: BLE001 - a body that is not JSON keeps no shape
                pass

    def result(self) -> dict:
        return {key: {"decision": e["decision"], "reason": e["reason"], "query": sorted(e["query"]),
                      "status": sorted(e["status"]), "seen": e["seen"], "response": e["response"]}
                for key, e in sorted(self.endpoints.items())}


def gui_links(page, origin: str) -> set[str]:
    hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))")
    out = set()
    for href in hrefs:
        if not href or href.startswith(("javascript:", "mailto:", "#")):
            continue
        url = urlsplit(href if "://" in href else origin + ("" if href.startswith("/") else "/") + href)
        if f"{url.scheme}://{url.netloc}" == origin and url.path.startswith("/ng/") and "logout" not in url.path:
            out.add(url.path)
    return out


def main() -> int:
    version = tomllib.loads((ROOT / "codegen" / "api.toml").read_text())["fortios_version"]
    host = os.environ["FORTIGATE_HOST"]
    port = os.environ.get("FORTIGATE_ADMIN_HTTPS_PORT", "443")
    user = os.environ.get("FORTI_API_RECON_ADMIN_USER", "forti-api-recon")
    password = os.environ["FORTI_API_RECON_ADMIN_PASS"]
    origin = f"https://{host}" + ("" if port == "443" else f":{port}")
    monitor_get, cmdb = load_catalogs(version)
    recorder = Recorder(origin, monitor_get, cmdb)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(service_workers="block")
        context.route("**/*", recorder.route)
        page = context.new_page()
        page.on("response", recorder.response)

        page.goto(f"{origin}/login", wait_until="domcontentloaded")
        page.fill("#username", user)
        page.fill("#secretkey", password)
        page.click("#login_button")
        page.wait_for_url(lambda url: "/login" not in url, timeout=30000)
        page.wait_for_load_state("networkidle")
        if urlsplit(page.url).path == "/prompt":
            buttons = page.eval_on_selector_all("button, input[type=button], a.button",
                                                "els => els.map(e => (e.innerText || e.value || '').trim()).filter(Boolean)")
            print(f"post-login prompt: title={page.title()!r} buttons={buttons}", file=sys.stderr)

        if os.environ.get("RECON_DEBUG_LINKS"):
            hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))")
            nav = page.eval_on_selector_all("[routerlink], [ng-reflect-router-link], nav a, .nav-item, [role=menuitem]",
                                            "els => els.slice(0, 15).map(e => e.tagName + ' ' + (e.getAttribute('href') || e.getAttribute('routerlink') || '') + ' ' + (e.innerText || '').slice(0, 30))")
            print(f"landed on {urlsplit(page.url).path} title={page.title()!r}; {len(hrefs)} hrefs, sample {hrefs[:15]}; nav {nav}",
                  file=sys.stderr)
        routes_file = ROOT / "codegen" / "catalog" / version / "gui-routes.json"
        routes = json.loads(routes_file.read_text()) if routes_file.exists() else []
        queue, seen = deque(sorted(gui_links(page, origin) | set(routes)) or ["/ng/"]), set()
        while queue and recorder.pages < MAX_PAGES:
            path = queue.popleft()
            if path in seen:
                continue
            seen.add(path)
            try:
                page.goto(origin + path, wait_until="domcontentloaded", timeout=30000)
                page.wait_for_timeout(SETTLE_MS)
                recorder.pages += 1
                if os.environ.get("RECON_DEBUG_LINKS"):
                    print(f"visited {path} -> {urlsplit(page.url).path}", file=sys.stderr)
                queue.extend(sorted(gui_links(page, origin) - seen))
            except Exception as error:  # noqa: BLE001 - a page that fails to load is skipped
                print(f"skip {path}: {type(error).__name__}", file=sys.stderr)

        page.goto(f"{origin}/logout", wait_until="domcontentloaded")
        browser.close()

    out = ROOT / "codegen" / "catalog" / version / "gui-recon.json"
    out.write_text(json.dumps({"pages_visited": recorder.pages, "requests": dict(sorted(recorder.decisions.items())),
                               "endpoints": recorder.result()}, indent=1) + "\n")
    allowed = sum(1 for e in recorder.result().values() if e["decision"] == "read")
    print(f"{recorder.pages} pages, {len(recorder.endpoints)} API endpoints ({allowed} read), "
          f"requests {recorder.decisions} -> {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
