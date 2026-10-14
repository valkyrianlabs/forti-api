"""Safe-route policy and sanitizer for the read-only GUI reconnaissance recorder.

Every request the web GUI makes during a recon session is classified here BEFORE it is allowed to
reach the device. The policy is an allowlist: anything not explicitly safe is aborted.

  auth     the login form submission and logout; nothing else may write
  static   same-origin GETs of the GUI's own files (HTML routes, /static, images, fonts)
  read     GET of cmdb objects (plain reads, ?action=schema|default only), monitor endpoints the
           bundle catalog confirms as GET, and log queries; never downloads, exports, backups or
           anything whose name reads like an action
  reject   everything else: every other POST/PUT/DELETE, websockets, other origins, unknown monitor
           endpoints. Rejected requests are still recorded (method + sanitized path), which is how
           the recorder learns the methods the static catalog could not see.

Nothing persisted carries values: paths are templated, query strings reduced to parameter names,
response bodies reduced to their JSON shape (keys and types), dynamic keys collapsed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

AUTH_ROUTES = {("POST", "/logincheck"), ("GET", "/logout"), ("POST", "/logout"), ("GET", "/login")}

# Words that mark an action, a download or sensitive material. Matched against the whole tokens of
# monitor, log and service path segments ("clear-all" -> {"clear", "all"}), so "address" is not
# "add" and "settings" is not "set". A match is always rejected, whatever the method.
UNSAFE_WORDS = frozenset("""
    download backup export import upload restore debug dump crash core reboot shutdown restart reset
    clear flush delete remove disconnect kill revoke upgrade update refresh start stop run trigger test
    sniffer capture packet abort purge quarantine ban format generate keygen register activate login
    logout password passwd sso token csr migrate push sync create add set change enable disable
    authorize deauth block unblock cancel approve reject send email sms ping traceroute diagnose
    heapdump mock interceptor script execute exec cli shell terminal console
""".split())

STATIC_PREFIXES = ("/static/", "/favicon/", "/images/", "/fonts/", "/css/", "/ng/", "/lang/")
# GUI HTML pages outside /ng: the post-login prompt (disclaimers, notices) is shown before the GUI.
GUI_PAGES = {"/", "/prompt"}


@dataclass(frozen=True)
class Decision:
    allow: bool
    category: str      # auth | static | read | reject
    reason: str


def _unsafe(path: str) -> bool:
    tokens = {t.lower() for segment in path.split("/") for t in re.split(r"[-_.]", segment) if t}
    return not tokens.isdisjoint(UNSAFE_WORDS)


def classify(method: str, url: str, origin: str, monitor_get: set[str], resource_type: str = "") -> Decision:
    """Decides one request. `monitor_get` holds monitor paths ('system/status') the static catalog
    confirmed the GUI reads with GET."""
    method = method.upper()
    parts = urlsplit(url)
    if f"{parts.scheme}://{parts.netloc}" != origin:
        return Decision(False, "reject", "other origin")
    if resource_type == "websocket" or parts.scheme in ("ws", "wss"):
        return Decision(False, "reject", "websocket")
    path = parts.path or "/"
    if (method, path.rstrip("/") or "/") in AUTH_ROUTES:
        return Decision(True, "auth", "login/logout")
    if not path.startswith("/api/"):
        if method == "GET" and (path in GUI_PAGES or path.startswith(STATIC_PREFIXES) or "." in path.rsplit("/", 1)[-1]):
            return Decision(True, "static", "GUI file")
        return Decision(False, "reject", f"{method} outside the API")
    if method != "GET":
        return Decision(False, "reject", f"{method} (only GET is allowed)")
    if path.startswith("/api/v2/static/"):
        return Decision(True, "static", "GUI file (API static)")
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    if path.startswith("/api/v2/cmdb/"):
        if query.get("action") not in (None, "schema", "default"):
            return Decision(False, "reject", f"cmdb action {query.get('action')}")
        return Decision(True, "read", "cmdb read")
    if path.startswith("/api/v2/monitor/"):
        rel = path[len("/api/v2/monitor/"):].strip("/")
        if _unsafe(rel):
            return Decision(False, "reject", "unsafe monitor name")
        if rel in monitor_get or any(rel.startswith(known + "/") for known in monitor_get):
            return Decision(True, "read", "monitor GET (catalog)")
        return Decision(False, "reject", "monitor endpoint not confirmed as GET")
    if path.startswith("/api/v2/log/"):
        rel = path[len("/api/v2/log/"):]
        if _unsafe(rel) or "archive" in rel:
            return Decision(False, "reject", "unsafe log name")
        return Decision(True, "read", "log query")
    return Decision(False, "reject", "unknown API area")


# -- sanitizing -------------------------------------------------------------------------------------

_VALUE_SEGMENT = re.compile(
    r"^(\d+|[0-9a-f]{8}-[0-9a-f-]{27}|[0-9a-fA-F:]{11,}|\d{1,3}(\.\d{1,3}){3}(/\d+)?|.*[%@ ].*|FG[A-Z0-9]{10,})$")
_FIELD_KEY = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


def template_path(path: str, cmdb_paths: set[str]) -> str:
    """'/api/v2/cmdb/firewall/address/LAN%2010.0.0.0' -> 'cmdb/firewall/address/{mkey}';
    value-like monitor/log segments -> '{param}'."""
    rel = path.split("/api/v2/", 1)[-1].strip("/")
    kind, _, rest = rel.partition("/")
    if kind == "cmdb":
        segments = rest.split("/")
        for n in range(len(segments), 0, -1):
            base = "/".join(segments[:n])
            if base in cmdb_paths:
                return "cmdb/" + base + ("/{mkey}" + ("/..." if len(segments) > n + 1 else "") if len(segments) > n else "")
        return "cmdb/" + "/".join(segments[:2]) + ("/{...}" if len(segments) > 2 else "")
    return kind + "/" + "/".join("{param}" if _VALUE_SEGMENT.match(s) else s for s in rest.split("/") if s)


def query_names(url: str) -> list[str]:
    return sorted({k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})


def shape(value, depth: int = 0):
    """The JSON shape of a value: types only, no values. Objects whose keys are not field-like names
    (addresses, serials, object names used as keys) are collapsed to {"{key}": shape}."""
    if depth > 12:
        return "..."
    if isinstance(value, dict):
        if value and not all(_FIELD_KEY.match(k) for k in value):
            merged = None
            for item in value.values():
                merged = merge(merged, shape(item, depth + 1))
            return {"{key}": merged}
        return {k: shape(v, depth + 1) for k, v in sorted(value.items())}
    if isinstance(value, list):
        merged = None
        for item in value[:50]:
            merged = merge(merged, shape(item, depth + 1))
        return [merged] if merged is not None else []
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if value is None:
        return "null"
    return "string"


def merge(a, b):
    """Union of two shapes."""
    if a is None:
        return b
    if b is None or a == b:
        return a
    if isinstance(a, dict) and isinstance(b, dict):
        return {k: merge(a.get(k), b.get(k)) for k in sorted(set(a) | set(b))}
    if isinstance(a, list) and isinstance(b, list):
        return [merge(a[0] if a else None, b[0] if b else None)] if (a or b) else []
    kinds = set((a if isinstance(a, str) else type(a).__name__).split("|")) | \
        set((b if isinstance(b, str) else type(b).__name__).split("|"))
    return "|".join(sorted(kinds))
