"""Deterministic C++ generation from FortiOS cmdb schema snapshots.

Input:  codegen/api.toml (which paths, names) + codegen/schema/<version>/cmdb/<path>.json
Output: include/forti_api/gen/<path>.hpp, one header per path, plus gen/all.hpp.

The output depends only on the inputs (stable ordering, no timestamps), so `check` can regenerate
into memory and compare byte for byte.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GEN_DIR = ROOT / "include" / "forti_api" / "gen"
ENDPOINTS_DOC = ROOT / "docs" / "reference" / "endpoints.md"
MANIFEST = ROOT / "codegen" / "api.toml"

CPP_KEYWORDS = {
    "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor", "bool", "break", "case",
    "catch", "char", "char8_t", "char16_t", "char32_t", "class", "compl", "concept", "const", "consteval",
    "constexpr", "constinit", "const_cast", "continue", "co_await", "co_return", "co_yield", "decltype",
    "default", "delete", "do", "double", "dynamic_cast", "else", "enum", "explicit", "export", "extern",
    "false", "float", "for", "friend", "goto", "if", "import", "inline", "int", "long", "module",
    "mutable", "namespace", "new", "noexcept", "not", "not_eq", "nullptr", "operator", "or", "or_eq",
    "private", "protected", "public", "register", "reinterpret_cast", "requires", "return", "short",
    "signed", "sizeof", "static", "static_assert", "static_cast", "struct", "switch", "template", "this",
    "thread_local", "throw", "true", "try", "typedef", "typeid", "typename", "union", "unsigned", "using",
    "virtual", "void", "volatile", "wchar_t", "while", "xor", "xor_eq",
    # names the generated code itself uses (mkey: the key member of a table entry)
    "visit", "fortiapi", "std", "self", "v", "mkey",
}

# Preprocessor macros a consumer's translation unit may already define (C/C++ standard library,
# POSIX/glibc, GNU predefines). A generated identifier with one of these names would be rewritten
# by the preprocessor, so it gets a trailing underscore like a keyword.
MACRO_NAMES = {
    "NULL", "EOF", "BUFSIZ", "FILENAME_MAX", "FOPEN_MAX", "TMP_MAX", "SEEK_SET", "SEEK_CUR", "SEEK_END",
    "CLOCKS_PER_SEC", "EXIT_SUCCESS", "EXIT_FAILURE", "RAND_MAX", "MB_CUR_MAX", "EDOM", "EILSEQ", "ERANGE",
    "errno", "assert", "offsetof", "setjmp", "stdin", "stdout", "stderr", "linux", "unix", "i386",
    "INFINITY", "NAN", "HUGE_VAL", "CHAR_BIT", "CHAR_MIN", "CHAR_MAX", "INT_MIN", "INT_MAX", "UINT_MAX",
    "LONG_MIN", "LONG_MAX", "ULONG_MAX", "SHRT_MIN", "SHRT_MAX", "USHRT_MAX", "LLONG_MIN", "LLONG_MAX",
    "SIGABRT", "SIGFPE", "SIGILL", "SIGINT", "SIGSEGV", "SIGTERM", "SIGHUP", "SIGKILL", "SIGPIPE",
    "BIG_ENDIAN", "LITTLE_ENDIAN", "BYTE_ORDER", "PDP_ENDIAN", "TRUE", "FALSE", "DEBUG", "NDEBUG",
    "PATH_MAX", "NAME_MAX", "PAGE_SIZE", "BSD", "major", "minor", "makedev",
}

STRING_TYPES = {
    "string", "var-string", "user", "uuid", "datetime", "mac-address", "key", "password", "password-2",
    "password-3", "password_aes256", "ipv4-address", "ipv4-address-any", "ipv4-address-multicast",
    "ipv4-classnet", "ipv4-classnet-any", "ipv4-classnet-host", "ipv4-netmask", "ipv4-netmask-any",
    "ipv4-range", "ipv6-address", "ipv6-network", "ipv6-prefix", "ipv6-range", "email",
}


class GenerationError(Exception):
    pass


def identifier(name: str) -> str:
    """A safe C++ identifier for a FortiOS name, preserving case."""
    out = re.sub(r"[^0-9A-Za-z_]", "_", name)
    if not out or out[0].isdigit():
        out = "_" + out
    if out in CPP_KEYWORDS or out in MACRO_NAMES:
        out += "_"
    return out


def member_name(key: str) -> str:
    return identifier(key.replace("-", "_"))


def camel(name: str) -> str:
    parts = [p for p in re.split(r"[^0-9A-Za-z]+", name) if p]
    out = "".join(p[:1].upper() + p[1:] for p in parts) or "Unnamed"
    return "_" + out if out[0].isdigit() else out


def snake(name: str) -> str:
    out = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", name).lower()
    return identifier(out)


def plural(name: str) -> str:
    if re.search(r"[^aeiou]y$", name):
        return name[:-1] + "ies"
    if re.search(r"(s|x|z|ch|sh)$", name):
        return name + "es"
    return name + "s"


def cpp_string(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)


def raw_literal(json_text: str) -> str:
    return f'R"({json_text})"' if ')"' not in json_text else f'R"fortiapi({json_text})fortiapi"'


def comment(text: str) -> str:
    return " ".join(str(text).split()).replace("*/", "* /")


@dataclass
class Endpoint:
    path: str                    # "firewall/policy", "firewall.service/custom"
    namespace: list[str]         # ["firewall"] / ["firewall", "service"]
    type_name: str               # "Policy"
    alias: str                   # "Policies" (table) / type name (singleton)
    schema: dict
    snapshot: Path

    @property
    def is_table(self) -> bool:
        return self.schema.get("category") == "table"

    @property
    def header(self) -> Path:
        collection, _, name = self.path.partition("/")
        return GEN_DIR.joinpath(*collection.split("."), f"{name.replace('-', '_')}.hpp")

    @property
    def guard(self) -> str:
        rel = self.header.relative_to(GEN_DIR).with_suffix("")
        return "FORTI_API_GEN_" + re.sub(r"[^0-9A-Za-z]", "_", str(rel)).upper() + "_HPP"


@dataclass
class StructRecord:
    """One generated struct, for gen/schema.hpp: its qualified C++ name, schema node and members."""
    name: str                    # "fortiapi::firewall::Address::MacaddrEntry"
    node: dict                   # the schema node (cmdb; {} for monitor results, which have no schema)
    members: list[tuple]         # (key, C++ type, reset, read_only, child schema node or None)
    nested: dict[str, str]       # local nested type name -> qualified name


@dataclass
class Emitter:
    endpoint: Endpoint
    lines: list[str] = field(default_factory=list)
    records: list[StructRecord] = field(default_factory=list)   # every struct, nested ones first
    scope: list[str] = field(default_factory=list)              # enclosing namespaces and structs

    def emit(self, text: str = "", indent: int = 0) -> None:
        self.lines.append(("    " * indent + text) if text else "")

    # -- types -------------------------------------------------------------------------------------

    def scalar_type(self, node: dict) -> str:
        if node.get("multiple_values"):
            return "std::string"
        kind = node.get("type")
        if kind == "integer":
            lo, hi = node.get("min-value"), node.get("max-value")
            if isinstance(lo, int) and isinstance(hi, int) and lo >= 0 and hi <= 4294967295:
                return "std::uint32_t"
            return "std::int64_t"
        if kind == "option" or kind in STRING_TYPES:
            return "std::string"
        if kind is None:
            return "nlohmann::json"
        # Unknown scalar kinds are strings on the wire; keep them usable.
        return "std::string"

    def reset_value(self, node: dict, cpp_type: str) -> str:
        category = node.get("category")
        if category == "table":
            return "[]"
        if category == "complex":
            return "{}"
        default = node.get("default")
        if cpp_type in ("std::uint32_t", "std::int64_t"):
            return json.dumps(default if isinstance(default, int) else 0)
        if cpp_type == "nlohmann::json":
            return json.dumps(default) if default is not None else "null"
        return json.dumps(default if isinstance(default, str) else "", ensure_ascii=False)

    @staticmethod
    def is_ref_table(node: dict) -> bool:
        children = node.get("children") or {}
        return set(children) == {"name"} and children["name"].get("category") == "unitary"

    # -- structs -----------------------------------------------------------------------------------

    def struct(self, name: str, node: dict, indent: int, option_scope: list[str], doc: str | None) -> None:
        self.scope.append(name)
        qualified = "::".join(self.scope)
        children = node.get("children") or {}
        members: list[tuple[str, str, str, str, str]] = []   # key, member, cpp type, reset, flags
        nested: list[tuple[str, dict, list[str]]] = []
        option_structs: list[tuple[str, list[dict], str | None]] = []
        used_members: set[str] = set()
        used_types: set[str] = set()

        for key, child in children.items():
            member = member_name(key)
            if member in used_members:
                raise GenerationError(f"{self.endpoint.path}: duplicate member {member} in {name}")
            used_members.add(member)
            category = child.get("category")
            scope = option_scope + [member]
            if category == "table":
                if self.is_ref_table(child):
                    cpp = "std::vector<fortiapi::Ref>"
                else:
                    entry = camel(key) + "Entry"
                    if entry in used_types or entry == name:
                        entry = camel(key) + "TableEntry"
                    if entry in used_types or entry == name:
                        raise GenerationError(f"{self.endpoint.path}: nested type {entry} collides in {name}")
                    used_types.add(entry)
                    nested.append((entry, child, scope))
                    cpp = f"std::vector<{entry}>"
            elif category == "complex":
                sub = camel(key)
                if sub in used_types or sub == name:
                    sub += "Object"
                if sub in used_types or sub == name:
                    raise GenerationError(f"{self.endpoint.path}: nested type {sub} collides in {name}")
                used_types.add(sub)
                nested.append((sub, child, scope))
                cpp = sub
            else:
                cpp = self.scalar_type(child)
                if child.get("options"):
                    holder = camel(key)
                    if holder in used_types or holder == name:
                        holder += "Values"
                    if holder in used_types or holder == name:
                        raise GenerationError(f"{self.endpoint.path}: constants {holder} collide in {name}")
                    used_types.add(holder)
                    option_structs.append((holder, child["options"], child.get("help")))
            flags = "fortiapi::read_only" if child.get("readonly") or category == "info-read-only" else "fortiapi::none"
            members.append((key, member, cpp, self.reset_value(child, cpp), flags))

        if doc:
            self.emit(f"// {comment(doc)}", indent)
        self.emit(f"struct {name} {{", indent)
        for holder, options, help_text in option_structs:
            self.emit(f"// Values of {holder}: {comment(help_text or '')}".rstrip(": "), indent + 1)
            self.emit(f"struct {holder} {{", indent + 1)
            for constant, value in self.constant_names(options, holder):
                self.emit(f"static constexpr std::string_view {constant} = {cpp_string(value)};", indent + 2)
            self.emit("};", indent + 1)
            self.emit()
        for sub_name, sub_node, sub_scope in nested:
            self.struct(sub_name, sub_node, indent + 1, sub_scope, sub_node.get("help"))
            self.emit()
        for key, member, cpp, _, flags in members:
            child = children[key]
            notes = [comment(child.get("help", ""))]
            if child.get("required"):
                notes.append("Required.")
            if flags == "fortiapi::read_only":
                notes.append("Read-only.")
            if child.get("datasource"):
                notes.append("References: " + ", ".join(child["datasource"]) + ".")
            note = " ".join(n for n in notes if n)
            self.emit(f"fortiapi::Field<{cpp}> {member};" + (f"  // {note}" if note else ""), indent + 1)
        # A table entry names its key (the table's mkey), so fortiapi::ChildTable can address one
        # entry (cmdb/<path>/<parent key>/<attribute>/<entry key>). The top-level key is in the Spec.
        entry_key = node.get("mkey") if indent > 0 and node.get("category") == "table" else None
        if entry_key:
            if entry_key not in children:
                raise GenerationError(f"{self.endpoint.path}: {name} has mkey {entry_key}, not one of its attributes")
            self.emit()
            self.emit(f"static constexpr auto mkey = &{name}::{member_name(entry_key)};  // the entry key", indent + 1)
        self.emit()
        self.emit("template<typename Self, typename Visitor>", indent + 1)
        self.emit("static void visit(Self& self, Visitor&& v) {", indent + 1)
        for key, member, _, reset, flags in members:
            self.emit(f"v({cpp_string(key)}, self.{member}, {raw_literal(reset)}, {flags});", indent + 2)
        if not members:
            self.emit("(void) self; (void) v;", indent + 2)
        self.emit("}", indent + 1)
        self.emit("};", indent)
        self.scope.pop()
        self.records.append(StructRecord(
            qualified, node,
            [(key, cpp, reset, flags == "fortiapi::read_only", children[key]) for key, _, cpp, reset, flags in members],
            {sub_name: f"{qualified}::{sub_name}" for sub_name, _, _ in nested}))

    @staticmethod
    def constant_names(options: list[dict], holder: str) -> list[tuple[str, str]]:
        values, seen = [], set()
        for option in options:
            value = option["name"]
            name = identifier(value)
            if name == holder:
                name += "_"
            base, n = name, 2
            while name in seen:
                name, n = f"{base}_{n}", n + 1
            seen.add(name)
            values.append((name, value))
        return values

    # -- header ------------------------------------------------------------------------------------

    def render(self, version: str) -> str:
        ep = self.endpoint
        ns = "fortiapi::" + "::".join(identifier(p) for p in ep.namespace)
        rel_include = Path("../" * (len(ep.header.relative_to(GEN_DIR).parts) - 1 + 1)) / "endpoint.hpp"
        snapshot = ep.snapshot.relative_to(ROOT).as_posix()

        body = Emitter(ep, scope=["fortiapi", *(identifier(p) for p in ep.namespace)])
        body.struct(ep.type_name, ep.schema, 0, [snake(ep.type_name)], ep.schema.get("help"))
        self.records = body.records

        out = [
            f"// Generated by tools/fortios/fortios.py from {snapshot} (FortiOS {version}).",
            "// Do not edit: change codegen/api.toml or the generator and regenerate.",
            "",
            f"#ifndef {ep.guard}",
            f"#define {ep.guard}",
            "",
            f'#include "{rel_include.as_posix()}"',
            "",
            "#include <cstdint>",
            "#include <string>",
            "#include <string_view>",
            "#include <vector>",
            "",
            f"namespace {ns} {{",
            "",
        ]
        out += body.lines
        out.append("")
        key = ep.schema.get("mkey")
        if ep.is_table:
            if not key:
                raise GenerationError(f"{ep.path}: table without mkey")
            out += [
                f"struct {ep.type_name}Spec {{",
                f"    using type = {ep.type_name};",
                f"    static constexpr std::string_view path = {cpp_string('cmdb/' + ep.path)};",
                f"    static constexpr auto key = &{ep.type_name}::{member_name(key)};",
                "};",
                "",
                f"using {ep.alias} = fortiapi::Table<{ep.type_name}Spec>;",
            ]
        else:
            out += [
                f"struct {ep.type_name}Spec {{",
                f"    using type = {ep.type_name};",
                f"    static constexpr std::string_view path = {cpp_string('cmdb/' + ep.path)};",
                "};",
                "",
                f"using {ep.alias} = fortiapi::Singleton<{ep.type_name}Spec>;",
            ]
        out += ["", f"}}  // namespace {ns}", "", f"#endif // {ep.guard}", ""]
        return "\n".join(out)


def load_manifest() -> tuple[str, list[dict], bool]:
    data = tomllib.loads(MANIFEST.read_text())
    version = data.get("fortios_version")
    if not version:
        raise GenerationError(f"{MANIFEST}: fortios_version is required")
    entries = data.get("cmdb", [])
    paths = [e["path"] for e in entries]
    if len(paths) != len(set(paths)):
        raise GenerationError(f"{MANIFEST}: duplicate paths")
    return version, entries, bool(data.get("generate_all", False))


def snapshot_path(version: str, api_path: str) -> Path:
    collection, _, name = api_path.partition("/")
    return ROOT / "codegen" / "schema" / version / "cmdb" / collection / f"{name}.json"


def endpoints() -> tuple[str, list[Endpoint]]:
    version, entries, generate_all = load_manifest()
    by_path = {e["path"]: e for e in entries}
    paths = set(by_path)
    if generate_all:
        catalog = ROOT / "codegen" / "catalog" / version / "cmdb.json"
        paths |= set(json.loads(catalog.read_text()))
    out, names = [], {}
    for api_path in sorted(paths):
        entry = by_path.get(api_path, {"path": api_path})
        snap = snapshot_path(version, api_path)
        if not snap.exists():
            raise GenerationError(f"{api_path}: no schema snapshot at {snap.relative_to(ROOT)} (run `fortios.py pull`)")
        schema = json.loads(snap.read_text())
        collection, _, name = api_path.partition("/")
        raw_namespace = entry.get("namespace", collection).split(".")
        namespace = [identifier(part.replace("-", "_").replace("+", "_")) for part in raw_namespace]
        type_name = entry.get("type", camel(name))
        is_table = schema.get("category") == "table"
        alias = entry.get("alias", plural(type_name) if is_table else type_name + "Settings")
        ep = Endpoint(api_path, namespace, type_name, alias, schema, snap)
        for symbol in (type_name, alias, type_name + "Spec"):
            qualified = "::".join(namespace + [symbol])
            if qualified in names:
                raise GenerationError(f"{api_path}: {qualified} also generated by {names[qualified]}; "
                                      f"set type/alias in codegen/api.toml")
            names[qualified] = api_path
        header = ep.header
        if header in names:
            raise GenerationError(f"{api_path}: header {header.relative_to(ROOT)} also generated by {names[header]}")
        names[header] = api_path
        out.append(ep)
    # A C++ namespace and a type cannot share a qualified name.
    namespaces = {"::".join(ep.namespace[:i]) for ep in out for i in range(1, len(ep.namespace) + 1)}
    for qualified, api_path in names.items():
        if isinstance(qualified, str) and qualified in namespaces:
            raise GenerationError(f"{api_path}: {qualified} is both a type and a namespace")
    return version, out


# -- monitor endpoints (from the sanitized GUI recon catalog) -----------------------------------------

@dataclass
class MonitorEndpoint:
    path: str                    # "system/available-interfaces" (relative to monitor/)
    namespace: list[str]         # ["monitor", "system"]
    alias: str                   # "AvailableInterfaces"
    data: str                    # "AvailableInterfacesEntry" / "StatusResult"
    is_list: bool
    shape: object                # shape of `results` (element shape for lists)
    query: list[str]

    @property
    def header(self) -> Path:
        return GEN_DIR.joinpath("monitor", *[p.replace("-", "_") for p in self.path.split("/")]).with_suffix(".hpp")


def monitor_endpoints(version: str) -> list[MonitorEndpoint]:
    recon = ROOT / "codegen" / "catalog" / version / "gui-recon.json"
    if not recon.exists():
        return []
    out = []
    for key, entry in sorted(json.loads(recon.read_text())["endpoints"].items()):
        method, _, target = key.partition(" ")
        if method != "GET" or entry["decision"] != "read" or not target.startswith("monitor/") or "{" in target:
            continue
        response = entry.get("response")
        if not isinstance(response, dict) or "results" not in response:
            continue
        path = target[len("monitor/"):]
        segments = path.split("/")
        group, rest = segments[0], segments[1:] or segments[:1]
        alias = camel("-".join(rest))
        results = response["results"]
        is_list = isinstance(results, list)
        element = results[0] if is_list and results else results
        if is_list and not results:
            element = None
        typed = isinstance(element, dict) and "{key}" not in element
        data = alias + ("Entry" if is_list else "Result") if typed else "nlohmann::json"
        out.append(MonitorEndpoint(path, ["monitor", identifier(group.replace("-", "_"))], alias, data, is_list,
                                   element, entry.get("query", [])))
    return out


class MonitorEmitter:
    def __init__(self, ep: MonitorEndpoint) -> None:
        self.ep, self.lines = ep, []
        self.records: list[StructRecord] = []
        self.scope = ["fortiapi", *ep.namespace]

    def emit(self, text: str = "", indent: int = 0) -> None:
        self.lines.append(("    " * indent + text) if text else "")

    def cpp_type(self, key: str, shape, indent: int, nested: list, used: set[str]) -> str:
        if isinstance(shape, str):
            return {"string": "std::string", "integer": "std::int64_t", "number": "double",
                    "boolean": "bool"}.get(shape, "nlohmann::json")
        if isinstance(shape, list):
            if not shape or shape[0] is None:
                return "std::vector<nlohmann::json>"
            inner = shape[0]
            if isinstance(inner, dict) and "{key}" not in inner:
                return f"std::vector<{self.nested(camel(key) + 'Entry', inner, nested, used)}>"
            return f"std::vector<{self.cpp_type(key, inner, indent, nested, used)}>"
        if isinstance(shape, dict):
            if "{key}" in shape:
                inner = shape["{key}"]
                if isinstance(inner, dict) and "{key}" not in inner:
                    return f"std::map<std::string, {self.nested(camel(key) + 'Value', inner, nested, used)}>"
                return f"std::map<std::string, {self.cpp_type(key, inner, indent, nested, used)}>"
            return self.nested(camel(key), shape, nested, used)
        return "nlohmann::json"

    @staticmethod
    def nested(name: str, shape: dict, nested: list, used: set[str]) -> str:
        if name in used:
            name += "Object"
        used.add(name)
        nested.append((name, shape))
        return name

    def struct(self, name: str, shape: dict, indent: int) -> None:
        self.scope.append(name)
        qualified = "::".join(self.scope)
        nested: list[tuple[str, dict]] = []
        used: set[str] = {name}
        members = []
        for key, value in sorted(shape.items()):
            member = member_name(key)
            members.append((key, member, self.cpp_type(key, value, indent, nested, used)))
        self.emit(f"struct {name} {{", indent)
        for sub, sub_shape in nested:
            self.struct(sub, sub_shape, indent + 1)
            self.emit()
        for key, member, cpp in members:
            self.emit(f"fortiapi::Field<{cpp}> {member};", indent + 1)
        self.emit()
        self.emit("template<typename Self, typename Visitor>", indent + 1)
        self.emit("static void visit(Self& self, Visitor&& v) {", indent + 1)
        for key, member, _ in members:
            self.emit(f"v({cpp_string(key)}, self.{member}, R\"(null)\", fortiapi::read_only);", indent + 2)
        if not members:
            self.emit("(void) self; (void) v;", indent + 2)
        self.emit("}", indent + 1)
        self.emit("};", indent)
        self.scope.pop()
        self.records.append(StructRecord(qualified, {}, [(key, cpp, "null", True, None) for key, _, cpp in members],
                                         {sub: f"{qualified}::{sub}" for sub, _ in nested}))

    def render(self, version: str) -> str:
        ep = self.ep
        guard = "FORTI_API_GEN_" + re.sub(r"[^0-9A-Za-z]", "_", str(ep.header.relative_to(GEN_DIR).with_suffix(""))).upper() + "_HPP"
        depth = len(ep.header.relative_to(GEN_DIR).parts)
        ns = "fortiapi::" + "::".join(ep.namespace)
        data = ep.data
        if data != "nlohmann::json":
            self.emit(f"// Result of GET monitor/{ep.path}, from response shapes recorded on FortiOS {version}.")
            self.struct(data, ep.shape, 0)
        out = [
            f"// Generated by tools/fortios/fortios.py from codegen/catalog/{version}/gui-recon.json (FortiOS {version}).",
            "// Do not edit: the type follows response shapes recorded on a device; attributes it did not",
            "// report are absent, unknown attributes are ignored.",
            "",
            f"#ifndef {guard}",
            f"#define {guard}",
            "",
            f'#include "{"../" * depth}monitor.hpp"',
            "",
            "#include <cstdint>",
            "#include <map>",
            "#include <string>",
            "#include <string_view>",
            "#include <vector>",
            "",
            f"namespace {ns} {{",
            "",
        ]
        if self.lines:
            out += self.lines + [""]
        query = f"  // query parameters seen: {', '.join(ep.query)}" if ep.query else ""
        out += [
            f"struct {ep.alias}Spec {{",
            f"    using type = {data};",
            f"    static constexpr std::string_view path = {cpp_string(ep.path)};",
            f"    static constexpr bool list = {'true' if ep.is_list else 'false'};",
            "};",
            "",
            f"using {ep.alias} = fortiapi::MonitorGet<{ep.alias}Spec>;{query}",
            "",
            f"}}  // namespace {ns}",
            "",
            f"#endif // {guard}",
            "",
        ]
        return "\n".join(out)


def render_all() -> dict[Path, str]:
    version, eps = endpoints()
    emitters = [Emitter(ep) for ep in eps]
    files = {e.endpoint.header: e.render(version) for e in emitters}
    monitors = monitor_endpoints(version)
    monitor_emitters = []
    seen: dict[str, str] = {}
    for mon in monitors:
        for symbol in (mon.alias, mon.alias + "Spec") + ((mon.data,) if mon.data != "nlohmann::json" else ()):
            qualified = "::".join(mon.namespace + [symbol])
            if qualified in seen:
                raise GenerationError(f"monitor/{mon.path}: {qualified} also generated by monitor/{seen[qualified]}")
            seen[qualified] = mon.path
        emitter = MonitorEmitter(mon)
        files[mon.header] = emitter.render(version)
        monitor_emitters.append(emitter)
    includes = sorted(f'#include "{p.relative_to(GEN_DIR).as_posix()}"' for p in files if p.parent != GEN_DIR)
    files[GEN_DIR / "all.hpp"] = "\n".join([
        "// Generated by tools/fortios/fortios.py: every generated endpoint. Do not edit.",
        "",
        "#ifndef FORTI_API_GEN_ALL_HPP",
        "#define FORTI_API_GEN_ALL_HPP",
        "",
        *includes,
        "",
        "#endif // FORTI_API_GEN_ALL_HPP",
        "",
    ])
    groups: dict[str, list[Path]] = {}
    for ep in eps:
        groups.setdefault(ep.path.split("/")[0].split(".")[0], []).append(ep.header)
    for mon in monitors:
        groups.setdefault("monitor", []).append(mon.header)
    for group, headers in sorted(groups.items()):
        guard = "FORTI_API_GEN_GROUP_" + re.sub(r"[^0-9A-Za-z]", "_", group).upper() + "_HPP"
        files[GEN_DIR / f"{group}.hpp"] = "\n".join([
            f"// Generated by tools/fortios/fortios.py: every generated {group} endpoint. Do not edit.",
            "",
            f"#ifndef {guard}",
            f"#define {guard}",
            "",
            *sorted(f'#include "{h.relative_to(GEN_DIR).as_posix()}"' for h in headers),
            "",
            f"#endif // {guard}",
            "",
        ])
    files[GEN_DIR / "registry.hpp"] = registry(eps, monitors)
    files[GEN_DIR / "schema.hpp"] = schema_tables(version, emitters, monitor_emitters)
    files[ENDPOINTS_DOC] = endpoints_doc(version, eps, monitors)
    return files


def registry(eps: list[Endpoint], monitors: list["MonitorEndpoint"]) -> str:
    calls = [f"    f.template operator()<fortiapi::{'::'.join(ep.namespace)}::{ep.alias}>();" for ep in eps]
    monitor_calls = [f"    f.template operator()<fortiapi::{'::'.join(m.namespace)}::{m.alias}>();" for m in monitors]
    return "\n".join([
        "// Generated by tools/fortios/fortios.py: every generated endpoint, for introspection. Do not edit.",
        "",
        "#ifndef FORTI_API_GEN_REGISTRY_HPP",
        "#define FORTI_API_GEN_REGISTRY_HPP",
        "",
        '#include "all.hpp"',
        "",
        "namespace fortiapi::gen {",
        "",
        "// Calls f.template operator()<Endpoint>() for every generated Table and Singleton, e.g.",
        "//   for_each_endpoint([]<typename E>() { std::cout << E::path << \"\\n\"; });",
        "template<typename F>",
        "void for_each_endpoint(F&& f) {",
        *calls,
        "}",
        "",
        "inline constexpr std::size_t endpoint_count = " + str(len(eps)) + ";",
        "",
        "// Calls f.template operator()<Endpoint>() for every generated read-only monitor endpoint.",
        "template<typename F>",
        "void for_each_monitor(F&& f) {",
        *monitor_calls,
        *(["    (void) f;"] if not monitor_calls else []),
        "}",
        "",
        "inline constexpr std::size_t monitor_count = " + str(len(monitors)) + ";",
        "",
        "}  // namespace fortiapi::gen",
        "",
        "#endif // FORTI_API_GEN_REGISTRY_HPP",
        "",
    ])


def endpoints_doc(version: str, eps: list[Endpoint], monitors: list["MonitorEndpoint"]) -> str:
    rows = []
    for ep in eps:
        kind = "Table" if ep.is_table else "Singleton"
        ns = "fortiapi::" + "::".join(ep.namespace)
        header = ep.header.relative_to(ROOT / "include").as_posix()
        rows.append(f"| `cmdb/{ep.path}` | `{ns}::{ep.type_name}` | `{ns}::{ep.alias}` ({kind}) | `{header}` | "
                    f"{len(ep.schema.get('children') or {})} |")
    return "\n".join([
        "---",
        "title: Supported endpoints",
        "description: The FortiOS endpoints forti-api generates, with their C++ types and headers.",
        "order: 100",
        "status: published",
        "tags:",
        "  - reference",
        "---",
        "",
        "<!-- Generated by tools/fortios/fortios.py gen from codegen/api.toml. Do not edit. -->",
        "",
        "# Supported endpoints",
        "",
        f"Generated from FortiOS {version} schemas. Each header declares the object type, its option",
        "constants and the endpoint alias; `forti_api/gen/all.hpp` includes them all.",
        "",
        f"{len(eps)} configuration endpoints ({sum(1 for e in eps if e.is_table)} tables, "
        f"{sum(1 for e in eps if not e.is_table)} singletons) and {len(monitors)} monitor endpoints.",
        "",
        "## Configuration (cmdb)",
        "",
        "| FortiOS path | Type | Endpoint | Header | Attributes |",
        "|---|---|---|---|---|",
        *rows,
        "",
        "## Monitor",
        "",
        "Read-only monitor endpoints with result types generated from response shapes recorded on a",
        f"FortiOS {version} device. Every other monitor path, and every monitor action, is available untyped",
        "through `fortiapi::Monitor`.",
        "",
        "| FortiOS path | Endpoint | Result | Header |",
        "|---|---|---|---|",
        *[f"| `monitor/{m.path}` | `fortiapi::{'::'.join(m.namespace)}::{m.alias}` | "
          f"{('`std::vector<' + m.data + '>`') if m.is_list else ('`' + m.data + '`')} | "
          f"`{m.header.relative_to(ROOT / 'include').as_posix()}` |" for m in monitors],
        "",
        "New endpoints are added through the generator; see [Code generation](/development/code-generation).",
        "",
    ])


# -- gen/schema.hpp: every generated type and endpoint as data ------------------------------------------

SCALAR_KINDS = {"std::string": "string", "std::uint32_t": "uint32", "std::int64_t": "int64", "double": "number",
                "bool": "boolean", "nlohmann::json": "json"}


def split_cpp_type(cpp: str) -> tuple[str, list[str]]:
    """'std::map<std::string, std::vector<X>>' -> ('std::map', ['std::string', 'std::vector<X>'])."""
    if not cpp.endswith(">"):
        return cpp, []
    head, _, inner = cpp.partition("<")
    args, depth, start = [], 0, 0
    inner = inner[:-1]
    for i, ch in enumerate(inner):
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(inner[start:i].strip())
            start = i + 1
    args.append(inner[start:].strip())
    return head, args


class SchemaTables:
    """Emits the constexpr descriptor tables of gen/schema.hpp (types in schema_types.hpp).

    Built from the emitters' struct records, so every Field describes exactly the Field<T> member the
    typed header declares (key, C++ type, reset value, read-only flag, in visit() order). Identical
    string lists, ranges and element descriptors are emitted once."""

    def __init__(self) -> None:
        self.out: list[str] = []
        self.types: dict[str, str] = {"fortiapi::Ref": "ref"}   # qualified C++ name -> identifier
        self.elements: dict[tuple, str] = {}
        self.lists: dict[tuple[str, ...], str] = {}
        self.ranges: dict[tuple[int, int], str] = {}

    def string_list(self, values: list[str]) -> str:
        if not values:
            return "{}"
        key = tuple(values)
        if key not in self.lists:
            self.lists[key] = f"s{len(self.lists)}"
            self.out.append(f"inline constexpr std::string_view {self.lists[key]}[] = {{"
                            + ", ".join(cpp_string(v) for v in values) + "};")
        return self.lists[key]

    def range(self, node: dict) -> str:
        lo, hi = node.get("min-value"), node.get("max-value")
        if not (isinstance(lo, int) and isinstance(hi, int)):
            return "nullptr"
        if (lo, hi) not in self.ranges:
            self.ranges[(lo, hi)] = f"r{len(self.ranges)}"
            self.out.append(f"inline constexpr Range {self.ranges[(lo, hi)]}{{{lo}, {hi}}};")
        return "&" + self.ranges[(lo, hi)]

    def kind(self, cpp: str, nested: dict[str, str]) -> tuple[str, str, str]:
        """(Kind, type pointer, item pointer) for a C++ attribute type; emits element descriptors."""
        if cpp in SCALAR_KINDS:
            return SCALAR_KINDS[cpp], "nullptr", "nullptr"
        head, args = split_cpp_type(cpp)
        if head == "std::vector":
            return "array", "nullptr", "&" + self.element(args[0], nested)
        if head == "std::map":
            return "map", "nullptr", "&" + self.element(args[1], nested)
        qualified = nested.get(cpp, cpp)
        if qualified not in self.types:
            raise GenerationError(f"schema: unknown attribute type {cpp}")
        return "object", "&" + self.types[qualified], "nullptr"

    def element(self, cpp: str, nested: dict[str, str]) -> str:
        kind, type_ptr, item = self.kind(cpp, nested)
        key = (kind, type_ptr, item)
        if key not in self.elements:
            self.elements[key] = f"e{len(self.elements)}"
            self.out.append(f"inline constexpr Field {self.elements[key]}{{\"\", Kind::{kind}, {type_ptr}, {item}, "
                            f"R\"(null)\", false, \"\", \"\", {{}}, {{}}, nullptr, 0, false, false}};")
        return self.elements[key]

    def struct(self, record: "StructRecord") -> str:
        if record.name in self.types:
            raise GenerationError(f"schema: {record.name} generated twice")
        ident = f"t{len(self.types)}"
        rows = []
        for key, cpp, reset, read_only, child in record.members:
            kind, type_ptr, item = self.kind(cpp, record.nested)
            child = child or {}
            category = child.get("category")
            fortios_type = child.get("type") or (category if category in ("table", "complex") else "")
            references = child.get("datasource") or []
            if category == "table" and Emitter.is_ref_table(child):
                references = child["children"]["name"].get("datasource") or []
            size = child.get("size")
            rows.append(f"    {{{cpp_string(key)}, Kind::{kind}, {type_ptr}, {item}, {raw_literal(reset)}, "
                        f"{'true' if read_only else 'false'}, {cpp_string(fortios_type)}, "
                        f"{cpp_string(comment(child.get('help', '')))}, "
                        f"{self.string_list([o['name'] for o in child.get('options') or []])}, "
                        f"{self.string_list(references)}, {self.range(child)}, "
                        f"{size if isinstance(size, int) and size > 0 else 0}, "
                        f"{'true' if child.get('required') else 'false'}, "
                        f"{'true' if child.get('multiple_values') else 'false'}}},")
        help_text = comment(record.node.get("help", ""))
        mkey = record.node.get("mkey", "")
        fields = "{}"
        if rows:
            self.out.append(f"inline constexpr Field {ident}_fields[] = {{  // {record.name}")
            self.out += rows
            self.out.append("};")
            fields = f"{ident}_fields"
        self.out.append(f"inline constexpr Type {ident}{{{cpp_string(record.name)}, {cpp_string(help_text)}, "
                        f"{cpp_string(mkey)}, {fields}}};")
        self.types[record.name] = ident
        return ident


def schema_tables(version: str, emitters: list[Emitter], monitors: list["MonitorEmitter"]) -> str:
    tables = SchemaTables()
    endpoints_rows = []
    for e in emitters:
        ep = e.endpoint
        top = ""
        for record in e.records:
            top = tables.struct(record)
        ns = "fortiapi::" + "::".join(ep.namespace)
        value = tables.element(f"{ns}::{ep.type_name}", {})
        key, key_kind = "", "string"
        if ep.is_table:
            key = ep.schema["mkey"]
            member = next(m for m in e.records[-1].members if m[0] == key)
            key_kind = SCALAR_KINDS[member[1]]
        endpoints_rows.append((f"cmdb/{ep.path}",
                               f"{{{cpp_string('cmdb/' + ep.path)}, EndpointKind::{'table' if ep.is_table else 'singleton'}, "
                               f"&{top}, &{value}, {cpp_string(key)}, Kind::{key_kind}, {cpp_string(f'{ns}::{ep.alias}')}, "
                               f"{cpp_string(ep.header.relative_to(GEN_DIR.parent.parent).as_posix())}}},"))
    for m in monitors:
        mon = m.ep
        type_ptr = "nullptr"
        for record in m.records:
            type_ptr = "&" + tables.struct(record)
        ns = "fortiapi::" + "::".join(mon.namespace)
        data = mon.data if mon.data == "nlohmann::json" else f"{ns}::{mon.data}"
        value = tables.element(f"std::vector<{data}>" if mon.is_list else data, {})
        endpoints_rows.append((f"monitor/{mon.path}",
                               f"{{{cpp_string('monitor/' + mon.path)}, EndpointKind::monitor, {type_ptr}, &{value}, \"\", "
                               f"Kind::string, {cpp_string(f'{ns}::{mon.alias}')}, "
                               f"{cpp_string(mon.header.relative_to(GEN_DIR.parent.parent).as_posix())}}},"))
    endpoints_rows.sort()
    return "\n".join([
        "// Generated by tools/fortios/fortios.py: every generated type and endpoint as data (fortiapi::schema,",
        "// forti_api/schema.hpp). Do not edit.",
        "",
        "#ifndef FORTI_API_GEN_SCHEMA_HPP",
        "#define FORTI_API_GEN_SCHEMA_HPP",
        "",
        '#include "../schema_types.hpp"',
        "",
        "#include <span>",
        "#include <string_view>",
        "",
        "// Hidden: these thousands of inline tables point at each other. With default visibility each is a",
        "// weak exported symbol, and in an executable every one of those pointers becomes a symbol bind that",
        "// the dynamic loader resolves at each start (about 20 ms on macOS, forti-api G15).",
        "#if defined(__GNUC__)",
        "#pragma GCC visibility push(hidden)",
        "#endif",
        "",
        "namespace fortiapi::gen::schema_tables {",
        "",
        "using fortiapi::schema::EndpointKind;",
        "using fortiapi::schema::Field;",
        "using fortiapi::schema::Kind;",
        "using fortiapi::schema::Range;",
        "using fortiapi::schema::Type;",
        "",
        "// fortiapi::Ref: the {\"name\": ...} entries of a table of references.",
        'inline constexpr Field ref_fields[] = {{"name", Kind::string, nullptr, nullptr, R"("")", false, "", "", {}, {}, '
        "nullptr, 0, false, false}};",
        'inline constexpr Type ref{"fortiapi::Ref", "", "name", ref_fields};',
        "",
        *tables.out,
        "",
        "// Sorted by path (fortiapi::schema::find).",
        "inline constexpr fortiapi::schema::Endpoint endpoints[] = {",
        *("    " + row for _, row in endpoints_rows),
        "};",
        "",
        "}  // namespace fortiapi::gen::schema_tables",
        "",
        "#if defined(__GNUC__)",
        "#pragma GCC visibility pop",
        "#endif",
        "",
        "namespace fortiapi::gen {",
        "",
        "// The FortiOS version the generated types follow (codegen/api.toml).",
        f"inline constexpr std::string_view fortios_version = {cpp_string(version)};",
        "",
        "}  // namespace fortiapi::gen",
        "",
        "#endif // FORTI_API_GEN_SCHEMA_HPP",
        "",
    ])


def generate(check: bool = False) -> list[str]:
    """Writes the headers, or with check=True returns the paths that differ from the work tree."""
    files = render_all()
    existing = {p for p in GEN_DIR.rglob("*.hpp")} if GEN_DIR.exists() else set()
    problems = []
    for p in sorted(existing - set(files)):
        problems.append(f"stale: {p.relative_to(ROOT)}")
        if not check:
            p.unlink()
    for p, text in sorted(files.items()):
        if p.exists() and p.read_text() == text:
            continue
        problems.append(f"{'differs' if p.exists() else 'missing'}: {p.relative_to(ROOT)}")
        if not check:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
    if not check and GEN_DIR.exists():
        for d in sorted(GEN_DIR.rglob("*"), reverse=True):
            if d.is_dir() and not any(d.iterdir()):
                d.rmdir()
    return problems
