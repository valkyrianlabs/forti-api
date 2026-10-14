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
    # names the generated code itself uses
    "visit", "fortiapi", "std", "self", "v",
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
    if out in CPP_KEYWORDS:
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
class Emitter:
    endpoint: Endpoint
    lines: list[str] = field(default_factory=list)
    constants: list[tuple[list[str], list[tuple[str, str]]]] = field(default_factory=list)

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
        children = node.get("children") or {}
        members: list[tuple[str, str, str, str, str]] = []   # key, member, cpp type, reset, flags
        nested: list[tuple[str, dict, list[str]]] = []
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
                        raise GenerationError(f"{self.endpoint.path}: nested type {entry} collides in {name}")
                    used_types.add(entry)
                    nested.append((entry, child, scope))
                    cpp = f"std::vector<{entry}>"
            elif category == "complex":
                sub = camel(key)
                if sub in used_types or sub == name:
                    raise GenerationError(f"{self.endpoint.path}: nested type {sub} collides in {name}")
                used_types.add(sub)
                nested.append((sub, child, scope))
                cpp = sub
            else:
                cpp = self.scalar_type(child)
                if child.get("options"):
                    self.add_constants(scope, child["options"])
            flags = "fortiapi::read_only" if child.get("readonly") or category == "info-read-only" else "fortiapi::none"
            members.append((key, member, cpp, self.reset_value(child, cpp), flags))

        if doc:
            self.emit(f"// {comment(doc)}", indent)
        self.emit(f"struct {name} {{", indent)
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
        self.emit()
        self.emit("template<typename Self, typename Visitor>", indent + 1)
        self.emit("static void visit(Self& self, Visitor&& v) {", indent + 1)
        for key, member, _, reset, flags in members:
            self.emit(f"v({cpp_string(key)}, self.{member}, {raw_literal(reset)}, {flags});", indent + 2)
        if not members:
            self.emit("(void) self; (void) v;", indent + 2)
        self.emit("}", indent + 1)
        self.emit("};", indent)

    def add_constants(self, scope: list[str], options: list[dict]) -> None:
        values, seen = [], set()
        for option in options:
            value = option["name"]
            name = identifier(value)
            base, n = name, 2
            while name in seen:
                name, n = f"{base}_{n}", n + 1
            seen.add(name)
            values.append((name, value))
        self.constants.append((scope, values))

    # -- header ------------------------------------------------------------------------------------

    def render(self, version: str) -> str:
        ep = self.endpoint
        ns = "fortiapi::" + "::".join(identifier(p) for p in ep.namespace)
        rel_include = Path("../" * (len(ep.header.relative_to(GEN_DIR).parts) - 1 + 1)) / "endpoint.hpp"
        snapshot = ep.snapshot.relative_to(ROOT).as_posix()

        body = Emitter(ep)
        body.struct(ep.type_name, ep.schema, 0, [snake(ep.type_name)], ep.schema.get("help"))
        self.constants = body.constants

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
        if self.constants:
            out += ["", "// Allowed values of option attributes."]
            for scope, values in self.constants:
                out.append(f"namespace {'::'.join(scope)} {{")
                for name, value in values:
                    out.append(f"    inline constexpr std::string_view {name} = {cpp_string(value)};")
                out.append("}")
        out += ["", f"}}  // namespace {ns}", "", f"#endif // {ep.guard}", ""]
        return "\n".join(out)


def load_manifest() -> tuple[str, list[dict]]:
    data = tomllib.loads(MANIFEST.read_text())
    version = data.get("fortios_version")
    if not version:
        raise GenerationError(f"{MANIFEST}: fortios_version is required")
    entries = data.get("cmdb", [])
    paths = [e["path"] for e in entries]
    if len(paths) != len(set(paths)):
        raise GenerationError(f"{MANIFEST}: duplicate paths")
    return version, entries


def snapshot_path(version: str, api_path: str) -> Path:
    collection, _, name = api_path.partition("/")
    return ROOT / "codegen" / "schema" / version / "cmdb" / collection / f"{name}.json"


def endpoints() -> tuple[str, list[Endpoint]]:
    version, entries = load_manifest()
    out, names = [], {}
    for entry in sorted(entries, key=lambda e: e["path"]):
        api_path = entry["path"]
        snap = snapshot_path(version, api_path)
        if not snap.exists():
            raise GenerationError(f"{api_path}: no schema snapshot at {snap.relative_to(ROOT)} (run `fortios.py pull`)")
        schema = json.loads(snap.read_text())
        collection, _, name = api_path.partition("/")
        namespace = entry.get("namespace", collection).replace("-", "_").split(".")
        type_name = entry.get("type", camel(name))
        is_table = schema.get("category") == "table"
        alias = entry.get("alias", plural(type_name) if is_table else type_name + "Settings")
        ep = Endpoint(api_path, namespace, type_name, alias, schema, snap)
        for symbol in (type_name, alias, type_name + "Spec", snake(type_name)):
            qualified = "::".join(namespace + [symbol])
            if qualified in names:
                raise GenerationError(f"{api_path}: {qualified} also generated by {names[qualified]}")
            names[qualified] = api_path
        out.append(ep)
    return version, out


def render_all() -> dict[Path, str]:
    version, eps = endpoints()
    files = {ep.header: Emitter(ep).render(version) for ep in eps}
    includes = sorted(f'#include "{p.relative_to(GEN_DIR).as_posix()}"' for p in files)
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
    return files


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
