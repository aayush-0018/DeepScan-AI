"""Function-level extraction of JavaScript / TypeScript source using tree-sitter.

Every detector and the ML pipeline consume the same `FunctionUnit`s, so training data
and inference input are produced by identical code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cache
from pathlib import PurePosixPath

import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts
from tree_sitter import Language, Node, Parser, Tree

FUNCTION_TYPES = {
    "function_declaration",
    "function_expression",
    "function",  # older grammar name for function expressions
    "arrow_function",
    "method_definition",
    "generator_function_declaration",
    "generator_function",
}

LANGUAGE_BY_EXT = {
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
}
SUPPORTED_EXTENSIONS = tuple(LANGUAGE_BY_EXT)


@dataclass
class FunctionUnit:
    name: str
    kind: str  # function | method | arrow | callback | module
    start_line: int  # 1-based, inclusive
    end_line: int
    code: str
    file: str
    node: Node | None = field(default=None, repr=False, compare=False)
    depth: int = 0  # nesting depth (0 = top-level function or module)

    @property
    def line_count(self) -> int:
        return self.end_line - self.start_line + 1


@dataclass
class ParsedFile:
    file: str
    language: str
    source: bytes
    tree: Tree
    units: list[FunctionUnit]

    @property
    def has_errors(self) -> bool:
        return self.tree.root_node.has_error


@cache
def _language(name: str) -> Language:
    if name == "javascript":
        return Language(tsjs.language())
    if name == "typescript":
        return Language(tsts.language_typescript())
    if name == "tsx":
        return Language(tsts.language_tsx())
    raise ValueError(f"Unsupported language: {name}")


def get_parser(language: str) -> Parser:
    return Parser(_language(language))


def detect_language(filename: str, explicit: str | None = None) -> str:
    if explicit:
        return explicit
    return LANGUAGE_BY_EXT.get(PurePosixPath(filename).suffix.lower(), "javascript")


def node_text(node: Node | None) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", errors="replace")


def _short(text: str, limit: int = 40) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def function_name(node: Node) -> tuple[str, str]:
    """Return (display_name, kind) for a function-like node."""
    line = node.start_point[0] + 1
    name_node = node.child_by_field_name("name")

    if node.type == "method_definition":
        cls = _enclosing_class_name(node)
        method = node_text(name_node) or "<method>"
        return (f"{cls}.{method}" if cls else method), "method"

    if name_node is not None:
        return node_text(name_node), "function"

    kind = "arrow" if node.type == "arrow_function" else "function"
    parent = node.parent
    # Unwrap `await`, parentheses, etc.
    while parent is not None and parent.type in ("parenthesized_expression", "await_expression"):
        parent = parent.parent
    if parent is None:
        return f"<anonymous@{line}>", kind

    if parent.type == "variable_declarator":
        return node_text(parent.child_by_field_name("name")), kind
    if parent.type in ("assignment_expression", "augmented_assignment_expression"):
        return _short(node_text(parent.child_by_field_name("left"))), kind
    if parent.type == "pair":
        return _short(node_text(parent.child_by_field_name("key"))), kind
    if parent.type in ("public_field_definition", "field_definition"):
        cls = _enclosing_class_name(node)
        prop = node_text(parent.child_by_field_name("name") or parent.child_by_field_name("property"))
        return (f"{cls}.{prop}" if cls else prop), kind
    if parent.type == "arguments":
        call = parent.parent
        if call is not None and call.type == "call_expression":
            callee = node_text(call.child_by_field_name("function"))
            first = parent.named_children[0] if parent.named_children else None
            route = ""
            if first is not None and first.type in ("string", "template_string") and first != node:
                route = f" {node_text(first)}"
            return f"{_short(callee)}({_short(route.strip(), 30)}) callback", "callback"
    if parent.type == "export_statement":
        return "default export", kind
    return f"<anonymous@{line}>", kind


def _enclosing_class_name(node: Node) -> str | None:
    cur = node.parent
    while cur is not None:
        if cur.type in ("class_declaration", "class", "abstract_class_declaration"):
            return node_text(cur.child_by_field_name("name")) or None
        cur = cur.parent
    return None


def _walk(node: Node):
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(reversed(cur.children))


def _function_depth(node: Node) -> int:
    depth = 0
    cur = node.parent
    while cur is not None:
        if cur.type in FUNCTION_TYPES and cur.is_named:
            depth += 1
        cur = cur.parent
    return depth


def _has_top_level_code(root: Node) -> bool:
    """True if the module has executable statements beyond imports / declarations of functions."""
    declarative = {
        "import_statement",
        "function_declaration",
        "generator_function_declaration",
        "class_declaration",
        "comment",
        "empty_statement",
        "interface_declaration",
        "type_alias_declaration",
        "enum_declaration",
    }
    for child in root.named_children:
        if child.type in declarative:
            continue
        if child.type == "export_statement":
            decl = child.child_by_field_name("declaration")
            if decl is not None and decl.type in declarative:
                continue
        if child.type == "lexical_declaration" and all(
            (d.child_by_field_name("value") is not None and d.child_by_field_name("value").type in FUNCTION_TYPES)
            for d in child.named_children
            if d.type == "variable_declarator"
        ):
            continue
        return True
    return False


def parse_source(code: str, filename: str = "snippet.js", language: str | None = None) -> ParsedFile:
    language = detect_language(filename, language)
    source = code.encode("utf-8")
    tree = get_parser(language).parse(source)
    root = tree.root_node

    units: list[FunctionUnit] = []
    for node in _walk(root):
        if node.type not in FUNCTION_TYPES or not node.is_named:
            continue
        name, kind = function_name(node)
        # For methods / named function expressions include the full declaration text.
        units.append(
            FunctionUnit(
                name=name,
                kind=kind,
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                code=node_text(node),
                file=filename,
                node=node,
                depth=_function_depth(node),
            )
        )

    if not units or _has_top_level_code(root):
        units.insert(
            0,
            FunctionUnit(
                name="<module>",
                kind="module",
                start_line=1,
                end_line=root.end_point[0] + 1,
                code=code,
                file=filename,
                node=root,
                depth=0,
            ),
        )
    return ParsedFile(file=filename, language=language, source=source, tree=tree, units=units)


def extract_functions(code: str, filename: str = "snippet.js", language: str | None = None) -> list[FunctionUnit]:
    return parse_source(code, filename, language).units
