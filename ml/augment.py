"""Train-time augmentation: consistent random renaming of local identifiers.

Fights the shortcut where a model keys on variable names (`userInput`, `sql`, `id`) instead
of the data flow. API names (req, db, pool, knex, sequelize, ...) and property names are
kept, so the semantics of the code are unchanged.
"""

from __future__ import annotations

import random

import common  # noqa: F401  (puts backend/ on sys.path)
from app.extraction.functions import parse_source

KEEP = {
    "req", "res", "request", "reply", "ctx", "event", "next", "db", "pool", "client", "connection", "conn", "knex",
    "sequelize", "prisma", "util", "format", "sprintf", "vsprintf", "console", "logger", "JSON", "Number", "String",
    "parseInt", "parseFloat", "Math", "Promise", "resolve", "reject", "err", "error", "Error", "QueryTypes", "app",
    "router", "fastify", "exports", "module", "require", "this", "undefined", "mysql", "SqlString", "dataSource",
    "queryRunner", "entityManager", "getManager", "metrics", "Date", "Object", "Array", "sql", "SQL", "Prisma",
}
NAME_POOL = [
    "a", "b", "tmp", "val", "input", "arg", "p", "s", "item", "payload", "field", "entry", "subject", "token",
    "raw", "userValue", "incoming", "candidate", "x1", "y2", "param0", "filterValue", "lookupKey", "q1", "text2",
    "stmtText", "builder", "queryStr", "cmdText", "outRows", "res1", "list", "bucket", "dataSet", "rec",
]
RENAMEABLE = {"identifier", "shorthand_property_identifier_pattern"}


def rename_identifiers(code: str, rng: random.Random, wrap_class: bool = False) -> str:
    source = "class Sample {\n" + code + "\n}" if wrap_class else code
    offset = len(b"class Sample {\n") if wrap_class else 0
    parsed = parse_source(source, "sample.js")
    declared: set[str] = set()
    occurrences: list[tuple[int, int, str]] = []

    stack = [parsed.tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type in ("variable_declarator", "required_parameter"):
            name = node.child_by_field_name("name") or node.child_by_field_name("pattern")
            if name is not None:
                _collect_declared(name, declared)
        elif node.type == "formal_parameters":
            for child in node.named_children:
                _collect_declared(child, declared)
        elif node.type == "arrow_function":
            param = node.child_by_field_name("parameter")
            if param is not None:
                _collect_declared(param, declared)
        elif node.type == "for_in_statement":
            left = node.child_by_field_name("left")
            if left is not None:
                _collect_declared(left, declared)
        if node.type in RENAMEABLE:
            occurrences.append((node.start_byte, node.end_byte, node.text.decode()))

    targets = sorted(n for n in declared if n not in KEEP and not n.isupper())
    if not targets:
        return code
    pool = [n for n in NAME_POOL if n not in declared]
    rng.shuffle(pool)
    mapping = {name: (pool[i] if i < len(pool) else f"v{i}") for i, name in enumerate(targets)}

    src = parsed.source
    out, last = [], 0
    for start, end, text in sorted(occurrences):
        if text in mapping:
            out.append(src[last:start])
            out.append(mapping[text].encode())
            last = end
    out.append(src[last:])
    result = b"".join(out)
    if wrap_class:
        result = result[offset : len(result) - len(b"\n}")]
    return result.decode()


def _collect_declared(node, declared: set[str]) -> None:
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type in ("type_annotation",):
            continue
        if cur.type in ("identifier", "shorthand_property_identifier_pattern"):
            declared.add(cur.text.decode())
            continue
        if cur.type == "pair_pattern":
            value = cur.child_by_field_name("value")
            if value is not None:
                stack.append(value)
            continue
        if cur.type in ("assignment_pattern", "object_assignment_pattern"):
            left = cur.child_by_field_name("left")
            if left is not None:
                stack.append(left)
            continue
        stack.extend(cur.named_children)


if __name__ == "__main__":
    demo = """async (req, res) => {
  const { email } = req.query;
  const sql = "SELECT * FROM users WHERE email = '" + email + "'";
  const [rows] = await pool.query(sql);
  res.json(rows);
}"""
    print(rename_identifiers(demo, random.Random(1)))
