"""v1: AST rule detector with lightweight intra-function taint tracking.

Sources   : request objects (req / ctx / event ...), function parameters, process.argv,
            and values read back from the database (for second-order injection).
Propagation: assignments, destructuring, `+`, template literals, .concat/.join,
            util.format, .replace, string methods, generic calls.
Sanitizers: Number/parseInt/escape..., allow-list checks (`ALLOWED.includes(x)`),
            lookups into constant maps, tagged templates (sql``, Prisma.sql``).
Sinks     : .query/.execute/.raw/$queryRawUnsafe/... whose SQL argument was built unsafely.

The pattern label comes from *how* the SQL string was built and *what* the sink is.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from tree_sitter import Node

from app.detectors.base import Hit, merge_hits_per_unit
from app.extraction.functions import FUNCTION_TYPES, FunctionUnit, ParsedFile, node_text

SQL_RE = re.compile(
    r"\bSELECT\b|\bINSERT\s+INTO\b|\bUPDATE\b\s+[\w\"`.]+\s+SET\b|\bDELETE\s+FROM\b|\bWHERE\b|\bORDER\s+BY\b"
    r"|\bGROUP\s+BY\b|\bVALUES\s*\(|\bFROM\s+[\w\"`.]+|\bJOIN\b|\bLIMIT\b|\bCREATE\s+TABLE\b|\bDROP\s+TABLE\b",
    re.IGNORECASE,
)
_KEYWORD_RE = re.compile(
    r"\b(ORDER\s+BY|GROUP\s+BY|FROM|JOIN|INTO|UPDATE|TABLE|SELECT|DISTINCT|WHERE|AND|OR|SET|VALUES|LIKE|IN|ON"
    r"|HAVING|LIMIT|OFFSET|BETWEEN|NOT|IS)\b",
    re.IGNORECASE,
)
_IDENTIFIER_KEYWORDS = {"ORDER BY", "GROUP BY", "FROM", "JOIN", "INTO", "UPDATE", "TABLE", "SELECT", "DISTINCT"}

REQUEST_PARAM_NAMES = {"req", "request", "ctx", "context", "event", "evt"}
REQUEST_ROOT_IDENTIFIERS = {"req", "request", "ctx", "event"}

SINK_METHODS = {
    "query", "execute", "exec", "raw", "run", "all", "get", "each", "prepare", "none", "one", "many", "any",
    "oneOrNone", "manyOrNone", "multi", "unsafe", "$queryRawUnsafe", "$executeRawUnsafe", "whereRaw",
    "orderByRaw", "havingRaw", "joinRaw", "selectRaw", "groupByRaw", "fromRaw", "unprepared", "batch",
}
ORM_RAW_METHODS = {
    "raw", "whereRaw", "orderByRaw", "havingRaw", "joinRaw", "selectRaw", "groupByRaw", "fromRaw",
    "$queryRawUnsafe", "$executeRawUnsafe",
}
ORM_RECEIVER_RE = re.compile(
    r"sequelize|typeorm|dataSource|datasource|manager|entityManager|queryRunner|repository|repo\b|getManager|"
    r"getConnection|knex|prisma|bookshelf|objection|mikro|orm",
    re.IGNORECASE,
)
PREPARED_RECEIVER_RE = re.compile(r"\.prepare\(|^(stmt|statement|prepared)\w*$", re.IGNORECASE)
SINK_FUNCTION_RE =re.compile(r"(query|exec|execute|sql|runSql|rawQuery)", re.IGNORECASE)

DB_READ_METHODS = SINK_METHODS | {
    "findOne", "findAll", "findByPk", "findUnique", "findFirst", "findMany", "findById", "findOneBy", "findBy",
    "find", "first", "select", "getOne", "getMany", "getRawOne", "getRawMany", "fetch", "fetchOne", "load",
}
AMBIGUOUS_DB_METHODS = {"find", "get", "all", "first", "select", "run", "each", "load", "fetch", "one", "any", "many"}
DB_RECEIVER_RE = re.compile(
    r"\b(db|database|pool|conn|connection|client|knex|sequelize|prisma|repo|repository|manager|model|stmt|"
    r"statement|sql|pg|mysql|sqlite|trx|tx)\b|^[A-Z]\w*$|\.(prepare|request)\(",
    re.IGNORECASE,
)

SANITIZER_FUNCS = {
    "Number", "parseInt", "parseFloat", "Boolean", "escape", "escapeId", "escapeLiteral", "escapeIdentifier",
    "ident", "literal", "quoteIdent", "quoteLiteral", "toInt", "toNumber", "isUUID", "uuidValidate",
    "BigInt", "Math.floor", "Math.round", "Math.trunc",
}
PASSTHROUGH_METHODS = {
    "trim", "trimStart", "trimEnd", "toLowerCase", "toUpperCase", "toString", "slice", "substring", "substr",
    "padStart", "padEnd", "normalize", "valueOf", "toLocaleLowerCase", "toLocaleUpperCase",
}
FORMAT_FUNCS = {"util.format", "format", "sprintf", "vsprintf", "printf", "fmt.format"}
_NAME = r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)"
GUARD_RE = re.compile(
    rf"\.(?:includes|has|indexOf)\(\s*{_NAME}\s*\)|Number\.isInteger\(\s*{_NAME}\s*\)"
    rf"|\.test\(\s*{_NAME}\s*\)|typeof\s+{_NAME}\s*[!=]==?\s*['\"]number['\"]"
)

STATEMENT_TYPES = {
    "program", "statement_block", "class_body", "class_declaration", "switch_body", "switch_case",
    "switch_default", "else_clause", "catch_clause", "finally_clause", "lexical_declaration",
    "variable_declaration", "variable_declarator", "export_statement", "method_definition", "abstract_class_declaration",
    "public_field_definition", "field_definition", "class_static_block",
}

TAINT_CONFIDENCE = {"request": 0.95, "param": 0.85, "stored": 0.82}


@dataclass(frozen=True)
class Build:
    pattern: str
    line: int
    taint: frozenset[str]


@dataclass
class Value:
    taint: frozenset[str] = frozenset()
    sqlish: bool = False
    build: Build | None = None
    literal: str | None = None
    items: list[Value] | None = None
    db_result: bool = False

    @property
    def is_const(self) -> bool:
        return self.literal is not None


CLEAN = Value()


def _union(values: list[Value]) -> frozenset[str]:
    out: set[str] = set()
    for v in values:
        out |= v.taint
    return frozenset(out)


def identifier_position(prefix: str) -> bool:
    """True if a value appended after `prefix` lands in an identifier slot (table/column/ORDER BY)."""
    matches = list(_KEYWORD_RE.finditer(prefix))
    if not matches:
        return False
    last = matches[-1]
    keyword = " ".join(last.group(1).upper().split())
    tail = prefix[last.end() :]
    if keyword in _IDENTIFIER_KEYWORDS:
        return not re.search(r"[=<>'()]", tail)
    return False


_COLUMN_FOLLOWER_RE = re.compile(r"^\s*(=|<>|!=|<=|>=|<|>|LIKE\b|IN\s*\(|IS\b|BETWEEN\b)", re.IGNORECASE)


def column_before_operator(prefix: str, following: str) -> bool:
    """`WHERE ${field} = ...` — the value is used as a column name, not inside a quoted literal."""
    if prefix.rstrip().endswith(("'", '"')):
        return False
    return bool(re.search(r"\b(WHERE|AND|OR|ON|HAVING)\s*$", prefix, re.IGNORECASE)) and bool(
        _COLUMN_FOLLOWER_RE.match(following or "")
    )


class _UnitAnalyzer:
    def __init__(self, unit: FunctionUnit):
        self.unit = unit
        self.env: dict[str, Value] = {}
        self.sanitized: set[str] = set()
        self.hits: list[Hit] = []
        self.skip_nested = unit.kind == "module"
        self.db_calls = 0

    # ------------------------------------------------------------------ entry
    def run(self) -> list[Hit]:
        node = self.unit.node
        if node is None:
            return []
        if node.type in FUNCTION_TYPES:
            self._bind_params(node, default_kind="param")
            body = node.child_by_field_name("body")
            if body is not None:
                self._visit_or_eval(body)
        else:
            self._visit(node)
        return self.hits

    # ---------------------------------------------------------------- binding
    def _bind_params(self, fn: Node, default_kind: str) -> None:
        params = fn.child_by_field_name("parameters") or fn.child_by_field_name("parameter")
        if params is None:
            return
        for name in self._pattern_names(params):
            kind = "request" if name in REQUEST_PARAM_NAMES else default_kind
            self.env[name] = Value(taint=frozenset({kind}))
            self.sanitized.discard(name)

    def _pattern_names(self, node: Node) -> list[str]:
        names: list[str] = []
        stack = [node]
        while stack:
            cur = stack.pop()
            if cur.type in ("type_annotation", "type_arguments", "type_parameters"):
                continue
            if cur.type in ("identifier", "shorthand_property_identifier_pattern"):
                names.append(node_text(cur))
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
        return names

    def _bind_pattern(self, pattern: Node, value: Value) -> None:
        if pattern.type == "identifier":
            self.env[node_text(pattern)] = value
            self.sanitized.discard(node_text(pattern))
            return
        element = Value(taint=value.taint, db_result=value.db_result)
        for name in self._pattern_names(pattern):
            self.env[name] = element
            self.sanitized.discard(name)

    # ------------------------------------------------------------- statements
    def _visit_or_eval(self, node: Node) -> None:
        if node.type in STATEMENT_TYPES or node.type.endswith("_statement"):
            self._visit(node)
        else:
            self._eval(node)

    def _visit(self, node: Node) -> None:
        t = node.type
        if t in FUNCTION_TYPES:
            self._enter_function(node)
            return
        if t == "variable_declarator":
            name = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            value = self._eval(value_node) if value_node is not None else CLEAN
            if name is not None:
                self._bind_pattern(name, value)
            return
        if t == "expression_statement":
            for child in node.named_children:
                self._eval(child)
            return
        if t == "if_statement":
            cond = node.child_by_field_name("condition")
            if cond is not None:
                self._eval(cond)
                self._apply_guards(cond)
            for child in node.named_children:
                if child != cond:
                    self._visit_or_eval(child)
            return
        if t == "for_in_statement":
            right = node.child_by_field_name("right")
            left = node.child_by_field_name("left")
            value = self._eval(right) if right is not None else CLEAN
            if left is not None:
                self._bind_pattern(left, Value(taint=value.taint, db_result=value.db_result))
            body = node.child_by_field_name("body")
            if body is not None:
                self._visit_or_eval(body)
            return
        if t in ("class_declaration", "class") and self.skip_nested:
            return
        for child in node.named_children:
            self._visit_or_eval(child)

    def _apply_guards(self, cond: Node) -> None:
        for match in GUARD_RE.finditer(node_text(cond)):
            name = next(g for g in match.groups() if g)
            self.sanitized.add(name)

    def _enter_function(self, fn: Node, param_kind: str = "param") -> None:
        if self.skip_nested:
            return
        saved_env = dict(self.env)
        saved_sanitized = set(self.sanitized)
        self._bind_params(fn, default_kind=param_kind)
        body = fn.child_by_field_name("body")
        if body is not None:
            self._visit_or_eval(body)
        # Closures may assign outer variables; keep their updates but drop the inner params.
        params = fn.child_by_field_name("parameters") or fn.child_by_field_name("parameter")
        inner_names = set(self._pattern_names(params)) if params is not None else set()
        for name in inner_names:
            if name in saved_env:
                self.env[name] = saved_env[name]
            else:
                self.env.pop(name, None)
        self.sanitized = saved_sanitized | (self.sanitized - inner_names)

    # ------------------------------------------------------------ expressions
    def _eval(self, node: Node | None) -> Value:
        if node is None:
            return CLEAN
        t = node.type

        if t == "string":
            text = node_text(node)[1:-1]
            return Value(sqlish=bool(SQL_RE.search(text)), literal=text)
        if t == "template_string":
            return self._eval_template(node)
        if t in ("number", "true", "false", "null", "undefined", "regex", "this", "super"):
            return Value(literal="")
        if t == "identifier":
            name = node_text(node)
            if name in self.sanitized:
                return CLEAN
            if name in self.env:
                return self.env[name]
            return CLEAN
        if t == "member_expression":
            return self._eval_member(node)
        if t == "subscript_expression":
            obj = self._eval(node.child_by_field_name("object"))
            self._eval(node.child_by_field_name("index"))
            if obj.items is not None:
                return Value(taint=obj.taint, sqlish=obj.sqlish, db_result=obj.db_result)
            return Value(taint=obj.taint, db_result=obj.db_result) if not obj.is_const else CLEAN
        if t == "call_expression":
            return self._eval_call(node)
        if t == "await_expression":
            inner = node.named_children[0] if node.named_children else None
            return self._eval(inner)
        if t in ("parenthesized_expression", "as_expression", "non_null_expression", "satisfies_expression",
                 "type_assertion", "spread_element"):
            inner = node.named_children[0] if node.named_children else None
            return self._eval(inner)
        if t == "binary_expression":
            return self._eval_binary(node)
        if t == "ternary_expression":
            return self._eval_ternary(node)
        if t == "assignment_expression":
            left = node.child_by_field_name("left")
            value = self._eval(node.child_by_field_name("right"))
            if left is not None and left.type in ("identifier", "object_pattern", "array_pattern"):
                self._bind_pattern(left, value)
            return value
        if t == "augmented_assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            op = node_text(node.child_by_field_name("operator"))
            if left is not None and left.type == "identifier" and op == "+=":
                current = self._eval(left)
                value = self._combine([current, self._eval(right)], "concat", node)
                self.env[node_text(left)] = value
                return value
            return self._eval(right)
        if t == "array":
            items = [self._eval(c) for c in node.named_children]
            return Value(
                taint=_union(items),
                sqlish=any(i.sqlish for i in items),
                items=items,
                build=next((i.build for i in items if i.build), None),
            )
        if t in FUNCTION_TYPES:
            self._enter_function(node)
            return CLEAN
        if t in ("unary_expression", "update_expression"):
            for child in node.named_children:
                self._eval(child)
            return CLEAN
        if t == "new_expression":
            # `new Promise((resolve) => db.query(sql, (err, rows) => resolve(rows)))` yields DB rows.
            db_calls_before = self.db_calls
            for child in node.named_children:
                self._eval(child)
            if node_text(node.child_by_field_name("constructor")) == "Promise" and self.db_calls > db_calls_before:
                return Value(taint=frozenset({"stored"}), db_result=True)
            return CLEAN

        # Default: evaluate children (so nested sinks are checked) and propagate taint only.
        values = [self._eval(c) if c.type not in STATEMENT_TYPES else self._visit(c) or CLEAN for c in node.named_children]
        return Value(taint=_union(values), db_result=any(v.db_result for v in values))

    def _eval_member(self, node: Node) -> Value:
        obj_node = node.child_by_field_name("object")
        text = node_text(node)
        root = obj_node
        while root is not None and root.type in ("member_expression", "subscript_expression", "call_expression"):
            root = root.child_by_field_name("object") or root.child_by_field_name("function")
        root_name = node_text(root) if root is not None and root.type == "identifier" else ""

        if text.startswith("process.argv"):
            return Value(taint=frozenset({"request"}))
        obj = self._eval(obj_node)
        if root_name in REQUEST_ROOT_IDENTIFIERS and (root_name not in self.env or "request" in obj.taint):
            if root_name in self.sanitized:
                return CLEAN
            return Value(taint=frozenset({"request"}))
        if text in self.sanitized:
            return CLEAN
        if obj.is_const:
            return CLEAN
        return Value(taint=obj.taint, db_result=obj.db_result)

    def _eval_template(self, node: Node) -> Value:
        parts: list[Value] = []
        has_sub = False
        for child in node.named_children:
            if child.type == "template_substitution":
                has_sub = True
                inner = child.named_children[0] if child.named_children else None
                parts.append(self._eval(inner))
            elif child.type in ("string_fragment", "escape_sequence"):
                parts.append(Value(literal=node_text(child)))
        if not has_sub:
            text = "".join(p.literal or "" for p in parts)
            return Value(sqlish=bool(SQL_RE.search(text)), literal=text)
        return self._combine(parts, "template", node)

    def _flatten_concat(self, node: Node) -> list[Node]:
        if node.type == "binary_expression" and node_text(node.child_by_field_name("operator")) == "+":
            return self._flatten_concat(node.child_by_field_name("left")) + self._flatten_concat(
                node.child_by_field_name("right")
            )
        if node.type == "parenthesized_expression" and node.named_children:
            inner = node.named_children[0]
            if inner.type == "binary_expression" and node_text(inner.child_by_field_name("operator")) == "+":
                return self._flatten_concat(inner)
        return [node]

    def _eval_binary(self, node: Node) -> Value:
        op = node_text(node.child_by_field_name("operator"))
        if op == "+":
            parts = [self._eval(n) for n in self._flatten_concat(node)]
            return self._combine(parts, "concat", node)
        left = self._eval(node.child_by_field_name("left"))
        right = self._eval(node.child_by_field_name("right"))
        if op in ("||", "??", "&&"):
            pick = [v for v in (left, right) if not v.is_const] or [left]
            return Value(
                taint=_union(pick),
                sqlish=any(v.sqlish for v in (left, right)),
                build=left.build or right.build,
                db_result=left.db_result or right.db_result,
            )
        return CLEAN  # comparisons / arithmetic produce booleans / numbers

    def _eval_ternary(self, node: Node) -> Value:
        cond = node.child_by_field_name("condition")
        cons = self._eval(node.child_by_field_name("consequence"))
        alt = self._eval(node.child_by_field_name("alternative"))
        self._eval(cond)
        if cond is not None and GUARD_RE.search(node_text(cond)):
            return Value(sqlish=cons.sqlish or alt.sqlish)
        return Value(
            taint=_union([cons, alt]),
            sqlish=cons.sqlish or alt.sqlish,
            build=cons.build or alt.build,
            db_result=cons.db_result or alt.db_result,
        )

    def _combine(self, parts: list[Value], mode: str, node: Node) -> Value:
        taint = _union([p for p in parts if not p.is_const])
        literal_text = " ".join(p.literal for p in parts if p.literal)
        sqlish = any(p.sqlish for p in parts) or bool(SQL_RE.search(literal_text))
        existing = next((p.build for p in parts if p.build), None)
        if all(p.is_const for p in parts):
            text = "".join(p.literal or "" for p in parts)
            return Value(sqlish=bool(SQL_RE.search(text)) or sqlish, literal=text)

        build = existing
        if taint and sqlish and existing is None:
            prefix = ""
            identifier_slot = False
            for i, part in enumerate(parts):
                if part.is_const:
                    prefix += part.literal or ""
                    continue
                following = parts[i + 1].literal if i + 1 < len(parts) and parts[i + 1].is_const else ""
                if part.taint and (identifier_position(prefix) or column_before_operator(prefix, following)):
                    identifier_slot = True
                prefix += " ? "
            if identifier_slot:
                pattern = "DYNAMIC_IDENTIFIER"
            else:
                pattern = "TEMPLATE_LITERAL" if mode == "template" else "STRING_CONCAT"
            build = Build(pattern=pattern, line=node.start_point[0] + 1, taint=taint)
        elif existing is not None and taint - existing.taint:
            build = Build(pattern=existing.pattern, line=existing.line, taint=existing.taint | taint)
        return Value(taint=taint, sqlish=sqlish, build=build)

    # ------------------------------------------------------------------ calls
    def _eval_call(self, node: Node) -> Value:
        callee = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")
        callee_text = node_text(callee)
        line = node.start_point[0] + 1

        method = ""
        receiver_node: Node | None = None
        if callee is not None and callee.type == "member_expression":
            method = node_text(callee.child_by_field_name("property"))
            receiver_node = callee.child_by_field_name("object")
        elif callee is not None and callee.type == "identifier":
            method = callee_text

        # Tagged template: sql`...`, Prisma.sql`...`, prisma.$queryRaw`...` -> parameterized.
        if args_node is not None and args_node.type == "template_string":
            for sub in args_node.named_children:
                if sub.type == "template_substitution":
                    for c in sub.named_children:
                        self._eval(c)
            return Value(db_result=True)

        receiver = self._eval(receiver_node) if receiver_node is not None else CLEAN
        receiver_text = node_text(receiver_node) if receiver_node is not None else ""
        is_db_call = method in DB_READ_METHODS and (
            method not in AMBIGUOUS_DB_METHODS or bool(DB_RECEIVER_RE.search(receiver_text))
        )
        if is_db_call:
            self.db_calls += 1
        callback_kind = "stored" if is_db_call or (method == "then" and receiver.db_result) else "param"

        arg_nodes = list(args_node.named_children) if args_node is not None else []
        args: list[Value] = []
        for arg in arg_nodes:
            if arg.type in FUNCTION_TYPES:
                self._enter_function(arg, param_kind=callback_kind)
                args.append(CLEAN)
            else:
                args.append(self._eval(arg))

        short = callee_text.split("(")[0]
        if method in SANITIZER_FUNCS or short in SANITIZER_FUNCS or short.endswith(".escape"):
            return Value(literal="")

        if short in FORMAT_FUNCS and args:
            fmt, rest = args[0], args[1:]
            rest_taint = _union(rest)
            unsafe_fmt = fmt.literal is None or "%s" in (fmt.literal or "")
            if fmt.sqlish and rest_taint and unsafe_fmt:
                return Value(taint=rest_taint, sqlish=True, build=Build("UNSAFE_FORMAT", line, rest_taint))
            return Value(sqlish=fmt.sqlish, taint=rest_taint if unsafe_fmt else frozenset())

        if method in ("replace", "replaceAll") and receiver_node is not None:
            replacement = args[1] if len(args) > 1 else CLEAN
            if receiver.sqlish and replacement.taint:
                taint = receiver.taint | replacement.taint
                return Value(taint=taint, sqlish=True, build=receiver.build or Build("UNSAFE_FORMAT", line, taint))
            return Value(taint=receiver.taint | replacement.taint, sqlish=receiver.sqlish, build=receiver.build)

        if method == "join" and receiver.items is not None:
            sep = args[0] if args else Value(literal=",")
            parts: list[Value] = []
            for i, item in enumerate(receiver.items):
                if i:
                    parts.append(sep if sep.is_const else Value(literal=" "))
                parts.append(item)
            return self._combine(parts, "concat", node)
        if method == "concat" and receiver_node is not None and (receiver.sqlish or receiver.is_const):
            return self._combine([receiver, *args], "concat", node)
        if method in PASSTHROUGH_METHODS and receiver_node is not None:
            return receiver

        if self._is_sink(method, callee, receiver_text) and args:
            self._check_sink(node, method, callee_text, receiver_text, args[0])

        if is_db_call:
            return Value(taint=frozenset({"stored"}), db_result=True)
        if method == "then" and receiver.db_result:
            return Value(taint=frozenset({"stored"}), db_result=True)
        taint = receiver.taint | _union(args)
        return Value(taint=taint, db_result=receiver.db_result)

    @staticmethod
    def _is_sink(method: str, callee: Node | None, receiver_text: str) -> bool:
        if callee is None:
            return False
        if callee.type == "member_expression":
            # db.prepare(sql).all(a, b): arguments of a prepared statement are bind parameters.
            if PREPARED_RECEIVER_RE.search(receiver_text):
                return False
            return method in SINK_METHODS
        return bool(SINK_FUNCTION_RE.search(method))

    def _check_sink(self, node: Node, method: str, callee_text: str, receiver_text: str, sql: Value) -> None:
        is_orm = method in ORM_RAW_METHODS or (
            method in ("query", "execute") and bool(ORM_RECEIVER_RE.search(receiver_text))
        )
        line = node.start_point[0] + 1
        if sql.build is not None:
            taint = sql.build.taint or sql.taint
            build_line = sql.build.line
            pattern = sql.build.pattern
        elif sql.taint and (is_orm or "request" in sql.taint) and method not in AMBIGUOUS_DB_METHODS:
            # The whole SQL string comes straight from a tainted source.
            taint = sql.taint
            build_line = line
            pattern = "STRING_CONCAT"
        else:
            return

        if is_orm:
            pattern = "ORM_RAW_QUERY"
        elif taint == frozenset({"stored"}):
            pattern = "SECOND_ORDER"

        confidence = max(TAINT_CONFIDENCE.get(k, 0.8) for k in taint) if taint else 0.7
        if sql.build is None:
            confidence -= 0.15
        source = ", ".join(sorted(taint)) or "unknown"
        self.hits.append(
            Hit(
                unit=self.unit,
                pattern=pattern,
                confidence=round(confidence, 4),
                vulnerable_probability=round(confidence, 4),
                detector="ast",
                message=(
                    f"SQL built on line {build_line} from {source} input reaches `{callee_text}` on line {line} "
                    f"without parameterization."
                ),
                evidence_lines=sorted({build_line, line}),
            )
        )


def _context_rank(hit: Hit) -> tuple[int, int, float]:
    return (hit.unit.kind != "module", hit.unit.line_count, hit.confidence)


class AstRuleDetector:
    name = "ast"

    @property
    def available(self) -> bool:
        return True

    def analyze_unit(self, unit: FunctionUnit) -> list[Hit]:
        return _UnitAnalyzer(unit).run()

    def detect(self, parsed: ParsedFile) -> list[Hit]:
        # The same sink is seen by every enclosing function. The outermost (non-module) analysis has
        # the most data-flow context — e.g. it knows a nested callback's `rows` came from the DB.
        best_by_sink: dict[tuple[int, ...], Hit] = {}
        for unit in parsed.units:
            for hit in self.analyze_unit(unit):
                key = tuple(hit.evidence_lines[-1:])
                current = best_by_sink.get(key)
                if current is None or _context_rank(hit) > _context_rank(current):
                    best_by_sink[key] = hit
        return merge_hits_per_unit(list(best_by_sink.values()))
