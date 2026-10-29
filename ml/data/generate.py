"""Synthetic JavaScript sample generator for the 7-class SQLi dataset.

Each sample is composed from independent parts so the model has to learn the *cause*
(how untrusted data reaches SQL) rather than surface cues:

    wrapper (express / koa / fastify / next / lambda / service / class ...)
  x driver  (mysql2 / mysql callbacks / pg / sqlite3 / better-sqlite3 / mssql / pg-promise)
  x shape   (SELECT / INSERT / UPDATE / DELETE / LIKE / multi-filter ...)
  x variant (how the query is built: concat, template, format, ORM raw, ...)
  x noise   (validation, logging, comments, try/catch, renamed identifiers)

Some wrappers, drivers and variants are reserved for the *held-out* set and never appear
in train/val/test, which gives an honest generalization number.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import dataclass, field
from pathlib import Path

ENTITIES: dict[str, dict[str, bool]] = {
    # table -> {column: is_numeric}
    "users": {"id": True, "email": False, "username": False, "role": False, "status": False, "age": True},
    "orders": {"id": True, "status": False, "customer_id": True, "total": True, "reference": False},
    "products": {"id": True, "name": False, "category": False, "price": True, "sku": False},
    "invoices": {"id": True, "number": False, "account_id": True, "state": False, "amount": True},
    "comments": {"id": True, "post_id": True, "author": False, "body": False},
    "accounts": {"id": True, "iban": False, "owner": False, "type": False, "balance": True},
    "sessions": {"id": True, "token": False, "user_id": True, "ip": False},
    "tickets": {"id": True, "title": False, "priority": False, "assignee": False},
    "employees": {"id": True, "department": False, "manager_id": True, "last_name": False, "salary": True},
    "posts": {"id": True, "slug": False, "title": False, "author_id": True, "published": True},
    "customers": {"id": True, "phone": False, "country": False, "company": False},
    "payments": {"id": True, "provider": False, "order_id": True, "currency": False},
    "audit_log": {"id": True, "actor": False, "action": False, "target": False},
    "files": {"id": True, "path": False, "owner_id": True, "mime": False},
}

ALT_NAMES = [
    "value", "input", "param", "arg", "term", "needle", "filter", "key", "lookup", "selector", "target",
    "criteria", "token", "ref", "item", "x", "v", "val", "query", "q", "data", "field", "subject", "entry",
]
SQL_VARS = ["sql", "query", "q", "stmt", "statement", "queryText", "sqlQuery", "text", "selectSql", "cmd"]
RESULT_VARS = ["result", "rows", "records", "data", "items", "found", "res2", "resultSet", "entries"]

WRAPPERS = ["express_arrow", "express_fn", "router_destructure", "fastify", "next_api", "service_fn",
            "class_method", "callback_service", "koa", "lambda"]
DRIVERS = ["mysql2", "mysql_cb", "pg", "sqlite3", "better_sqlite3", "mssql", "pg_promise"]

HELDOUT_WRAPPERS = {"koa", "lambda"}
HELDOUT_DRIVERS = {"mssql", "pg_promise"}
HELDOUT_VARIANTS = {
    "c_join", "t_helper", "d_where_column", "o_typeorm", "f_sprintf", "so_loop", "s_tagged_sql", "s_pgformat",
}


def camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(p.capitalize() for p in rest)


@dataclass
class Inp:
    var: str
    column: str
    numeric: bool
    source: str = "query"  # query | body | params


@dataclass
class Ctx:
    rng: random.Random
    wrapper: str
    driver: str
    table: str
    inputs: list[Inp] = field(default_factory=list)
    sql_var: str = "sql"
    result_var: str = "result"
    quote: str = '"'

    def lit(self, text: str) -> str:
        q = self.quote
        return q + text.replace("\\", "\\\\").replace(q, "\\" + q) + q

    def pick(self, seq):
        return self.rng.choice(list(seq))


# --------------------------------------------------------------------------- SQL shapes
# A shape is a list of segments: str literals and ("V", i) value slots / ("I", i) identifier slots.

def shape_select_where(ctx: Ctx):
    cols = ENTITIES[ctx.table]
    col = ctx.pick(cols)
    proj = ctx.pick(["*", ", ".join(ctx.rng.sample(list(cols), k=min(3, len(cols)))), "id"])
    ctx.inputs = [Inp(camel(col), col, cols[col])]
    return [f"SELECT {proj} FROM {ctx.table} WHERE {col} = ", ("V", 0)]


def shape_select_and(ctx: Ctx):
    cols = ENTITIES[ctx.table]
    c1, c2 = ctx.rng.sample(list(cols), 2)
    ctx.inputs = [Inp(camel(c1), c1, cols[c1]), Inp(camel(c2), c2, cols[c2])]
    return [f"SELECT * FROM {ctx.table} WHERE {c1} = ", ("V", 0), f" AND {c2} = ", ("V", 1)]


def shape_like(ctx: Ctx):
    cols = [c for c, num in ENTITIES[ctx.table].items() if not num]
    col = ctx.pick(cols)
    ctx.inputs = [Inp(ctx.pick(["search", "term", "q", "keyword", camel(col)]), col, False)]
    return [f"SELECT * FROM {ctx.table} WHERE {col} LIKE ", ("V", 0), " LIMIT 50"]


def shape_delete(ctx: Ctx):
    ctx.inputs = [Inp(ctx.pick(["id", f"{ctx.table[:-1]}Id", "recordId"]), "id", True, "params")]
    return [f"DELETE FROM {ctx.table} WHERE id = ", ("V", 0)]


def shape_update(ctx: Ctx):
    cols = ENTITIES[ctx.table]
    col = ctx.pick([c for c in cols if c != "id"])
    ctx.inputs = [Inp(camel(col), col, cols[col], "body"), Inp("id", "id", True, "params")]
    return [f"UPDATE {ctx.table} SET {col} = ", ("V", 0), " WHERE id = ", ("V", 1)]


def shape_insert(ctx: Ctx):
    cols = ENTITIES[ctx.table]
    c1, c2 = ctx.rng.sample([c for c in cols if c != "id"], 2)
    ctx.inputs = [Inp(camel(c1), c1, cols[c1], "body"), Inp(camel(c2), c2, cols[c2], "body")]
    return [f"INSERT INTO {ctx.table} ({c1}, {c2}) VALUES (", ("V", 0), ", ", ("V", 1), ")"]


def shape_count(ctx: Ctx):
    cols = ENTITIES[ctx.table]
    col = ctx.pick([c for c in cols if c != "id"])
    ctx.inputs = [Inp(camel(col), col, cols[col])]
    return [f"SELECT COUNT(*) AS total FROM {ctx.table} WHERE {col} = ", ("V", 0)]


VALUE_SHAPES = {
    "select_where": shape_select_where, "select_and": shape_select_and, "like": shape_like,
    "delete": shape_delete, "update": shape_update, "insert": shape_insert, "count": shape_count,
}


def shape_order_by(ctx: Ctx):
    ctx.inputs = [Inp(ctx.pick(["sort", "sortBy", "orderBy", "order", "column"]), "sort", False)]
    return [f"SELECT * FROM {ctx.table} ORDER BY ", ("I", 0)]


def shape_order_dir(ctx: Ctx):
    col = ctx.pick(ENTITIES[ctx.table])
    ctx.inputs = [Inp(ctx.pick(["dir", "direction", "order", "sortDir"]), "dir", False)]
    return [f"SELECT * FROM {ctx.table} ORDER BY {col} ", ("I", 0)]


def shape_select_cols(ctx: Ctx):
    ctx.inputs = [Inp(ctx.pick(["fields", "columns", "cols", "select"]), "fields", False)]
    return ["SELECT ", ("I", 0), f" FROM {ctx.table} LIMIT 100"]


def shape_from_table(ctx: Ctx):
    ctx.inputs = [Inp(ctx.pick(["table", "tableName", "entity", "resource", "collection"]), "table", False, "params")]
    return ["SELECT * FROM ", ("I", 0), " WHERE deleted_at IS NULL"]


def shape_group_by(ctx: Ctx):
    ctx.inputs = [Inp(ctx.pick(["groupBy", "group", "dimension"]), "group", False)]
    return ["SELECT ", ("I", 0), f", COUNT(*) AS n FROM {ctx.table} GROUP BY ", ("I", 0)]


def shape_where_column(ctx: Ctx):
    ctx.inputs = [Inp(ctx.pick(["field", "column", "attr", "by"]), "field", False), Inp("value", "value", False)]
    return [f"SELECT * FROM {ctx.table} WHERE ", ("I", 0), " = ", ("V", 1)]


IDENT_SHAPES = {
    "order_by": shape_order_by, "order_dir": shape_order_dir, "select_cols": shape_select_cols,
    "from_table": shape_from_table, "group_by": shape_group_by, "where_column": shape_where_column,
}


# --------------------------------------------------------------------------- renderers
def _quoted(ctx: Ctx, slot) -> bool:
    kind, i = slot
    return kind == "V" and not ctx.inputs[i].numeric


def render_concat(ctx: Ctx, segs, only=None) -> str:
    """JS concatenation expression; slots in `only` (or all) are inlined unsafely."""
    parts: list[str] = []
    buf = ""
    for seg in segs:
        if isinstance(seg, str):
            buf += seg
            continue
        if only is not None and seg[1] not in only:
            buf += "?"
            continue
        q = "'" if _quoted(ctx, seg) else ""
        if q and buf.rstrip().endswith("LIKE"):
            buf += "'%"
            parts.append(ctx.lit(buf))
            parts.append(ctx.inputs[seg[1]].var)
            buf = "%'"
            continue
        buf += q
        parts.append(ctx.lit(buf))
        parts.append(ctx.inputs[seg[1]].var)
        buf = q
    if buf:
        parts.append(ctx.lit(buf))
    return " + ".join(parts)


def render_template(ctx: Ctx, segs, only=None) -> str:
    out = ""
    for seg in segs:
        if isinstance(seg, str):
            out += seg.replace("`", "\\`").replace("${", "\\${")
            continue
        if only is not None and seg[1] not in only:
            out += "?"
            continue
        q = "'" if _quoted(ctx, seg) else ""
        if q and out.rstrip().endswith("LIKE"):
            out += "'%${" + ctx.inputs[seg[1]].var + "}%'"
        else:
            out += q + "${" + ctx.inputs[seg[1]].var + "}" + q
    return "`" + out + "`"


def placeholder_style(driver: str) -> str:
    return {"pg": "dollar", "pg_promise": "dollar", "mssql": "at"}.get(driver, "qmark")


def render_params(ctx: Ctx, segs, style: str, inline_idents: bool = False):
    """Parameterized SQL literal + list of bound vars (identifier slots must be resolved by caller)."""
    sql, params, n = "", [], 0
    for seg in segs:
        if isinstance(seg, str):
            sql += seg
            continue
        kind, i = seg
        if kind == "I":
            sql += "${" + ctx.inputs[i].var + "}" if inline_idents else ctx.inputs[i].var
            continue
        var = ctx.inputs[i].var
        if sql.rstrip().endswith("LIKE"):
            var = f"`%${{{var}}}%`"
        n += 1
        sql += {"qmark": "?", "dollar": f"${n}", "at": f"@{ctx.inputs[i].column.replace('_', '')}{n}",
                "named": f":{ctx.inputs[i].var}"}[style]
        params.append(var)
    return sql, params


# --------------------------------------------------------------------------- drivers
def driver_exec(ctx: Ctx, sql_expr: str, params: list[str] | None, multi_values=False) -> list[str]:
    r = ctx.result_var
    p = "[" + ", ".join(params) + "]" if params else None
    d = ctx.driver
    if d == "mysql2":
        return [f"const [{r}] = await pool.query({sql_expr}{', ' + p if p else ''});"]
    if d == "mysql_cb":
        return [
            f"const {r} = await new Promise((resolve, reject) => {{",
            f"  connection.query({sql_expr}{', ' + p if p else ''}, (err, rows) => (err ? reject(err) : resolve(rows)));",
            "});",
        ]
    if d == "pg":
        return [f"const {{ rows: {r} }} = await client.query({sql_expr}{', ' + p if p else ''});"]
    if d == "sqlite3":
        return [f"const {r} = await db.all({sql_expr}{', ' + p if p else ''});"]
    if d == "better_sqlite3":
        args = ", ".join(params) if params else ""
        return [f"const {r} = db.prepare({sql_expr}).all({args});"]
    if d == "pg_promise":
        return [f"const {r} = await db.any({sql_expr}{', ' + p if p else ''});"]
    if d == "mssql":
        lines = ["const request = pool.request();"]
        for i, prm in enumerate(params or []):
            lines.append(f"request.input('p{i + 1}', {prm});")
        lines.append(f"const {{ recordset: {r} }} = await request.query({sql_expr});")
        return lines
    raise ValueError(d)


def mssql_fix(sql: str) -> str:
    import re

    counter = iter(range(1, 100))
    return re.sub(r"@\w+?\d+", lambda _m: f"@p{next(counter)}", sql)


def safe_exec(ctx: Ctx, segs) -> list[str]:
    style = placeholder_style(ctx.driver)
    sql, params = render_params(ctx, segs, style)
    if ctx.driver == "mssql":
        sql = mssql_fix(sql)
    if ctx.rng.random() < 0.5:
        return [f"const {ctx.sql_var} = {ctx.lit(sql)};"] + driver_exec(ctx, ctx.sql_var, params)
    return driver_exec(ctx, ctx.lit(sql), params)


# --------------------------------------------------------------------------- wrappers
def wrap(ctx: Ctx, body: list[str], fn_name: str, extra_inputs_from_body: bool = False) -> str:
    rng = ctx.rng
    w = ctx.wrapper
    ind = "  "
    route = f"/api/{ctx.table}" + rng.choice(["", "/search", "/:id", "/list", "/export", "/filter"])
    method = rng.choice(["get", "post", "put", "delete"])
    inputs = [i for i in ctx.inputs if i.column != "__stored__"]

    def req_lines(root: str) -> list[str]:
        lines: list[str] = []
        if inputs and rng.random() < 0.4 and len({i.source for i in inputs}) == 1:
            names = ", ".join(i.var if i.var == camel(i.column) else f"{camel(i.column)}: {i.var}" for i in inputs)
            names = ", ".join(i.var for i in inputs) if rng.random() < 0.5 else names
            if all(i.var == camel(i.column) for i in inputs) or rng.random() < 0.5:
                lines.append(f"const {{ {', '.join(i.var for i in inputs)} }} = {root}.{inputs[0].source};")
            else:
                for i in inputs:
                    lines.append(f"const {i.var} = {root}.{i.source}.{camel(i.column)};")
        else:
            for i in inputs:
                src = i.source if rng.random() < 0.8 else rng.choice(["query", "body", "params"])
                acc = rng.choice([f"{root}.{src}.{camel(i.column)}", f"{root}.{src}['{camel(i.column)}']"])
                if rng.random() < 0.15:
                    acc += " || ''"
                lines.append(f"{rng.choice(['const', 'let'])} {i.var} = {acc};")
        return lines

    noise_pre = noise_lines(ctx)
    respond_any = f"{ctx.result_var}"

    if w in ("express_arrow", "router_destructure"):
        app = "app" if w == "express_arrow" else rng.choice(["router", "api", "userRouter"])
        params = "req, res" if w == "express_arrow" else "req, res, next"
        lines = [f"{app}.{method}('{route}', async ({params}) => {{"]
        inner = req_lines("req") + noise_pre + body + [f"res.json({respond_any});"]
        if w == "router_destructure":
            inner = ["try {"] + [ind + x for x in inner] + ["} catch (err) {", ind + "next(err);", "}"]
        lines += [ind + x for x in inner] + ["});"]
        return "\n".join(lines)
    if w == "express_fn":
        kw = rng.choice(["async function", "exports.{n} = async function", "module.exports.{n} = async function"])
        head = f"async function {fn_name}(req, res) {{" if kw == "async function" else \
            kw.format(n=fn_name) + " (req, res) {"
        inner = req_lines("req") + noise_pre + body + [rng.choice([f"res.json({respond_any});",
                                                                  f"return res.status(200).send({respond_any});"])]
        return "\n".join([head] + [ind + x for x in inner] + ["}" + (";" if "=" in head else "")])
    if w == "fastify":
        lines = [f"fastify.{method}('{route}', async (request, reply) => {{"]
        inner = req_lines("request") + noise_pre + body + [f"return {respond_any};"]
        return "\n".join(lines + [ind + x for x in inner] + ["});"])
    if w == "next_api":
        inner = req_lines("req") + noise_pre + body + [f"res.status(200).json({respond_any});"]
        return "\n".join(["export default async function handler(req, res) {"] + [ind + x for x in inner] + ["}"])
    if w == "koa":
        inner = req_lines("ctx") + noise_pre + body + [f"ctx.body = {respond_any};"]
        return "\n".join([f"router.{method}('{route}', async (ctx) => {{"] + [ind + x for x in inner] + ["});"])
    if w == "lambda":
        inner = [f"const {i.var} = event.queryStringParameters.{camel(i.column)};" for i in inputs]
        inner += noise_pre + body + [f"return {{ statusCode: 200, body: JSON.stringify({respond_any}) }};"]
        return "\n".join(["exports.handler = async (event) => {"] + [ind + x for x in inner] + ["};"])
    if w == "service_fn":
        args = ", ".join(i.var for i in inputs)
        head = rng.choice([f"async function {fn_name}({args}) {{", f"const {fn_name} = async ({args}) => {{",
                           f"export async function {fn_name}({args}) {{"])
        inner = noise_pre + body + [f"return {respond_any};"]
        return "\n".join([head] + [ind + x for x in inner] + ["}" + (";" if head.startswith("const") else "")])
    if w == "class_method":
        args = ", ".join(i.var for i in inputs)
        cls = ctx.table.capitalize().rstrip("s") + rng.choice(["Repository", "Service", "Dao", "Store"])
        inner = noise_pre + body + [f"return {respond_any};"]
        return "\n".join(
            [f"class {cls} {{", f"{ind}async {fn_name}({args}) {{"] + [ind * 2 + x for x in inner] + [f"{ind}}}", "}"]
        )
    if w == "callback_service":
        args = ", ".join([i.var for i in inputs] + ["callback"])
        inner = noise_pre + body + [f"callback(null, {respond_any});"]
        return "\n".join([f"async function {fn_name}({args}) {{"] + [ind + x for x in inner] + ["}"])
    raise ValueError(w)


def noise_lines(ctx: Ctx) -> list[str]:
    rng = ctx.rng
    out: list[str] = []
    request_like = ctx.wrapper not in ("service_fn", "class_method", "callback_service")
    if ctx.inputs and rng.random() < 0.35:
        v = ctx.inputs[0].var
        if request_like and ctx.wrapper not in ("lambda", "koa", "fastify"):
            out.append(f"if (!{v}) return res.status(400).json({{ error: 'missing {v}' }});")
        else:
            out.append(f"if ({v} === undefined) throw new Error('{v} is required');")
    if rng.random() < 0.3:
        out.append(rng.choice([
            f"logger.info('loading {ctx.table}');",
            f"console.log('query {ctx.table}', new Date().toISOString());",
            "const started = Date.now();",
            f"// fetch {ctx.table} for the current request",
            "/* TODO: add caching */",
            f"metrics.increment('{ctx.table}.lookup');",
        ]))
    if ctx.inputs and rng.random() < 0.15:
        v = ctx.inputs[0].var
        out.append(f"const cleaned = String({ctx.inputs[0].var}).trim();")
    return out


# --------------------------------------------------------------------------- pattern builders
def pick_value_shape(ctx: Ctx):
    name = ctx.pick(VALUE_SHAPES)
    return name, VALUE_SHAPES[name](ctx)


def b_string_concat(ctx: Ctx, variant: str):
    shape, segs = pick_value_shape(ctx)
    expr = render_concat(ctx, segs)
    if variant == "c_inline":
        return shape, driver_exec(ctx, expr, None)
    if variant == "c_var":
        return shape, [f"const {ctx.sql_var} = {expr};"] + driver_exec(ctx, ctx.sql_var, None)
    if variant == "c_multiline":
        pieces = expr.split(" + ")
        lines = [f"const {ctx.sql_var} ="] + ["  " + p + (" +" if k < len(pieces) - 1 else ";") for k, p in enumerate(pieces)]
        return shape, lines + driver_exec(ctx, ctx.sql_var, None)
    if variant == "c_incremental":
        cols = ENTITIES[ctx.table]
        chosen = ctx.rng.sample(list(cols), k=min(len(cols), ctx.rng.choice([1, 2, 3])))
        ctx.inputs = [Inp(camel(c), c, cols[c]) for c in chosen]
        lines = [f"let {ctx.sql_var} = {ctx.lit(f'SELECT * FROM {ctx.table} WHERE 1=1')};"]
        for inp in ctx.inputs:
            q = "" if inp.numeric else "'"
            lines += [f"if ({inp.var}) {{",
                      f"  {ctx.sql_var} += {ctx.lit(f' AND {inp.column} = {q}')} + {inp.var}" + (f" + {ctx.lit(q)};" if q else ";"),
                      "}"]
        return "filters", lines + driver_exec(ctx, ctx.sql_var, None)
    if variant == "c_concat_method":
        pieces = expr.split(" + ")
        return shape, [f"const {ctx.sql_var} = {pieces[0]}.concat({', '.join(pieces[1:])});"] + driver_exec(ctx, ctx.sql_var, None)
    if variant == "c_join":
        pieces = expr.split(" + ")
        return shape, [f"const {ctx.sql_var} = [{', '.join(pieces)}].join('');"] + driver_exec(ctx, ctx.sql_var, None)
    raise ValueError(variant)


def b_template(ctx: Ctx, variant: str):
    shape, segs = pick_value_shape(ctx)
    expr = render_template(ctx, segs)
    if variant == "t_inline":
        return shape, driver_exec(ctx, expr, None)
    if variant == "t_var":
        return shape, [f"const {ctx.sql_var} = {expr};"] + driver_exec(ctx, ctx.sql_var, None)
    if variant == "t_multiline":
        body = expr[1:-1]
        for kw in (" WHERE ", " AND ", " VALUES ", " SET ", " LIMIT "):
            body = body.replace(kw, "\n    " + kw.strip() + " ")
        return shape, [f"const {ctx.sql_var} = `", "    " + body, "  `;"] + driver_exec(ctx, ctx.sql_var, None)
    if variant == "t_helper":
        split = next(i for i, s in enumerate(segs) if isinstance(s, str) and " WHERE " in s) if any(
            isinstance(s, str) and " WHERE " in s for s in segs) else None
        if split is None:
            return shape, [f"const {ctx.sql_var} = {expr};"] + driver_exec(ctx, ctx.sql_var, None)
        head, tail = segs[split].split(" WHERE ", 1)
        where = render_template(ctx, ["WHERE " + tail] + segs[split + 1:])
        base = render_template(ctx, segs[:split] + [head])[1:-1]
        return shape, [f"const where = {where};", f"const {ctx.sql_var} = `{base} ${{where}}`;"] + \
            driver_exec(ctx, ctx.sql_var, None)
    raise ValueError(variant)


def b_dynamic_identifier(ctx: Ctx, variant: str):
    name = {"d_where_column": "where_column"}.get(variant) or ctx.pick([k for k in IDENT_SHAPES if k != "where_column"])
    segs = IDENT_SHAPES[name](ctx)
    style = placeholder_style(ctx.driver)
    use_template = ctx.rng.random() < 0.6
    if use_template:
        sql, params = render_params(ctx, segs, style, inline_idents=True)
        if ctx.driver == "mssql":
            sql = mssql_fix(sql)
        expr = "`" + sql + "`"
    else:
        sql_parts, params, n, buf = [], [], 0, ""
        for seg in segs:
            if isinstance(seg, str):
                buf += seg
            elif seg[0] == "I":
                sql_parts += [ctx.lit(buf), ctx.inputs[seg[1]].var]
                buf = ""
            else:
                n += 1
                buf += {"qmark": "?", "dollar": f"${n}", "at": f"@p{n}"}[style]
                params.append(ctx.inputs[seg[1]].var)
        if buf:
            sql_parts.append(ctx.lit(buf))
        expr = " + ".join(sql_parts)
    if ctx.rng.random() < 0.5:
        return name, [f"const {ctx.sql_var} = {expr};"] + driver_exec(ctx, ctx.sql_var, params or None)
    return name, driver_exec(ctx, expr, params or None)


def b_orm_raw(ctx: Ctx, variant: str):
    shape, segs = pick_value_shape(ctx)
    expr = render_template(ctx, segs) if ctx.rng.random() < 0.5 else render_concat(ctx, segs)
    r = ctx.result_var
    use_var = ctx.rng.random() < 0.4
    pre = [f"const {ctx.sql_var} = {expr};"] if use_var else []
    e = ctx.sql_var if use_var else expr
    if variant == "o_sequelize":
        opts = ctx.pick(["{ type: QueryTypes.SELECT }", "{ type: sequelize.QueryTypes.SELECT }", "{ raw: true }"])
        return shape, pre + [f"const {r} = await sequelize.query({e}, {opts});"]
    if variant == "o_knex_raw":
        return shape, pre + [f"const {r} = await knex.raw({e});"]
    if variant == "o_knex_where_raw":
        cols = ENTITIES[ctx.table]
        col = ctx.pick([c for c in cols if not cols[c]] or list(cols))
        ctx.inputs = [Inp(camel(col), col, False)]
        cond = ctx.pick([f"`{col} = '${{{camel(col)}}}'`", f"\"{col} = '\" + {camel(col)} + \"'\""])
        return "where_raw", [f"const {r} = await knex('{ctx.table}').whereRaw({cond}).limit(20);"]
    if variant == "o_prisma_unsafe":
        m = ctx.pick(["$queryRawUnsafe", "$executeRawUnsafe"])
        return shape, pre + [f"const {r} = await prisma.{m}({e});"]
    if variant == "o_typeorm":
        recv = ctx.pick(["dataSource", "this.dataSource", "getManager()", "queryRunner", "this.repository",
                         "entityManager"])
        return shape, pre + [f"const {r} = await {recv}.query({e});"]
    raise ValueError(variant)


def b_unsafe_format(ctx: Ctx, variant: str):
    shape, segs = pick_value_shape(ctx)
    if variant in ("f_util_format", "f_sprintf"):
        fmt = ""
        args = []
        for seg in segs:
            if isinstance(seg, str):
                fmt += seg
            else:
                q = "'" if _quoted(ctx, seg) else ""
                fmt += f"{q}%s{q}"
                args.append(ctx.inputs[seg[1]].var)
        fn = ctx.pick(["util.format", "format"]) if variant == "f_util_format" else ctx.pick(["sprintf", "vsprintf"])
        call_args = ", ".join(args) if fn != "vsprintf" else "[" + ", ".join(args) + "]"
        lines = [f"const {ctx.sql_var} = {fn}({ctx.lit(fmt)}, {call_args});"]
        return shape, lines + driver_exec(ctx, ctx.sql_var, None)
    if variant == "f_replace":
        tmpl = ""
        reps = []
        style = ctx.pick(["brace", "colon"])
        for seg in segs:
            if isinstance(seg, str):
                tmpl += seg
            else:
                q = "'" if _quoted(ctx, seg) else ""
                var = ctx.inputs[seg[1]].var
                token = "{" + var + "}" if style == "brace" else ":" + var
                tmpl += f"{q}{token}{q}"
                reps.append((token, var))
        chain = "".join(f".{ctx.pick(['replace', 'replaceAll'])}('{t}', {v})" for t, v in reps)
        if ctx.rng.random() < 0.5:
            lines = [f"const TEMPLATE_{ctx.table.upper()} = {ctx.lit(tmpl)};",
                     f"const {ctx.sql_var} = TEMPLATE_{ctx.table.upper()}{chain};"]
        else:
            lines = [f"const {ctx.sql_var} = {ctx.lit(tmpl)}{chain};"]
        return shape, lines + driver_exec(ctx, ctx.sql_var, None)
    raise ValueError(variant)


def b_second_order(ctx: Ctx, variant: str):
    rng = ctx.rng
    src_table = ctx.pick(["users", "accounts", "customers", "employees"])
    stored_col = ctx.pick([c for c, n in ENTITIES[src_table].items() if not n])
    dst_table = ctx.pick([t for t in ENTITIES if t != src_table])
    dst_col = ctx.pick([c for c, n in ENTITIES[dst_table].items() if not n] or ["id"])
    ctx.inputs = [Inp(ctx.pick(["id", "userId", "accountId", "ownerId"]), "id", True, "params")]
    idv = ctx.inputs[0].var
    first_sql = f"SELECT {stored_col} FROM {src_table} WHERE id = " + ("$1" if placeholder_style(ctx.driver) == "dollar" else "?")
    holder = ctx.pick(["user", "owner", "record", "profile", "account", "row"])
    ctx_first = Ctx(rng, ctx.wrapper, ctx.driver, ctx.table, ctx.inputs, ctx.sql_var, ctx.pick(["users", "found", "lookup"]))
    if ctx.driver == "mssql":
        first_sql = first_sql.replace("?", "@p1")
    first = driver_exec(ctx_first, ctx.lit(first_sql), [idv])
    stored_expr = f"{ctx_first.result_var}[0].{stored_col}"
    if variant == "so_rows":
        second_sql = render_second(ctx, dst_table, dst_col, stored_expr)
        return "second", first + driver_exec(ctx, second_sql, None)
    if variant == "so_variable":
        lines = first + [f"const {holder} = {ctx_first.result_var}[0];"]
        second_sql = render_second(ctx, dst_table, dst_col, f"{holder}.{stored_col}")
        return "second", lines + [f"const {ctx.sql_var} = {second_sql};"] + driver_exec(ctx, ctx.sql_var, None)
    if variant == "so_orm_model":
        model = src_table.capitalize().rstrip("s")
        lines = [f"const {holder} = await {model}.{ctx.pick(['findByPk', 'findOne', 'findById'])}({idv});"]
        second_sql = render_second(ctx, dst_table, dst_col, f"{holder}.{camel(stored_col)}")
        return "second", lines + driver_exec(ctx, second_sql, None)
    if variant == "so_loop":
        r = ctx.result_var
        lines = first + [f"const {r} = [];", f"for (const {holder} of {ctx_first.result_var}) {{"]
        second_sql = render_second(ctx, dst_table, dst_col, f"{holder}.{stored_col}")
        inner = driver_exec(Ctx(rng, ctx.wrapper, ctx.driver, ctx.table, ctx.inputs, ctx.sql_var, "part"), second_sql, None)
        lines += ["  " + x for x in inner] + [f"  {r}.push(...part);" if ctx.driver != "mysql_cb" else f"  {r}.push(part);", "}"]
        return "second", lines
    if variant == "so_callback":
        r = ctx.result_var
        second_sql = render_second(ctx, dst_table, dst_col, f"rows[0].{stored_col}")
        recv = "connection" if ctx.driver in ("mysql_cb", "mysql2") else "db"
        lines = [
            f"const {r} = await new Promise((resolve, reject) => {{",
            f"  {recv}.query({ctx.lit(first_sql)}, [{idv}], (err, rows) => {{",
            "    if (err) return reject(err);",
            f"    {recv}.query({second_sql}, (err2, out) => (err2 ? reject(err2) : resolve(out)));",
            "  });",
            "});",
        ]
        return "second", lines
    raise ValueError(variant)


def render_second(ctx: Ctx, table: str, col: str, value_expr: str) -> str:
    if ctx.rng.random() < 0.5:
        return f"`SELECT * FROM {table} WHERE {col} = '${{{value_expr}}}'`"
    return f"{ctx.lit(f'SELECT * FROM {table} WHERE {col} = ' + chr(39))} + {value_expr} + {ctx.lit(chr(39))}"


# --------------------------------------------------------------------------- safe builders
def b_safe(ctx: Ctx, variant: str):
    rng = ctx.rng
    r = ctx.result_var
    if variant == "s_param":
        shape, segs = pick_value_shape(ctx)
        return shape, safe_exec(ctx, segs)
    if variant == "s_orm":
        shape, segs = pick_value_shape(ctx)
        kind = ctx.pick(["seq_repl", "seq_bind", "knex_raw", "knex_builder", "prisma_tagged", "prisma_find",
                         "typeorm_params", "typeorm_find", "seq_find"])
        inp = ctx.inputs[0]
        if kind == "seq_repl":
            sql, params = render_params(ctx, segs, "named")
            repl = ", ".join(f"{p}: {p}" if not p.startswith("`") else f"{ctx.inputs[0].var}: {p}" for p in params)
            return shape, [f"const {r} = await sequelize.query({ctx.lit(sql)}, {{ replacements: {{ {repl} }}, "
                           f"type: QueryTypes.SELECT }});"]
        if kind == "seq_bind":
            sql, params = render_params(ctx, segs, "dollar")
            return shape, [f"const {r} = await sequelize.query({ctx.lit(sql)}, {{ bind: [{', '.join(params)}] }});"]
        if kind == "knex_raw":
            sql, params = render_params(ctx, segs, "qmark")
            return shape, [f"const {r} = await knex.raw({ctx.lit(sql)}, [{', '.join(params)}]);"]
        if kind == "knex_builder":
            return shape, [f"const {r} = await knex('{ctx.table}').where({{ {inp.column}: {inp.var} }}).select('*');"]
        if kind == "prisma_tagged":
            return shape, [f"const {r} = await prisma.$queryRaw{render_template(ctx, segs).replace(chr(39) + '${', '${').replace('}' + chr(39), '}')};"]
        if kind == "prisma_find":
            model = ctx.table.rstrip("s")
            return shape, [f"const {r} = await prisma.{model}.findMany({{ where: {{ {camel(inp.column)}: {inp.var} }} }});"]
        if kind == "typeorm_params":
            sql, params = render_params(ctx, segs, "dollar")
            return shape, [f"const {r} = await dataSource.query({ctx.lit(sql)}, [{', '.join(params)}]);"]
        if kind == "typeorm_find":
            return shape, [f"const {r} = await this.repository.findOneBy({{ {camel(inp.column)}: {inp.var} }});"]
        model = ctx.table.capitalize().rstrip("s")
        return shape, [f"const {r} = await {model}.findAll({{ where: {{ {camel(inp.column)}: {inp.var} }} }});"]
    if variant == "s_allowlist":
        name = ctx.pick([k for k in IDENT_SHAPES if k != "where_column"])
        segs = IDENT_SHAPES[name](ctx)
        inp = ctx.inputs[0]
        cols = list(ENTITIES[ctx.table])
        choices = (["ASC", "DESC"] if inp.column == "dir" else
                   [ctx.table, "archived_" + ctx.table] if inp.column == "table" else cols[:3])
        safe_var = ctx.pick(["column", "safeColumn", "orderColumn", "chosen", "target"])
        mode = ctx.pick(["map", "includes_ternary", "guard"])
        lines: list[str] = []
        if mode == "map":
            mapping = ", ".join(f"{c.lower()}: '{c}'" for c in choices)
            lines += [f"const ALLOWED = {{ {mapping} }};", f"const {safe_var} = ALLOWED[{inp.var}] || '{choices[0]}';"]
        elif mode == "includes_ternary":
            arr = ", ".join(f"'{c}'" for c in choices)
            lines += [f"const {safe_var} = [{arr}].includes({inp.var}) ? {inp.var} : '{choices[0]}';"]
        else:
            arr = ", ".join(f"'{c}'" for c in choices)
            lines += [f"const ALLOWED = [{arr}];",
                      f"if (!ALLOWED.includes({inp.var})) {{", f"  throw new Error('invalid {inp.column}');", "}"]
            safe_var = inp.var
        swapped = [s if isinstance(s, str) else ("I", 0) for s in segs]
        ctx_inputs = ctx.inputs
        ctx.inputs = [Inp(safe_var, inp.column, False)]
        expr = render_template(ctx, swapped) if rng.random() < 0.6 else render_concat(ctx, swapped)
        ctx.inputs = ctx_inputs
        return name, lines + driver_exec(ctx, expr, None)
    if variant == "s_numeric":
        cols = ENTITIES[ctx.table]
        col = ctx.pick([c for c in cols if cols[c]])
        ctx.inputs = [Inp(camel(col), col, True)]
        conv = ctx.pick(["Number", "parseInt", "parseFloat", "Math.floor"])
        arg = f"{camel(col)}, 10" if conv == "parseInt" else camel(col)
        safe = ctx.pick([f"safe{camel(col).capitalize()}", "n", "num", "numericId"])
        lines = [f"const {safe} = {conv}({arg});"]
        sqltext = f"SELECT * FROM {ctx.table} WHERE {col} = "
        expr = f"`{sqltext}${{{safe}}}`" if rng.random() < 0.5 else f"{ctx.lit(sqltext)} + {safe}"
        return "numeric", lines + driver_exec(ctx, expr, None)
    if variant in ("s_escape", "s_pgformat"):
        shape, segs = pick_value_shape(ctx)
        if variant == "s_escape":
            esc = ctx.pick(["mysql.escape", "connection.escape", "pool.escape", "SqlString.escape"])
            parts, buf = [], ""
            for seg in segs:
                if isinstance(seg, str):
                    buf += seg
                else:
                    parts += [ctx.lit(buf), f"{esc}({ctx.inputs[seg[1]].var})"]
                    buf = ""
            if buf:
                parts.append(ctx.lit(buf))
            return shape, driver_exec(ctx, " + ".join(parts), None)
        fmt, args = "", []
        for seg in segs:
            if isinstance(seg, str):
                fmt += seg
            else:
                fmt += "%L"
                args.append(ctx.inputs[seg[1]].var)
        return shape, [f"const {ctx.sql_var} = format({ctx.lit(fmt)}, {', '.join(args)});"] + driver_exec(ctx, ctx.sql_var, None)
    if variant == "s_constant_concat":
        shape, segs = pick_value_shape(ctx)
        const = ctx.pick(["TABLE", "TABLE_NAME", "COLUMNS", "BASE_QUERY"])
        style = placeholder_style(ctx.driver)
        sql, params = render_params(ctx, segs, style)
        if ctx.driver == "mssql":
            sql = mssql_fix(sql)
        head, tail = sql.split(" FROM ", 1) if " FROM " in sql else (sql, "")
        if tail:
            lines = [f"const {const} = {ctx.lit(head)};", f"const {ctx.sql_var} = {const} + {ctx.lit(' FROM ' + tail)};"]
        else:
            lines = [f"const {ctx.sql_var} = {ctx.lit(sql)};"]
        return shape, lines + driver_exec(ctx, ctx.sql_var, params)
    if variant == "s_log":
        shape, segs = pick_value_shape(ctx)
        logger = ctx.pick(["console.log", "logger.debug", "logger.info", "debug"])
        msg = render_concat(ctx, segs) if rng.random() < 0.5 else render_template(ctx, segs)
        return shape, [f"{logger}('about to run: ' + {msg});" if rng.random() < 0.5 else f"{logger}({msg});"] + safe_exec(ctx, segs)
    if variant == "s_tagged_sql":
        shape, segs = pick_value_shape(ctx)
        tag = ctx.pick(["sql", "SQL", "Prisma.sql"])
        tmpl = render_template(ctx, segs).replace("'${", "${").replace("}'", "}").replace("'%${", "${").replace("}%'", "}")
        return shape, [f"const {ctx.sql_var} = {tag}{tmpl};", f"const {r} = await {ctx.pick(['db', 'pool', 'client'])}.query({ctx.sql_var});"]
    if variant == "s_second_order_safe":
        shape, segs = "second", None
        ctx.inputs = [Inp("id", "id", True, "params")]
        style = placeholder_style(ctx.driver)
        ph = "$1" if style == "dollar" else ("@p1" if style == "at" else "?")
        first = driver_exec(Ctx(rng, ctx.wrapper, ctx.driver, ctx.table, ctx.inputs, ctx.sql_var, "users"),
                            ctx.lit(f"SELECT email FROM users WHERE id = {ph}"), ["id"])
        second = driver_exec(ctx, ctx.lit(f"SELECT * FROM {ctx.table} WHERE owner = {ph}"), ["users[0].email"])
        return shape, first + second
    if variant == "s_non_sql_concat":
        shape, segs = pick_value_shape(ctx)
        v = ctx.inputs[0].var
        extra = ctx.pick([f"const cacheKey = '{ctx.table}:' + {v};", f"const url = `https://api.example.com/{ctx.table}/${{{v}}}`;",
                          f"const message = 'Looking up ' + {v} + ' in {ctx.table}';",
                          f"res.setHeader('X-Lookup', `{ctx.table}-${{{v}}}`);" if ctx.wrapper.startswith("express") else
                          f"const label = `{ctx.table}-${{{v}}}`;"])
        return shape, [extra] + safe_exec(ctx, segs)
    raise ValueError(variant)


PATTERN_BUILDERS = {
    "STRING_CONCAT": (b_string_concat, ["c_inline", "c_var", "c_multiline", "c_incremental", "c_concat_method", "c_join"]),
    "TEMPLATE_LITERAL": (b_template, ["t_inline", "t_var", "t_multiline", "t_helper"]),
    "DYNAMIC_IDENTIFIER": (b_dynamic_identifier, ["d_generic", "d_where_column"]),
    "ORM_RAW_QUERY": (b_orm_raw, ["o_sequelize", "o_knex_raw", "o_knex_where_raw", "o_prisma_unsafe", "o_typeorm"]),
    "UNSAFE_FORMAT": (b_unsafe_format, ["f_util_format", "f_replace", "f_sprintf"]),
    "SECOND_ORDER": (b_second_order, ["so_rows", "so_variable", "so_orm_model", "so_loop", "so_callback"]),
    "SAFE": (b_safe, ["s_param", "s_orm", "s_allowlist", "s_numeric", "s_escape", "s_pgformat", "s_constant_concat",
                      "s_log", "s_tagged_sql", "s_second_order_safe", "s_non_sql_concat"]),
}

FN_NAMES = ["getRecords", "findItems", "loadData", "search", "list", "fetchOne", "remove", "update", "create",
            "lookup", "handle", "query", "resolve", "byFilter", "exportRows", "report", "show", "index"]


def make_sample(rng: random.Random, label: str, heldout: bool) -> dict:
    builder, variants = PATTERN_BUILDERS[label]
    allowed_variants = [v for v in variants if (v in HELDOUT_VARIANTS) == heldout] or variants
    wrappers = [w for w in WRAPPERS if w not in HELDOUT_WRAPPERS]
    drivers = [d for d in DRIVERS if d not in HELDOUT_DRIVERS]
    variant = rng.choice(allowed_variants if not heldout or rng.random() < 0.5 else variants)
    wrapper = rng.choice(wrappers)
    driver = rng.choice(drivers)
    if heldout and variant not in HELDOUT_VARIANTS:
        # A held-out sample must contain at least one component never seen in training.
        if rng.random() < 0.5:
            wrapper = rng.choice(sorted(HELDOUT_WRAPPERS))
        else:
            driver = rng.choice(sorted(HELDOUT_DRIVERS))
    if label == "SECOND_ORDER" and variant == "so_callback":
        driver = rng.choice(["mysql_cb", "mysql2", "sqlite3"])

    ctx = Ctx(
        rng=rng,
        wrapper=wrapper,
        driver=driver,
        table=rng.choice(list(ENTITIES)),
        sql_var=rng.choice(SQL_VARS),
        result_var=rng.choice(RESULT_VARS),
        quote=rng.choice(['"', "'"]),
    )
    shape, body = builder(ctx, variant)
    if rng.random() < 0.35:  # rename input variables away from column names (anti-shortcut)
        body, ctx = rename_inputs(ctx, body)
    fn_name = rng.choice(FN_NAMES) + ctx.table.capitalize()
    code = wrap(ctx, body, fn_name)
    if driver == "mssql" or ctx.wrapper in HELDOUT_WRAPPERS or driver in HELDOUT_DRIVERS or variant in HELDOUT_VARIANTS:
        split_hint = "heldout"
    else:
        split_hint = "main"
    return {
        "code": code,
        "label": label,
        "variant": variant,
        "shape": shape,
        "wrapper": wrapper,
        "driver": driver,
        "split_hint": split_hint,
        "template_id": f"{label}|{variant}|{shape}",
        "source": "synthetic",
    }


def replace_identifier_in_code(line: str, old: str, new: str) -> str:
    """Rename identifier `old` only in code positions (outside string literals, or inside `${...}`).
    Operates on the whole body so multi-line template literals keep their quote state."""
    import re

    ident = re.compile(rf"(?<![\w.$]){re.escape(old)}(?![\w$])")
    out, i, quote, depth_stack = [], 0, None, []
    code_start = 0

    def flush_code(end):
        out.append(ident.sub(new, line[code_start:end]))

    while i < len(line):
        ch = line[i]
        if quote is None:
            if ch in "'\"`":
                flush_code(i)
                quote, code_start = ch, i
            elif ch == "}" and depth_stack:
                flush_code(i)
                quote = depth_stack.pop()
                code_start = i
            i += 1
            continue
        if ch == "\\":
            i += 2
            continue
        if quote == "`" and line.startswith("${", i):
            out.append(line[code_start : i + 2])
            depth_stack.append("`")
            quote, code_start = None, i + 2
            i += 2
            continue
        if ch == quote:
            out.append(line[code_start : i + 1])
            quote, code_start = None, i + 1
        i += 1
    if quote is None:
        flush_code(len(line))
    else:
        out.append(line[code_start:])
    return "".join(out)


def rename_inputs(ctx: Ctx, body: list[str]):
    new_inputs = []
    for inp in ctx.inputs:
        new = ctx.rng.choice(ALT_NAMES)
        if any(new == i.var for i in ctx.inputs) or any(new == i.var for i in new_inputs):
            new_inputs.append(inp)
            continue
        body = replace_identifier_in_code("\n".join(body), inp.var, new).split("\n")
        new_inputs.append(Inp(new, inp.column, inp.numeric, inp.source))
    ctx.inputs = new_inputs
    return body, ctx


def make_twin(rng: random.Random, sample: dict) -> dict:
    """Minimal-edit safe twin: same wrapper/driver, parameterized query."""
    twin_rng = random.Random(rng.random())
    ctx = Ctx(rng=twin_rng, wrapper=sample["wrapper"], driver=sample["driver"], table=twin_rng.choice(list(ENTITIES)),
              sql_var=twin_rng.choice(SQL_VARS), result_var=twin_rng.choice(RESULT_VARS),
              quote=twin_rng.choice(['"', "'"]))
    shape, segs = pick_value_shape(ctx)
    body = safe_exec(ctx, segs)
    code = wrap(ctx, body, twin_rng.choice(FN_NAMES) + ctx.table.capitalize())
    return {**sample, "code": code, "label": "SAFE", "variant": "s_twin", "shape": shape,
            "template_id": f"SAFE|s_twin|{shape}"}


def generate(n: int, heldout_n: int, seed: int, safe_ratio: float = 0.4, twin_prob: float = 0.25) -> list[dict]:
    rng = random.Random(seed)
    vulnerable = [lbl for lbl in PATTERN_BUILDERS if lbl != "SAFE"]
    rows: list[dict] = []

    def emit(count: int, heldout: bool):
        produced = 0
        while produced < count:
            if rng.random() < safe_ratio:
                label = "SAFE"
            else:
                label = rng.choice(vulnerable)
            sample = make_sample(rng, label, heldout)
            rows.append(sample)
            produced += 1
            if label != "SAFE" and rng.random() < twin_prob and produced < count:
                rows.append(make_twin(rng, sample))
                produced += 1

    emit(n, heldout=False)
    emit(heldout_n, heldout=True)
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--n", type=int, default=11000, help="main (train/val/test) samples")
    parser.add_argument("--heldout-n", type=int, default=1500, help="held-out samples")
    parser.add_argument("--seed", type=int, default=13)
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "processed" / "raw_synthetic.jsonl")
    parser.add_argument("--show", type=int, default=0, help="print N random samples and exit")
    args = parser.parse_args(argv)

    rows = generate(args.n, args.heldout_n, args.seed)
    if args.show:
        for row in random.Random(args.seed).sample(rows, args.show):
            print(f"// {row['label']} | {row['template_id']} | {row['wrapper']} | {row['driver']}\n{row['code']}\n")
        return
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    print(f"wrote {len(rows)} samples -> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
