import pytest
from app.detectors.ast_detector import AstRuleDetector, column_before_operator, identifier_position
from app.detectors.regex_detector import RegexDetector
from app.extraction.functions import parse_source

from .conftest import read_fixture

ast = AstRuleDetector()
regex = RegexDetector()


def ast_hits(code: str, filename: str = "a.js"):
    return ast.detect(parse_source(code, filename))


@pytest.mark.parametrize(
    "fixture, pattern",
    [
        ("string_concat.js", "STRING_CONCAT"),
        ("template_literal.js", "TEMPLATE_LITERAL"),
        ("dynamic_identifier.js", "DYNAMIC_IDENTIFIER"),
        ("orm_raw_query.js", "ORM_RAW_QUERY"),
        ("unsafe_format.js", "UNSAFE_FORMAT"),
        ("second_order.js", "SECOND_ORDER"),
    ],
)
def test_ast_detects_each_pattern(fixture, pattern):
    hits = ast_hits(read_fixture(fixture), fixture)
    assert len(hits) == 1, [h.message for h in hits]
    assert hits[0].pattern == pattern
    assert hits[0].confidence >= 0.8
    assert hits[0].evidence_lines


def test_ast_has_no_false_positives_on_hard_negatives():
    hits = ast_hits(read_fixture("safe.js"), "safe.js")
    assert hits == [], [(h.unit.name, h.pattern, h.message) for h in hits]


def test_ast_typescript_mixed_file():
    hits = {h.unit.name: h.pattern for h in ast_hits(read_fixture("mixed.ts"), "mixed.ts")}
    assert hits == {"ReportService.byField": "DYNAMIC_IDENTIFIER", "handler": "ORM_RAW_QUERY"}


def test_ast_sql_variable_built_incrementally():
    code = """
async function search(req) {
  let sql = "SELECT * FROM users WHERE 1=1";
  if (req.query.name) {
    sql += " AND name = '" + req.query.name + "'";
  }
  return db.query(sql);
}"""
    hits = ast_hits(code)
    assert [h.pattern for h in hits] == ["STRING_CONCAT"]


def test_ast_array_join_and_replace():
    join_code = """
function q(id) {
  const sql = ["SELECT * FROM users", "WHERE id =", id].join(" ");
  return db.query(sql);
}"""
    replace_code = """
function q(req) {
  const sql = "SELECT * FROM users WHERE id = {id}".replace("{id}", req.query.id);
  return db.query(sql);
}"""
    assert [h.pattern for h in ast_hits(join_code)] == ["STRING_CONCAT"]
    assert [h.pattern for h in ast_hits(replace_code)] == ["UNSAFE_FORMAT"]


def test_ast_second_order_in_callback():
    code = """
function rename(id) {
  db.query('SELECT name FROM users WHERE id = ?', [id], (err, rows) => {
    db.query("UPDATE profiles SET display = '" + rows[0].name + "'");
  });
}"""
    hits = ast_hits(code)
    assert [h.pattern for h in hits] == ["SECOND_ORDER"]


def test_ast_sanitizers_and_guards():
    code = """
async function a(req) {
  const id = Number(req.query.id);
  return db.query("SELECT * FROM t WHERE id = " + id);
}
async function b(req) {
  const col = req.query.col;
  if (!ALLOWED.includes(col)) throw new Error('bad');
  return db.query(`SELECT ${col} FROM t`);
}
async function c(req) {
  return db.query("SELECT * FROM t WHERE name = " + mysql.escape(req.query.name));
}
async function d(table, value) {
  return pgClient.query(format('SELECT * FROM %I WHERE v = %L', table, value));
}"""
    assert ast_hits(code) == []


def test_ast_whole_query_from_request():
    hits = ast_hits("app.post('/run', (req, res) => db.query(req.body.sql));")
    assert len(hits) == 1 and hits[0].confidence < 0.9


def test_identifier_position_helpers():
    assert identifier_position("SELECT * FROM users ORDER BY ")
    assert identifier_position("SELECT * FROM ")
    assert not identifier_position("SELECT * FROM users WHERE id = ")
    assert not identifier_position("INSERT INTO t (a) VALUES ('")
    assert column_before_operator("SELECT * FROM t WHERE ", " = 1")
    assert not column_before_operator("SELECT * FROM t WHERE name = '", "'")


def test_regex_baseline_finds_obvious_and_misses_second_order():
    assert regex.detect(parse_source(read_fixture("template_literal.js"), "t.js"))
    assert regex.detect(parse_source(read_fixture("string_concat.js"), "s.js"))
    second = regex.detect(parse_source(read_fixture("second_order.js"), "so.js"))
    assert all(h.pattern != "SECOND_ORDER" for h in second)
