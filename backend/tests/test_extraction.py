from app.extraction.functions import detect_language, extract_functions

from .conftest import read_fixture


def test_extracts_named_arrow_method_and_callback():
    code = """
function plain(a) { return a; }
const arrow = async (x) => x * 2;
class Repo {
  find(id) { return id; }
}
app.get('/users', (req, res) => { res.send('ok'); });
const obj = { handler: function () {} };
"""
    units = extract_functions(code, "a.js")
    names = {u.name: u.kind for u in units}
    assert names["plain"] == "function"
    assert names["arrow"] == "arrow"
    assert names["Repo.find"] == "method"
    assert any(n.startswith("app.get('/users')") and k == "callback" for n, k in names.items())
    assert names["handler"] == "function"
    assert "<module>" in names  # app.get(...) is top-level executable code


def test_module_unit_omitted_for_pure_declarations():
    units = extract_functions("function a() {}\nexport async function b() {}\n", "a.js")
    assert [u.name for u in units] == ["a", "b"]


def test_line_numbers_are_one_based():
    units = extract_functions("\n\nfunction f() {\n  return 1;\n}\n", "a.js")
    assert (units[0].start_line, units[0].end_line) == (3, 5)


def test_typescript_class_and_types():
    units = extract_functions(read_fixture("mixed.ts"), "mixed.ts")
    names = [u.name for u in units]
    assert "ReportService.byField" in names
    assert "ReportService.byId" in names
    assert "handler" in names


def test_nested_functions_are_emitted_with_depth():
    code = "function outer() { const inner = () => 1; return inner(); }"
    units = {u.name: u for u in extract_functions(code, "a.js")}
    assert units["outer"].depth == 0
    assert units["inner"].depth == 1


def test_language_detection():
    assert detect_language("a.ts") == "typescript"
    assert detect_language("a.tsx") == "tsx"
    assert detect_language("a.mjs") == "javascript"
    assert detect_language("weird.txt") == "javascript"
