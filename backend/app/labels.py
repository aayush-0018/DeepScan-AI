"""Label set shared by the detectors, the dataset generator and the training pipeline."""

LABELS: list[str] = [
    "SAFE",
    "STRING_CONCAT",
    "TEMPLATE_LITERAL",
    "DYNAMIC_IDENTIFIER",
    "ORM_RAW_QUERY",
    "UNSAFE_FORMAT",
    "SECOND_ORDER",
]
LABEL2ID: dict[str, int] = {name: i for i, name in enumerate(LABELS)}
ID2LABEL: dict[int, str] = dict(enumerate(LABELS))
VULNERABLE_LABELS: list[str] = LABELS[1:]

PATTERN_DESCRIPTIONS: dict[str, str] = {
    "STRING_CONCAT": "SQL query built by concatenating untrusted input with the + operator, .concat() or .join().",
    "TEMPLATE_LITERAL": "Untrusted input interpolated into a SQL template literal (`...${x}...`).",
    "DYNAMIC_IDENTIFIER": "Untrusted input used as a table, column, or ORDER BY / sort-direction identifier.",
    "ORM_RAW_QUERY": "Untrusted input passed into an ORM / query-builder raw-SQL escape hatch "
    "(sequelize.query, knex.raw, prisma.$queryRawUnsafe, ...).",
    "UNSAFE_FORMAT": "SQL produced by string formatting (util.format, %s, .replace) with untrusted input.",
    "SECOND_ORDER": "A value previously read from the database or storage is concatenated into a new SQL query.",
}
