"""Python AST extractor that reads key_size keyword arguments from function calls."""
from __future__ import annotations

import ast
from typing import Dict


class _KeySizeVisitor(ast.NodeVisitor):
    """Collect {line_number: key_size_value} from keyword args named 'key_size'."""

    def __init__(self) -> None:
        self.sizes: Dict[int, int] = {}

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        for kw in node.keywords:
            if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                if isinstance(kw.value.value, int):
                    self.sizes[node.lineno] = kw.value.value
        self.generic_visit(node)


def extract_key_sizes(source: str) -> Dict[int, int]:
    """Parse *source* as Python and return {call_line: key_size_value}.

    Returns an empty dict if the source cannot be parsed.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    visitor = _KeySizeVisitor()
    visitor.visit(tree)
    return visitor.sizes
