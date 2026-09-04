"""Path heuristics shared across layers. Pure, no I/O."""
from __future__ import annotations

_TEST_MARKERS = (
    "/test/", "/tests/", "/spec/", "/__tests__/", "/testdata/", "/test_data/",
    "/examples/", "/example/", "/e2e/", "/it/", "fixture", "/mocks/", "/mock/",
    ".test.", "_test.", "-test.", "test_", "spec.", ".spec.",
)


def is_test_path(component: str) -> bool:
    p = "/" + component.replace("\\", "/").lower()
    return any(m in p for m in _TEST_MARKERS)
