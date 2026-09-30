"""Regression tests: PDF object walk must terminate on pathological object
graphs.

A real attachment (Office Order PDF) had a cyclic /Parent chain; the old
_walk_pdf_objects had no visited set or depth cap, and its blanket
`except Exception` swallowed RecursionError and kept looping — the scan
thread pegged a CPU forever and the background queue deadlocked behind it.
"""

from app.engines.analyzers.pdf_analyzer import _walk_pdf_objects


class _CyclicDict(dict):
    """dict that survives deep recursion tests (plain dict is fine too)."""


class _FakeReader:
    def __init__(self, trailer, pages):
        self.trailer = trailer
        self.pages = pages


def test_cyclic_object_graph_terminates_and_finds_keys():
    a = _CyclicDict()
    b = _CyclicDict()
    a["/Kids"] = b
    b["/Parent"] = a          # cycle back to the root
    a["/JS"] = "app.alert()"  # dangerous key must still be detected

    keys = _walk_pdf_objects(_FakeReader(trailer=a, pages=[b]))

    assert "/JS" in keys


def test_deep_nesting_terminates_at_depth_cap():
    root = _CyclicDict()
    cur = root
    for i in range(5000):     # far beyond Python's recursion limit
        nxt = _CyclicDict()
        cur[f"/Level{i}"] = nxt
        cur = nxt
    cur["/Launch"] = "cmd"    # deeper than MAX_DEPTH — not required to find

    keys = _walk_pdf_objects(_FakeReader(trailer=root, pages=[]))

    assert isinstance(keys, list)   # returned instead of hanging/raising


def test_repeated_shared_references_do_not_loop():
    shared = _CyclicDict({"/EmbeddedFile": "stream"})
    parent = _CyclicDict()
    for i in range(50):             # same object referenced many times
        parent[f"/Ref{i}"] = shared

    keys = _walk_pdf_objects(_FakeReader(trailer=parent, pages=[shared]))

    # visited set: counted once, not 50 times
    assert keys.count("/EmbeddedFile") == 1
