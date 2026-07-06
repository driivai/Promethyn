"""Adversarial unit tests for the SQL result comparator — the leak surface.

The comparator is the one place execution-based SQL verification could leak a
false PASS, so every documented semantic is attacked directly: shape vs
content, order sensitivity, duplicates as a bag, NULL handling, column-name
independence with column-count enforcement, and numeric tolerance.
"""

from __future__ import annotations

from prometheus_protocol.verifier.sql import results_equivalent


def _r(columns, rows):
    return {"columns": columns, "rows": rows}


def test_right_shape_wrong_content_fails():
    ok, why = results_equivalent(
        _r(["a", "b"], [[1, "x"], [2, "y"]]),
        _r(["a", "b"], [[1, "x"], [2, "z"]]),
    )
    assert not ok and "differs" in why


def test_order_mismatch_passes_unordered_and_fails_ordered():
    ref = _r(["v"], [[1], [2], [3]])
    cand = _r(["v"], [[3], [1], [2]])
    assert results_equivalent(ref, cand, ordered=False)[0]
    ok, why = results_equivalent(ref, cand, ordered=True)
    assert not ok and "ordered row" in why


def test_duplicates_are_a_bag_not_a_set():
    # Same distinct values, different multiplicities: must FAIL.
    ok, _ = results_equivalent(
        _r(["v"], [[1], [1], [2]]),
        _r(["v"], [[1], [2], [2]]),
    )
    assert not ok
    # Same multiset in a different order: PASSes unordered.
    assert results_equivalent(
        _r(["v"], [[1], [2], [1]]),
        _r(["v"], [[1], [1], [2]]),
    )[0]


def test_row_and_column_count_mismatches_fail():
    assert not results_equivalent(_r(["v"], [[1]]), _r(["v"], [[1], [1]]))[0]
    ok, why = results_equivalent(_r(["a", "b"], [[1, 2]]), _r(["a"], [[1]]))
    assert not ok and "column count" in why


def test_column_names_are_ignored_but_positions_matter():
    # Aliases differ: still equivalent.
    assert results_equivalent(
        _r(["SUM(total)"], [[10.0]]), _r(["revenue"], [[10.0]])
    )[0]
    # Same values in swapped columns: NOT equivalent.
    assert not results_equivalent(
        _r(["a", "b"], [[1, "x"]]), _r(["b", "a"], [["x", 1]])
    )[0]


def test_null_handling_is_exact():
    assert results_equivalent(_r(["v"], [[None]]), _r(["v"], [[None]]))[0]
    assert not results_equivalent(_r(["v"], [[None]]), _r(["v"], [[0]]))[0]
    assert not results_equivalent(_r(["v"], [[None]]), _r(["v"], [[""]]))[0]
    # NULLs participate in bag matching positionally.
    assert results_equivalent(
        _r(["a", "b"], [[None, 1], [2, None]]),
        _r(["a", "b"], [[2, None], [None, 1]]),
    )[0]


def test_numeric_tolerance_and_cross_type():
    assert results_equivalent(
        _r(["v"], [[0.1 + 0.2]]), _r(["v"], [[0.3]])
    )[0]  # float arithmetic path differences are not wrongness
    assert results_equivalent(_r(["v"], [[1]]), _r(["v"], [[1.0]]))[0]
    assert not results_equivalent(_r(["v"], [[1]]), _r(["v"], [[1.001]]))[0]


def test_mixed_type_rows_sort_and_compare_deterministically():
    ref = _r(["v"], [["x"], [None], [2], [1.5]])
    cand = _r(["v"], [[2], ["x"], [1.5], [None]])
    assert results_equivalent(ref, cand)[0]
    assert not results_equivalent(ref, _r(["v"], [[2], ["x"], [1.5], ["y"]]))[0]
