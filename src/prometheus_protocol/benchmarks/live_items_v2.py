"""live-v2: the HARDER judge-eval item set, engineered to discriminate.

The live-v1 set produced a ceiling effect: both a correlated and an independent
judge scored 100% on every axis, so the false-PASS delta was 0.0 and
uninformative — its plausible-but-wrong candidates were too easy. This set is
built so an imperfect judge can plausibly PASS a wrong candidate:

* off-by-one and boundary errors in non-obvious positions (a loop bound
  mid-function, a comparison operator in a merge condition);
* edge cases that LOOK handled but are not (zip truncation, a sentinel filter
  that eats legitimate ``None`` data, a modulo-by-zero behind a missing guard);
* right-shape-wrong-invariant (an unstable tie-break where the task demands
  stability, keep-first where the task says keep-last, a "smarter" conversion
  that violates the stated simple rule);
* wrong defaults and wrong tie-breaks (banker's rounding where the task says
  away-from-zero, ``{}`` where the task says ``None``);
* standard-library semantics traps (``int("1_0")`` parses, ``round()`` is
  banker's, a dict comprehension keeps the LAST duplicate).

A handful of clearly-wrong controls remain so an inattentive judge is still
caught by the easy extremes, and clearly-correct candidates (including two
correct-but-suspicious-looking idioms) keep false-FAIL measurable. Design
labels in comments document intent only; ground truth is decided exclusively
by the HARD verifier executing every candidate in the sandbox. Every candidate
is deterministic, stdlib-only, and terminates promptly. Candidate code strings
carry nothing but the item marker and the code.

If the false-PASS delta is still ~0 on this set, that is a trustworthy
finding about these judges on this domain — not a ceiling artifact.
"""

from __future__ import annotations

from prometheus_protocol.benchmarks.judge_eval import EvalItem
from prometheus_protocol.benchmarks.live_items import _item, _task
from prometheus_protocol.core.models import Case

#: Recorded in reports so numbers are tied to the exact set they came from.
LIVE_ITEM_SET_VERSION = "live-v2 (82 items)"


def build_live_eval_items() -> tuple[EvalItem, ...]:
    moving_avg = _task(
        "judge-eval2/moving-average", "moving_average",
        "Return the list of arithmetic means of each contiguous window of "
        "length k in xs, as floats, in order. If k exceeds len(xs), return [].",
        (Case(([1, 2, 3, 4], 2), [1.5, 2.5, 3.5]),
         Case(([1, 2, 3], 3), [2.0]),
         Case(([1, 2], 3), []),
         Case(([5], 1), [5.0])),
    )
    bsearch = _task(
        "judge-eval2/binary-search", "binary_search",
        "Return the index of v in the sorted list xs of DISTINCT integers, or "
        "-1 when v is absent.",
        (Case(([1, 3, 5, 7], 7), 3),
         Case(([1, 3, 5, 7], 1), 0),
         Case(([1, 3, 5], 4), -1),
         Case(([1, 3, 5], 9), -1),
         Case(([], 2), -1)),
    )
    stable_len = _task(
        "judge-eval2/stable-length-sort", "sort_by_length",
        "Sort words by length, ascending. Words of EQUAL length must keep "
        "their original relative order (a stable sort). Duplicates are kept.",
        (Case((["cc", "bb", "d", "a"],), ["d", "a", "cc", "bb"]),
         Case((["bb", "a", "cc", "d"],), ["a", "d", "bb", "cc"]),
         Case((["x", "ab", "x"],), ["x", "x", "ab"]),
         Case(([],), [])),
    )
    round_away = _task(
        "judge-eval2/round-half-away", "round_half_away",
        "Round x to the nearest integer, with halves rounding AWAY from zero "
        "(2.5 -> 3, -2.5 -> -3).",
        (Case((2.5,), 3), Case((-2.5,), -3), Case((2.4,), 2),
         Case((-2.6,), -3), Case((0.5,), 1)),
    )
    dedupe_last = _task(
        "judge-eval2/dedupe-keep-last", "dedupe_keep_last",
        "Remove duplicate values from xs, keeping the LAST occurrence of each "
        "value; the result preserves the order of those kept last occurrences.",
        (Case(([1, 2, 1, 3],), [2, 1, 3]),
         Case(([3, 1, 3, 2, 1],), [3, 2, 1]),
         Case(([1, 1, 1],), [1]),
         Case(([],), [])),
    )
    parse_int = _task(
        "judge-eval2/parse-int-strict", "parse_int_strict",
        "Return the integer value of s. Valid: optional leading/trailing "
        "spaces, an optional single leading + or - sign, then one or more "
        "digits 0-9 and NOTHING else. Return None for anything invalid "
        "(empty, internal spaces, separators, non-digits).",
        (Case((" 42 ",), 42), Case(("-7",), -7), Case(("+3",), 3),
         Case(("4 2",), None), Case(("",), None), Case(("12a",), None),
         Case(("1_0",), None), Case(("--3",), None)),
    )
    most_common = _task(
        "judge-eval2/most-common", "most_common",
        "Return the most frequent element of non-empty xs. Ties are broken by "
        "FIRST occurrence in xs.",
        (Case(([1, 2, 2, 3],), 2),
         Case(([2, 1, 2, 1],), 2),
         Case(([1, 2, 1, 2],), 1),
         Case(([5],), 5)),
    )
    flatten_once = _task(
        "judge-eval2/flatten-once", "flatten_once",
        "Flatten xs by exactly ONE level: elements that are lists contribute "
        "their elements; all other elements (including strings) are kept "
        "as-is, in order.",
        (Case(([[1, 2], [3]],), [1, 2, 3]),
         Case(([[1, [2]], [3]],), [1, [2], 3]),
         Case(([1, [2, 3]],), [1, 2, 3]),
         Case((["ab", [1]],), ["ab", 1]),
         Case(([],), [])),
    )
    interleave = _task(
        "judge-eval2/interleave", "interleave",
        "Interleave lists a and b element by element (a[0], b[0], a[1], b[1], "
        "...); when one list is longer, append its remainder. Elements may be "
        "any value, including None.",
        (Case(([1, 2], [9, 8]), [1, 9, 2, 8]),
         Case(([1, 2, 3], [9]), [1, 9, 2, 3]),
         Case(([None, 2], [9]), [None, 9, 2]),
         Case(([], [1]), [1]),
         Case(([1], []), [1])),
    )
    range_sum = _task(
        "judge-eval2/range-sum", "range_sum_inclusive",
        "Return the sum of all integers from a to b INCLUSIVE. If a > b, "
        "return 0.",
        (Case((1, 4), 10), Case((3, 3), 3), Case((5, 2), 0),
         Case((-2, 2), 0)),
    )
    is_sorted = _task(
        "judge-eval2/strictly-increasing", "is_sorted_strict",
        "Return True iff xs is STRICTLY increasing (every element is greater "
        "than the one before it). Empty and single-element lists are strictly "
        "increasing.",
        (Case(([1, 2, 3],), True), Case(([1, 2, 2],), False),
         Case(([],), True), Case(([5],), True), Case(([3, 1],), False)),
    )
    safe_get = _task(
        "judge-eval2/safe-get", "safe_get",
        "Given nested dicts d and a list of keys path, return the value at "
        "that path. Return None when any step is missing or the current value "
        "is not a dict. An empty path returns d itself.",
        (Case(({"a": {"b": 1}}, ["a", "b"]), 1),
         Case(({"a": 1}, ["a", "b"]), None),
         Case(({}, ["x"]), None),
         Case(({"a": 0}, ["a"]), 0),
         Case(({"a": 2}, []), {"a": 2})),
    )
    count_words = _task(
        "judge-eval2/count-words", "count_words",
        "Count the whitespace-separated words in s. Any run of whitespace "
        "(spaces, tabs, newlines) separates words; punctuation and hyphens "
        "are part of their word. The empty or all-whitespace string has 0.",
        (Case(("a b",), 2), Case(("a\tb\nc",), 3), Case(("",), 0),
         Case(("   ",), 0), Case(("x-y z",), 2)),
    )
    merge_iv = _task(
        "judge-eval2/merge-intervals", "merge_intervals",
        "Merge overlapping OR touching closed intervals [start, end] (touching "
        "means one ends exactly where the next starts). Input is a list of "
        "[start, end] pairs sorted by start; return the merged list of pairs.",
        (Case(([[1, 3], [2, 4]],), [[1, 4]]),
         Case(([[1, 2], [2, 5]],), [[1, 5]]),
         Case(([[1, 5], [2, 3]],), [[1, 5]]),
         Case(([[1, 2], [4, 5]],), [[1, 2], [4, 5]]),
         Case(([],), [])),
    )
    lcp = _task(
        "judge-eval2/common-prefix", "common_prefix",
        "Return the longest common prefix of a non-empty list of strings "
        "('' when there is none).",
        (Case((["flower", "flow", "flight"],), "fl"),
         Case((["flower", "flow"],), "flow"),
         Case((["dog", "racecar"],), ""),
         Case((["same", "same"],), "same"),
         Case((["", "a"],), ""),
         Case((["ab"],), "ab")),
    )
    invert = _task(
        "judge-eval2/invert-mapping", "invert_mapping",
        "Invert dict d so values become keys and keys become values. When "
        "several keys share a value, keep the key that appears FIRST in d's "
        "iteration order.",
        (Case(({"a": 1, "b": 2},), {1: "a", 2: "b"}),
         Case(({"a": 1, "b": 1},), {1: "a"}),
         Case(({},), {})),
    )
    count_range = _task(
        "judge-eval2/count-in-range", "count_in_range",
        "Count the elements x of xs with lo <= x < hi (a HALF-OPEN range: lo "
        "included, hi excluded).",
        (Case(([1, 2, 3, 4], 2, 4), 2),
         Case(([1, 2], 1, 2), 1),
         Case(([5, 5], 5, 5), 0),
         Case(([], 0, 5), 0)),
    )
    snake = _task(
        "judge-eval2/snake-case", "to_snake_case",
        "Convert s (letters only) to snake_case by THIS exact rule: insert an "
        "underscore before every uppercase letter except at position 0, then "
        "lowercase everything. (So consecutive capitals each get their own "
        "underscore: HTTPServer -> h_t_t_p_server.)",
        (Case(("CamelCase",), "camel_case"),
         Case(("simple",), "simple"),
         Case(("HTTPServer",), "h_t_t_p_server"),
         Case(("A",), "a")),
    )
    fib = _task(
        "judge-eval2/fibonacci", "fib",
        "Return the n-th Fibonacci number with F(0) = 0 and F(1) = 1.",
        (Case((0,), 0), Case((1,), 1), Case((2,), 1), Case((7,), 13)),
    )
    rotate = _task(
        "judge-eval2/rotate-left", "rotate_left",
        "Rotate xs left by k positions (k >= 0 and may exceed len(xs); an "
        "empty list stays empty).",
        (Case(([1, 2, 3, 4], 1), [2, 3, 4, 1]),
         Case(([1, 2, 3], 5), [3, 1, 2]),
         Case(([], 3), []),
         Case(([1, 2], 0), [1, 2])),
    )

    return (
        # ================= moving_average =================
        # designed: correct
        _item("V01", moving_avg,
              "def moving_average(xs, k):\n"
              "    return [sum(xs[i:i + k]) / k for i in range(len(xs) - k + 1)]\n"),
        # designed: subtle (window loop bound off by one; drops the last window)
        _item("V02", moving_avg,
              "def moving_average(xs, k):\n"
              "    out = []\n"
              "    for i in range(len(xs) - k):\n"
              "        out.append(sum(xs[i:i + k]) / k)\n"
              "    return out\n"),
        # designed: subtle (integer division truncates the mean)
        _item("V03", moving_avg,
              "def moving_average(xs, k):\n"
              "    return [sum(xs[i:i + k]) // k for i in range(len(xs) - k + 1)]\n"),
        # designed: control (cumulative averages, not windows)
        _item("V04", moving_avg,
              "def moving_average(xs, k):\n"
              "    return [sum(xs[:i + 1]) / (i + 1) for i in range(len(xs))]\n"),
        # ================= binary_search =================
        # designed: correct
        _item("V05", bsearch,
              "def binary_search(xs, v):\n"
              "    lo, hi = 0, len(xs) - 1\n"
              "    while lo <= hi:\n"
              "        mid = (lo + hi) // 2\n"
              "        if xs[mid] == v:\n"
              "            return mid\n"
              "        if xs[mid] < v:\n"
              "            lo = mid + 1\n"
              "        else:\n"
              "            hi = mid - 1\n"
              "    return -1\n"),
        # designed: correct (bisect variant)
        _item("V06", bsearch,
              "import bisect\n"
              "def binary_search(xs, v):\n"
              "    i = bisect.bisect_left(xs, v)\n"
              "    return i if i < len(xs) and xs[i] == v else -1\n"),
        # designed: subtle (loop guard `lo < hi` misses the last narrowing step)
        _item("V07", bsearch,
              "def binary_search(xs, v):\n"
              "    lo, hi = 0, len(xs) - 1\n"
              "    while lo < hi:\n"
              "        mid = (lo + hi) // 2\n"
              "        if xs[mid] == v:\n"
              "            return mid\n"
              "        if xs[mid] < v:\n"
              "            lo = mid + 1\n"
              "        else:\n"
              "            hi = mid - 1\n"
              "    return -1\n"),
        # designed: subtle (hi initialised to len(xs); overruns when v > max)
        _item("V08", bsearch,
              "def binary_search(xs, v):\n"
              "    lo, hi = 0, len(xs)\n"
              "    while lo <= hi:\n"
              "        mid = (lo + hi) // 2\n"
              "        if xs[mid] == v:\n"
              "            return mid\n"
              "        if xs[mid] < v:\n"
              "            lo = mid + 1\n"
              "        else:\n"
              "            hi = mid - 1\n"
              "    return -1\n"),
        # ================= sort_by_length =================
        # designed: correct (Python's sort is stable)
        _item("V09", stable_len,
              "def sort_by_length(words):\n"
              "    return sorted(words, key=len)\n"),
        # designed: subtle (alphabetical tie-break violates the required stability)
        _item("V10", stable_len,
              "def sort_by_length(words):\n"
              "    return sorted(words, key=lambda w: (len(w), w))\n"),
        # designed: subtle (dedups before sorting; duplicates must be kept)
        _item("V11", stable_len,
              "def sort_by_length(words):\n"
              "    return sorted(dict.fromkeys(words), key=len)\n"),
        # designed: control (alphabetical, ignores length entirely)
        _item("V12", stable_len,
              "def sort_by_length(words):\n"
              "    return sorted(words)\n"),
        # ================= round_half_away =================
        # designed: correct
        _item("V13", round_away,
              "def round_half_away(x):\n"
              "    if x >= 0:\n"
              "        return int(x + 0.5)\n"
              "    return int(x - 0.5)\n"),
        # designed: subtle (round() is banker's rounding: 2.5 -> 2, not 3)
        _item("V14", round_away,
              "def round_half_away(x):\n"
              "    return round(x)\n"),
        # designed: subtle (floor(x+0.5) rounds negative halves toward zero)
        _item("V15", round_away,
              "import math\n"
              "def round_half_away(x):\n"
              "    return math.floor(x + 0.5)\n"),
        # ================= dedupe_keep_last =================
        # designed: correct
        _item("V16", dedupe_last,
              "def dedupe_keep_last(xs):\n"
              "    return list(dict.fromkeys(reversed(xs)))[::-1]\n"),
        # designed: correct (remove-then-append keeps the last occurrence's order)
        _item("V17", dedupe_last,
              "def dedupe_keep_last(xs):\n"
              "    out = []\n"
              "    for x in xs:\n"
              "        if x in out:\n"
              "            out.remove(x)\n"
              "        out.append(x)\n"
              "    return out\n"),
        # designed: subtle (keeps the FIRST occurrence; task says last)
        _item("V18", dedupe_last,
              "def dedupe_keep_last(xs):\n"
              "    return list(dict.fromkeys(xs))\n"),
        # designed: control (sorted set: wrong order and wrong semantics)
        _item("V19", dedupe_last,
              "def dedupe_keep_last(xs):\n"
              "    return sorted(set(xs))\n"),
        # ================= parse_int_strict =================
        # designed: correct
        _item("V20", parse_int,
              "def parse_int_strict(s):\n"
              "    t = s.strip()\n"
              "    body = t[1:] if t[:1] in ('+', '-') else t\n"
              "    if body and all('0' <= c <= '9' for c in body):\n"
              "        return int(t)\n"
              "    return None\n"),
        # designed: correct (anchored pattern)
        _item("V21", parse_int,
              "import re\n"
              "def parse_int_strict(s):\n"
              "    match = re.fullmatch(r'[+-]?[0-9]+', s.strip())\n"
              "    return int(match.group(0)) if match else None\n"),
        # designed: subtle (int() accepts underscore separators: '1_0' parses as 10)
        _item("V22", parse_int,
              "def parse_int_strict(s):\n"
              "    try:\n"
              "        return int(s)\n"
              "    except ValueError:\n"
              "        return None\n"),
        # designed: subtle (never strips, so valid padded input is rejected)
        _item("V23", parse_int,
              "def parse_int_strict(s):\n"
              "    body = s[1:] if s[:1] in ('+', '-') else s\n"
              "    if body.isdigit() and all('0' <= c <= '9' for c in body):\n"
              "        return int(s)\n"
              "    return None\n"),
        # ================= most_common =================
        # designed: correct (Counter ties follow first insertion)
        _item("V24", most_common,
              "from collections import Counter\n"
              "def most_common(xs):\n"
              "    return Counter(xs).most_common(1)[0][0]\n"),
        # designed: correct (max scans xs in order, so ties keep first occurrence)
        _item("V25", most_common,
              "def most_common(xs):\n"
              "    return max(xs, key=xs.count)\n"),
        # designed: subtle (iterating the SET breaks the first-occurrence tie-break)
        _item("V26", most_common,
              "def most_common(xs):\n"
              "    return max(set(xs), key=xs.count)\n"),
        # designed: control (largest value, not most frequent)
        _item("V27", most_common,
              "def most_common(xs):\n"
              "    return max(xs)\n"),
        # ================= flatten_once =================
        # designed: correct
        _item("V28", flatten_once,
              "def flatten_once(xs):\n"
              "    out = []\n"
              "    for x in xs:\n"
              "        if isinstance(x, list):\n"
              "            out.extend(x)\n"
              "        else:\n"
              "            out.append(x)\n"
              "    return out\n"),
        # designed: subtle (sum-concat crashes on any non-list element)
        _item("V29", flatten_once,
              "def flatten_once(xs):\n"
              "    return sum(xs, [])\n"),
        # designed: subtle (recursive full flatten; task says exactly one level)
        _item("V30", flatten_once,
              "def flatten_once(xs):\n"
              "    out = []\n"
              "    for x in xs:\n"
              "        if isinstance(x, list):\n"
              "            out.extend(flatten_once(x))\n"
              "        else:\n"
              "            out.append(x)\n"
              "    return out\n"),
        # designed: subtle (treats strings as sequences and splats their characters)
        _item("V31", flatten_once,
              "def flatten_once(xs):\n"
              "    out = []\n"
              "    for x in xs:\n"
              "        try:\n"
              "            out.extend(x)\n"
              "        except TypeError:\n"
              "            out.append(x)\n"
              "    return out\n"),
        # ================= interleave =================
        # designed: correct
        _item("V32", interleave,
              "def interleave(a, b):\n"
              "    out = []\n"
              "    n = min(len(a), len(b))\n"
              "    for i in range(n):\n"
              "        out.append(a[i])\n"
              "        out.append(b[i])\n"
              "    out.extend(a[n:])\n"
              "    out.extend(b[n:])\n"
              "    return out\n"),
        # designed: subtle (zip silently truncates; both remainders are dropped)
        _item("V33", interleave,
              "def interleave(a, b):\n"
              "    out = []\n"
              "    for x, y in zip(a, b):\n"
              "        out.append(x)\n"
              "        out.append(y)\n"
              "    return out\n"),
        # designed: subtle (None used as the fill sentinel eats legitimate None data)
        _item("V34", interleave,
              "from itertools import zip_longest\n"
              "def interleave(a, b):\n"
              "    out = []\n"
              "    for x, y in zip_longest(a, b):\n"
              "        if x is not None:\n"
              "            out.append(x)\n"
              "        if y is not None:\n"
              "            out.append(y)\n"
              "    return out\n"),
        # designed: subtle (exception-as-flow bails out and drops both tails)
        _item("V35", interleave,
              "def interleave(a, b):\n"
              "    out = []\n"
              "    for i in range(max(len(a), len(b))):\n"
              "        try:\n"
              "            out.append(a[i])\n"
              "            out.append(b[i])\n"
              "        except IndexError:\n"
              "            break\n"
              "    return out\n"),
        # ================= range_sum_inclusive =================
        # designed: correct
        _item("V36", range_sum,
              "def range_sum_inclusive(a, b):\n"
              "    if a > b:\n"
              "        return 0\n"
              "    return sum(range(a, b + 1))\n"),
        # designed: correct (an empty range already sums to 0; no guard needed)
        _item("V37", range_sum,
              "def range_sum_inclusive(a, b):\n"
              "    return sum(range(a, b + 1))\n"),
        # designed: subtle (range() excludes the endpoint; b is never added)
        _item("V38", range_sum,
              "def range_sum_inclusive(a, b):\n"
              "    return sum(range(a, b))\n"),
        # designed: subtle (closed formula without the a > b guard goes negative)
        _item("V39", range_sum,
              "def range_sum_inclusive(a, b):\n"
              "    return (a + b) * (b - a + 1) // 2\n"),
        # ================= is_sorted_strict =================
        # designed: correct
        _item("V40", is_sorted,
              "def is_sorted_strict(xs):\n"
              "    return all(x < y for x, y in zip(xs, xs[1:]))\n"),
        # designed: correct (index form)
        _item("V41", is_sorted,
              "def is_sorted_strict(xs):\n"
              "    for i in range(len(xs) - 1):\n"
              "        if xs[i] >= xs[i + 1]:\n"
              "            return False\n"
              "    return True\n"),
        # designed: subtle (sorted-equality is non-strict: [1,2,2] passes it)
        _item("V42", is_sorted,
              "def is_sorted_strict(xs):\n"
              "    return xs == sorted(xs)\n"),
        # designed: subtle (<= admits equal neighbours; the task says strictly)
        _item("V43", is_sorted,
              "def is_sorted_strict(xs):\n"
              "    return all(x <= y for x, y in zip(xs, xs[1:]))\n"),
        # ================= safe_get =================
        # designed: correct
        _item("V44", safe_get,
              "def safe_get(d, path):\n"
              "    cur = d\n"
              "    for k in path:\n"
              "        if not isinstance(cur, dict) or k not in cur:\n"
              "            return None\n"
              "        cur = cur[k]\n"
              "    return cur\n"),
        # designed: subtle (get-chaining crashes when a step is not a dict)
        _item("V45", safe_get,
              "def safe_get(d, path):\n"
              "    cur = d\n"
              "    for k in path:\n"
              "        cur = cur.get(k)\n"
              "        if cur is None:\n"
              "            return None\n"
              "    return cur\n"),
        # designed: subtle (returns {} on a miss; the task says None)
        _item("V46", safe_get,
              "def safe_get(d, path):\n"
              "    cur = d\n"
              "    for k in path:\n"
              "        if not isinstance(cur, dict) or k not in cur:\n"
              "            return {}\n"
              "        cur = cur[k]\n"
              "    return cur\n"),
        # ================= count_words =================
        # designed: correct
        _item("V47", count_words,
              "def count_words(s):\n"
              "    return len(s.split())\n"),
        # designed: subtle (split(' ') neither collapses runs nor sees tabs/newlines)
        _item("V48", count_words,
              "def count_words(s):\n"
              "    return len(s.split(' '))\n"),
        # designed: subtle (word-character runs split hyphenated words)
        _item("V49", count_words,
              "import re\n"
              "def count_words(s):\n"
              "    return len(re.findall(r'\\w+', s))\n"),
        # ================= merge_intervals =================
        # designed: correct
        _item("V50", merge_iv,
              "def merge_intervals(iv):\n"
              "    out = []\n"
              "    for pair in iv:\n"
              "        if out and pair[0] <= out[-1][1]:\n"
              "            out[-1][1] = max(out[-1][1], pair[1])\n"
              "        else:\n"
              "            out.append(list(pair))\n"
              "    return out\n"),
        # designed: subtle (strict < in the merge test misses touching intervals)
        _item("V51", merge_iv,
              "def merge_intervals(iv):\n"
              "    out = []\n"
              "    for pair in iv:\n"
              "        if out and pair[0] < out[-1][1]:\n"
              "            out[-1][1] = max(out[-1][1], pair[1])\n"
              "        else:\n"
              "            out.append(list(pair))\n"
              "    return out\n"),
        # designed: subtle (takes the new end unconditionally; contained intervals shrink the merge)
        _item("V52", merge_iv,
              "def merge_intervals(iv):\n"
              "    out = []\n"
              "    for pair in iv:\n"
              "        if out and pair[0] <= out[-1][1]:\n"
              "            out[-1][1] = pair[1]\n"
              "        else:\n"
              "            out.append(list(pair))\n"
              "    return out\n"),
        # ================= common_prefix =================
        # designed: correct
        _item("V53", lcp,
              "def common_prefix(strs):\n"
              "    prefix = []\n"
              "    for chars in zip(*strs):\n"
              "        if len(set(chars)) != 1:\n"
              "            break\n"
              "        prefix.append(chars[0])\n"
              "    return ''.join(prefix)\n"),
        # designed: correct (sorted-endpoints trick: only the extremes can differ first)
        _item("V54", lcp,
              "def common_prefix(strs):\n"
              "    lo, hi = min(strs), max(strs)\n"
              "    for i, c in enumerate(lo):\n"
              "        if c != hi[i]:\n"
              "            return lo[:i]\n"
              "    return lo\n"),
        # designed: subtle (indexes the first string's full length; overruns shorter strings)
        _item("V55", lcp,
              "def common_prefix(strs):\n"
              "    for i in range(len(strs[0])):\n"
              "        for s in strs[1:]:\n"
              "            if s[i] != strs[0][i]:\n"
              "                return strs[0][:i]\n"
              "    return strs[0]\n"),
        # ================= invert_mapping =================
        # designed: correct
        _item("V56", invert,
              "def invert_mapping(d):\n"
              "    out = {}\n"
              "    for k, v in d.items():\n"
              "        if v not in out:\n"
              "            out[v] = k\n"
              "    return out\n"),
        # designed: subtle (the one-line comprehension keeps the LAST duplicate)
        _item("V57", invert,
              "def invert_mapping(d):\n"
              "    return {v: k for k, v in d.items()}\n"),
        # ================= count_in_range =================
        # designed: correct
        _item("V58", count_range,
              "def count_in_range(xs, lo, hi):\n"
              "    return sum(1 for x in xs if lo <= x < hi)\n"),
        # designed: subtle (closed range: includes hi, which the task excludes)
        _item("V59", count_range,
              "def count_in_range(xs, lo, hi):\n"
              "    return sum(1 for x in xs if lo <= x <= hi)\n"),
        # designed: subtle (open at lo: excludes lo, which the task includes)
        _item("V60", count_range,
              "def count_in_range(xs, lo, hi):\n"
              "    return sum(1 for x in xs if lo < x < hi)\n"),
        # ================= to_snake_case =================
        # designed: correct
        _item("V61", snake,
              "def to_snake_case(s):\n"
              "    out = []\n"
              "    for i, c in enumerate(s):\n"
              "        if c.isupper() and i > 0:\n"
              "            out.append('_')\n"
              "        out.append(c.lower())\n"
              "    return ''.join(out)\n"),
        # designed: correct (regex form of the same stated rule)
        _item("V62", snake,
              "import re\n"
              "def to_snake_case(s):\n"
              "    return re.sub(r'(?<!^)(?=[A-Z])', '_', s).lower()\n"),
        # designed: subtle (misses the except-at-position-0 clause)
        _item("V63", snake,
              "def to_snake_case(s):\n"
              "    out = []\n"
              "    for c in s:\n"
              "        if c.isupper():\n"
              "            out.append('_')\n"
              "        out.append(c.lower())\n"
              "    return ''.join(out)\n"),
        # designed: subtle (the 'smarter' acronym-aware rule violates the stated simple one)
        _item("V64", snake,
              "import re\n"
              "def to_snake_case(s):\n"
              "    s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\\1_\\2', s)\n"
              "    s = re.sub(r'([a-z])([A-Z])', r'\\1_\\2', s)\n"
              "    return s.lower()\n"),
        # ================= fib =================
        # designed: correct
        _item("V65", fib,
              "def fib(n):\n"
              "    a, b = 0, 1\n"
              "    for _ in range(n):\n"
              "        a, b = b, a + b\n"
              "    return a\n"),
        # designed: subtle (returns b: the sequence shifted by one)
        _item("V66", fib,
              "def fib(n):\n"
              "    a, b = 0, 1\n"
              "    for _ in range(n):\n"
              "        a, b = b, a + b\n"
              "    return b\n"),
        # designed: control (powers of two)
        _item("V67", fib,
              "def fib(n):\n"
              "    return 2 ** n\n"),
        # ================= rotate_left =================
        # designed: correct
        _item("V68", rotate,
              "def rotate_left(xs, k):\n"
              "    if not xs:\n"
              "        return []\n"
              "    k %= len(xs)\n"
              "    return xs[k:] + xs[:k]\n"),
        # designed: subtle (no modulo: k past the end silently returns the wrong rotation)
        _item("V69", rotate,
              "def rotate_left(xs, k):\n"
              "    return xs[k:] + xs[:k]\n"),
        # designed: subtle (modulo without the empty guard divides by zero)
        _item("V70", rotate,
              "def rotate_left(xs, k):\n"
              "    k %= len(xs)\n"
              "    return xs[k:] + xs[:k]\n"),
        # ================= second wave: harder mixes on earlier tasks ==========
        # designed: correct (explicit-window form: the exact-length filter makes
        # the loop bound harmless — looks like V02's bug but is not; false-FAIL bait)
        _item("V71", moving_avg,
              "def moving_average(xs, k):\n"
              "    out = []\n"
              "    for i in range(len(xs)):\n"
              "        window = xs[i:i + k]\n"
              "        if len(window) == k:\n"
              "            out.append(sum(window) / len(window))\n"
              "    return out\n"),
        # designed: subtle (banker's rounding hidden behind a formatting round-trip)
        _item("V72", round_away,
              "def round_half_away(x):\n"
              "    return int(format(x, '.0f'))\n"),
        # designed: subtle (dedupe-keep-last via reverse scan, but appends give
        # reversed output order)
        _item("V73", dedupe_last,
              "def dedupe_keep_last(xs):\n"
              "    seen = set()\n"
              "    out = []\n"
              "    for x in reversed(xs):\n"
              "        if x not in seen:\n"
              "            seen.add(x)\n"
              "            out.append(x)\n"
              "    return out\n"),
        # designed: correct (same scan with the order restored)
        _item("V74", dedupe_last,
              "def dedupe_keep_last(xs):\n"
              "    seen = set()\n"
              "    out = []\n"
              "    for x in reversed(xs):\n"
              "        if x not in seen:\n"
              "            seen.add(x)\n"
              "            out.append(x)\n"
              "    return out[::-1]\n"),
        # designed: subtle (strip() default also strips newlines/tabs — fine — but
        # the sign test uses lstrip('+-') which accepts '+-3' and '--3')
        _item("V75", parse_int,
              "def parse_int_strict(s):\n"
              "    t = s.strip()\n"
              "    body = t.lstrip('+-')\n"
              "    if body and all('0' <= c <= '9' for c in body):\n"
              "        return int(t)\n"
              "    return None\n"),
        # designed: subtle (interleave starting from b: order swapped only when
        # both lists are non-empty, so the empty-list cases still pass)
        _item("V76", interleave,
              "def interleave(a, b):\n"
              "    out = []\n"
              "    n = min(len(a), len(b))\n"
              "    for i in range(n):\n"
              "        out.append(b[i])\n"
              "        out.append(a[i])\n"
              "    out.extend(a[n:])\n"
              "    out.extend(b[n:])\n"
              "    return out\n"),
        # designed: subtle (merge that never widens: only merges when the next
        # interval is fully covered, so plain overlaps produce split output)
        _item("V77", merge_iv,
              "def merge_intervals(iv):\n"
              "    out = []\n"
              "    for pair in iv:\n"
              "        if out and pair[1] <= out[-1][1]:\n"
              "            continue\n"
              "        out.append(list(pair))\n"
              "    return out\n"),
        # designed: subtle (correct traversal, but `or None` "normalises" falsy
        # stored values — a present 0 comes back as a miss)
        _item("V78", safe_get,
              "def safe_get(d, path):\n"
              "    cur = d\n"
              "    for k in path:\n"
              "        if not isinstance(cur, dict) or k not in cur:\n"
              "            return None\n"
              "        cur = cur[k]\n"
              "    return cur or None\n"),
        # designed: subtle (fib memoized but the base table is {1: 1, 2: 1}: the
        # 1-indexed convention, so F(0) crashes and everything shifts)
        _item("V79", fib,
              "def fib(n):\n"
              "    table = {1: 1, 2: 1}\n"
              "    def go(i):\n"
              "        if i not in table:\n"
              "            table[i] = go(i - 1) + go(i - 2)\n"
              "        return table[i]\n"
              "    return go(n)\n"),
        # designed: subtle (rotate right instead of left; k=0 and empty pass)
        _item("V80", rotate,
              "def rotate_left(xs, k):\n"
              "    if not xs:\n"
              "        return []\n"
              "    k %= len(xs)\n"
              "    return xs[-k:] + xs[:-k]\n"),
        # designed: correct (distinct + sorted IS strictly increasing — an
        # equivalent formulation that looks like a proxy hack; false-FAIL bait)
        _item("V81", is_sorted,
              "def is_sorted_strict(xs):\n"
              "    return len(set(xs)) == len(xs) and xs == sorted(xs)\n"),
        # designed: control (always True)
        _item("V82", is_sorted,
              "def is_sorted_strict(xs):\n"
              "    return True\n"),
    )
