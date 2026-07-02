"""The extended judge-eval item set for live (load-bearing) measurement.

The bundled ten-item set in ``judge_eval`` exists to prove the harness with
hand-checkable numbers; it is far too small for load-bearing percentages. This
module is the committed item set live runs use: fifteen tasks, forty-eight
candidates, weighted toward PLAUSIBLE-BUT-WRONG solutions (off-by-one, missed
edge cases, right-shape-wrong-logic) — the candidates false-PASS measurement
lives on, since a set of obviously-right and obviously-wrong items flatters
any judge.

Ground truth is never hand-labelled: the HARD subprocess verifier decides it by
executing every candidate against the hidden cases inside the mandatory
isolating sandbox. The design-intent categories in the comments below document
composition; they carry no authority. Candidate code strings contain nothing
but the item marker and the code — no hints ride into the judge prompt.

Every candidate is deterministic, stdlib-only, and terminates promptly (no
loops that could hit the wall clock: a timed-out reference would ABSTAIN and
silently shrink the measured set).

All items carry the neutral ``bundled-fixture`` actor attribution: none of
these candidates was produced by any live actor model, so the per-item
actor-identity split is intentionally not meaningful here. The correlated
vs independent comparison across live runs comes from the documented two-run
procedure (vary the judge config, compare the runs).
"""

from __future__ import annotations

from prometheus_protocol.benchmarks.judge_eval import EvalItem, _MARKER
from prometheus_protocol.core.models import Case, Task

#: Recorded in reports so numbers are tied to the exact set they came from.
LIVE_ITEM_SET_VERSION = "live-v1 (48 items)"

#: Honest attribution: these fixtures were not produced by any live actor.
FIXTURE_ACTOR = "bundled-fixture"


def _task(task_id: str, entry: str, prompt: str, cases: tuple[Case, ...]) -> Task:
    return Task(id=task_id, entry_point=entry, prompt=prompt, split="train", cases=cases)


def _item(item_id: str, task: Task, body: str) -> EvalItem:
    return EvalItem(item_id, task, f"{_MARKER}{item_id}\n{body}", FIXTURE_ACTOR)


def build_live_eval_items() -> tuple[EvalItem, ...]:
    median = _task(
        "judge-eval/median", "median",
        "Return the median of a non-empty list of numbers: the middle value of "
        "the sorted list, or the average of the two middle values when the "
        "length is even.",
        (Case(([1, 3, 2],), 2), Case(([4, 1, 3, 2],), 2.5),
         Case(([5],), 5), Case(([2, 2, 4, 4],), 3.0)),
    )
    first_index = _task(
        "judge-eval/first-index", "first_index",
        "Return the index of the first occurrence of v in the list xs, or -1 "
        "when v is absent.",
        (Case(([1, 2, 3, 2], 2), 1), Case(([1, 2], 5), -1),
         Case(([], 7), -1), Case(([4, 4], 4), 0)),
    )
    count_vowels = _task(
        "judge-eval/count-vowels", "count_vowels",
        "Count the vowels (a, e, i, o, u — case-insensitive) in the string s.",
        (Case(("Hello",), 2), Case(("xyz",), 0),
         Case(("AEiou",), 5), Case(("",), 0)),
    )
    palindrome = _task(
        "judge-eval/palindrome", "is_palindrome",
        "Return True iff s reads the same forwards and backwards, comparing "
        "exact characters (case-sensitive). The empty string is a palindrome.",
        (Case(("aba",), True), Case(("ab",), False),
         Case(("",), True), Case(("Aa",), False)),
    )
    sum_digits = _task(
        "judge-eval/sum-digits", "sum_digits",
        "Return the sum of the decimal digits of the integer n; for negative n "
        "use the digits of its absolute value.",
        (Case((123,), 6), Case((-45,), 9), Case((0,), 0), Case((999,), 27)),
    )
    running_max = _task(
        "judge-eval/running-max", "running_max",
        "Return a list whose element i is the maximum of xs[0..i] inclusive.",
        (Case(([3, 1, 4, 1, 5],), [3, 3, 4, 4, 5]), Case(([2],), [2]),
         Case(([5, 4, 3],), [5, 5, 5]), Case(([],), [])),
    )
    reverse_words = _task(
        "judge-eval/reverse-words", "reverse_words",
        "Return s with the order of its whitespace-separated words reversed, "
        "joined by single spaces (leading/trailing/repeated whitespace "
        "collapses).",
        (Case(("a b c",), "c b a"), Case(("hello",), "hello"),
         Case(("",), ""), Case(("  x  y ",), "y x")),
    )
    clamp = _task(
        "judge-eval/clamp-live", "clamp",
        "Clamp x into the inclusive range [lo, hi].",
        (Case((5, 0, 10), 5), Case((0, 0, 10), 0), Case((10, 0, 10), 10),
         Case((-1, 0, 10), 0), Case((11, 0, 10), 10)),
    )
    second_largest = _task(
        "judge-eval/second-largest", "second_largest",
        "Return the second-largest DISTINCT value in xs (xs always contains at "
        "least two distinct values).",
        (Case(([1, 3, 2],), 2), Case(([5, 5, 4],), 4),
         Case(([2, 1],), 1), Case(([7, 7, 9, 9, 3],), 7)),
    )
    factorial = _task(
        "judge-eval/factorial", "factorial",
        "Return n! (the factorial of n) for integers n >= 0; 0! is 1.",
        (Case((0,), 1), Case((1,), 1), Case((5,), 120)),
    )
    merge_sorted = _task(
        "judge-eval/merge-sorted", "merge_sorted",
        "Merge two already-sorted lists a and b into one sorted list containing "
        "all elements of both.",
        (Case(([1, 3], [2, 4]), [1, 2, 3, 4]), Case(([], [1]), [1]),
         Case(([1, 1], [1]), [1, 1, 1]), Case(([5], []), [5])),
    )
    unique_in_order = _task(
        "judge-eval/unique-in-order", "unique_in_order",
        "Return the elements of xs with CONSECUTIVE duplicates collapsed to "
        "one, preserving order (non-adjacent repeats stay).",
        (Case(([1, 1, 2, 2, 3],), [1, 2, 3]), Case(([1, 2, 1],), [1, 2, 1]),
         Case(([],), []), Case(([4, 4, 4, 4],), [4])),
    )
    dot = _task(
        "judge-eval/dot", "dot",
        "Return the dot product of two equal-length numeric vectors a and b "
        "(0 for empty vectors).",
        (Case(([1, 2], [3, 4]), 11), Case(([], []), 0), Case(([2], [5]), 10)),
    )
    title_case = _task(
        "judge-eval/title-case", "title_case",
        "Capitalize the first letter of each whitespace-separated word and "
        "lower-case the rest of each word, joining with single spaces.",
        (Case(("hello world",), "Hello World"), Case(("PYTHON",), "Python"),
         Case(("",), ""), Case(("a b",), "A B")),
    )
    safe_div = _task(
        "judge-eval/safe-div", "safe_div",
        "Return a divided by b as a float, or None when b is zero.",
        (Case((6, 3), 2.0), Case((1, 0), None),
         Case((0, 5), 0.0), Case((7, 2), 3.5)),
    )

    return (
        # -- median ----------------------------------------------------------
        # designed: correct
        _item("L01", median,
              "def median(xs):\n"
              "    s = sorted(xs)\n"
              "    n = len(s)\n"
              "    if n % 2 == 1:\n"
              "        return s[n // 2]\n"
              "    return (s[n // 2 - 1] + s[n // 2]) / 2\n"),
        # designed: subtle (forgets to sort first)
        _item("L02", median,
              "def median(xs):\n"
              "    n = len(xs)\n"
              "    if n % 2 == 1:\n"
              "        return xs[n // 2]\n"
              "    return (xs[n // 2 - 1] + xs[n // 2]) / 2\n"),
        # designed: subtle (even length takes one middle value, no averaging)
        _item("L03", median,
              "def median(xs):\n"
              "    s = sorted(xs)\n"
              "    return s[len(s) // 2]\n"),
        # designed: clearly wrong (maximum, not median)
        _item("L04", median,
              "def median(xs):\n"
              "    return max(xs)\n"),
        # -- first_index -------------------------------------------------------
        # designed: correct
        _item("L05", first_index,
              "def first_index(xs, v):\n"
              "    for i, x in enumerate(xs):\n"
              "        if x == v:\n"
              "            return i\n"
              "    return -1\n"),
        # designed: subtle (returns the LAST occurrence)
        _item("L06", first_index,
              "def first_index(xs, v):\n"
              "    idx = -1\n"
              "    for i, x in enumerate(xs):\n"
              "        if x == v:\n"
              "            idx = i\n"
              "    return idx\n"),
        # designed: subtle (list.index raises when v is absent)
        _item("L07", first_index,
              "def first_index(xs, v):\n"
              "    return xs.index(v)\n"),
        # designed: subtle (None instead of -1 for absent)
        _item("L08", first_index,
              "def first_index(xs, v):\n"
              "    for i, x in enumerate(xs):\n"
              "        if x == v:\n"
              "            return i\n"
              "    return None\n"),
        # -- count_vowels ------------------------------------------------------
        # designed: correct
        _item("L09", count_vowels,
              "def count_vowels(s):\n"
              "    return sum(1 for c in s if c.lower() in 'aeiou')\n"),
        # designed: subtle (misses upper-case vowels)
        _item("L10", count_vowels,
              "def count_vowels(s):\n"
              "    return sum(1 for c in s if c in 'aeiou')\n"),
        # designed: clearly wrong (counts non-vowel letters)
        _item("L11", count_vowels,
              "def count_vowels(s):\n"
              "    return sum(1 for c in s if c.isalpha() and c.lower() not in 'aeiou')\n"),
        # -- is_palindrome -----------------------------------------------------
        # designed: correct
        _item("L12", palindrome,
              "def is_palindrome(s):\n"
              "    return s == s[::-1]\n"),
        # designed: subtle (case-insensitive, but the task is case-sensitive)
        _item("L13", palindrome,
              "def is_palindrome(s):\n"
              "    t = s.lower()\n"
              "    return t == t[::-1]\n"),
        # designed: subtle (compares only the outermost characters; crashes on '')
        _item("L14", palindrome,
              "def is_palindrome(s):\n"
              "    return s[0] == s[-1]\n"),
        # -- sum_digits --------------------------------------------------------
        # designed: correct
        _item("L15", sum_digits,
              "def sum_digits(n):\n"
              "    return sum(int(d) for d in str(abs(n)))\n"),
        # designed: subtle (forgets negatives; int('-') raises)
        _item("L16", sum_digits,
              "def sum_digits(n):\n"
              "    return sum(int(d) for d in str(n))\n"),
        # designed: subtle (loop guard skips negative input entirely)
        _item("L17", sum_digits,
              "def sum_digits(n):\n"
              "    total = 0\n"
              "    while n > 0:\n"
              "        total += n % 10\n"
              "        n //= 10\n"
              "    return total\n"),
        # -- running_max -------------------------------------------------------
        # designed: correct
        _item("L18", running_max,
              "def running_max(xs):\n"
              "    out = []\n"
              "    cur = None\n"
              "    for x in xs:\n"
              "        cur = x if cur is None else max(cur, x)\n"
              "        out.append(cur)\n"
              "    return out\n"),
        # designed: subtle (appends the maximum BEFORE seeing the current element)
        _item("L19", running_max,
              "def running_max(xs):\n"
              "    out = []\n"
              "    cur = xs[0]\n"
              "    for x in xs:\n"
              "        out.append(cur)\n"
              "        cur = max(cur, x)\n"
              "    return out\n"),
        # designed: clearly wrong (sorts instead of scanning)
        _item("L20", running_max,
              "def running_max(xs):\n"
              "    return sorted(xs)\n"),
        # -- reverse_words -----------------------------------------------------
        # designed: correct
        _item("L21", reverse_words,
              "def reverse_words(s):\n"
              "    return ' '.join(reversed(s.split()))\n"),
        # designed: subtle (split(' ') keeps empty fields; whitespace not collapsed)
        _item("L22", reverse_words,
              "def reverse_words(s):\n"
              "    return ' '.join(reversed(s.split(' ')))\n"),
        # designed: subtle (reverses characters, which coincides on 1-char words)
        _item("L23", reverse_words,
              "def reverse_words(s):\n"
              "    return s[::-1]\n"),
        # designed: correct (slicing variant)
        _item("L24", reverse_words,
              "def reverse_words(s):\n"
              "    return ' '.join(s.split()[::-1])\n"),
        # -- clamp -------------------------------------------------------------
        # designed: correct
        _item("L25", clamp,
              "def clamp(x, lo, hi):\n"
              "    return max(lo, min(x, hi))\n"),
        # designed: subtle (min/max swapped — right shape, wrong logic)
        _item("L26", clamp,
              "def clamp(x, lo, hi):\n"
              "    return min(lo, max(x, hi))\n"),
        # designed: subtle (no upper clamp)
        _item("L27", clamp,
              "def clamp(x, lo, hi):\n"
              "    return max(lo, x)\n"),
        # -- second_largest ----------------------------------------------------
        # designed: correct
        _item("L28", second_largest,
              "def second_largest(xs):\n"
              "    return sorted(set(xs))[-2]\n"),
        # designed: subtle (duplicates not collapsed before picking)
        _item("L29", second_largest,
              "def second_largest(xs):\n"
              "    return sorted(xs)[-2]\n"),
        # designed: clearly wrong (minimum)
        _item("L30", second_largest,
              "def second_largest(xs):\n"
              "    return min(xs)\n"),
        # -- factorial ---------------------------------------------------------
        # designed: correct
        _item("L31", factorial,
              "def factorial(n):\n"
              "    result = 1\n"
              "    for i in range(2, n + 1):\n"
              "        result *= i\n"
              "    return result\n"),
        # designed: subtle (off-by-one: product stops at n-1)
        _item("L32", factorial,
              "def factorial(n):\n"
              "    result = 1\n"
              "    for i in range(1, n):\n"
              "        result *= i\n"
              "    return result\n"),
        # designed: subtle (0! handled as 0)
        _item("L33", factorial,
              "def factorial(n):\n"
              "    if n == 0:\n"
              "        return 0\n"
              "    result = 1\n"
              "    for i in range(2, n + 1):\n"
              "        result *= i\n"
              "    return result\n"),
        # -- merge_sorted ------------------------------------------------------
        # designed: correct
        _item("L34", merge_sorted,
              "def merge_sorted(a, b):\n"
              "    return sorted(a + b)\n"),
        # designed: subtle (concatenates without restoring order)
        _item("L35", merge_sorted,
              "def merge_sorted(a, b):\n"
              "    return a + b\n"),
        # designed: subtle (two-pointer merge drops the unconsumed tail)
        _item("L36", merge_sorted,
              "def merge_sorted(a, b):\n"
              "    out = []\n"
              "    i = j = 0\n"
              "    while i < len(a) and j < len(b):\n"
              "        if a[i] <= b[j]:\n"
              "            out.append(a[i])\n"
              "            i += 1\n"
              "        else:\n"
              "            out.append(b[j])\n"
              "            j += 1\n"
              "    return out\n"),
        # -- unique_in_order ---------------------------------------------------
        # designed: correct
        _item("L37", unique_in_order,
              "def unique_in_order(xs):\n"
              "    out = []\n"
              "    for x in xs:\n"
              "        if not out or out[-1] != x:\n"
              "            out.append(x)\n"
              "    return out\n"),
        # designed: subtle (global dedup; non-adjacent repeats wrongly removed)
        _item("L38", unique_in_order,
              "def unique_in_order(xs):\n"
              "    return list(dict.fromkeys(xs))\n"),
        # designed: clearly wrong (no dedup at all)
        _item("L39", unique_in_order,
              "def unique_in_order(xs):\n"
              "    return list(xs)\n"),
        # -- dot ---------------------------------------------------------------
        # designed: correct
        _item("L40", dot,
              "def dot(a, b):\n"
              "    return sum(x * y for x, y in zip(a, b))\n"),
        # designed: subtle (sum(a)*sum(b) coincides on short vectors)
        _item("L41", dot,
              "def dot(a, b):\n"
              "    return sum(a) * sum(b)\n"),
        # -- title_case --------------------------------------------------------
        # designed: correct
        _item("L42", title_case,
              "def title_case(s):\n"
              "    return ' '.join(w[:1].upper() + w[1:].lower() for w in s.split())\n"),
        # designed: subtle (capitalizes the string, not each word)
        _item("L43", title_case,
              "def title_case(s):\n"
              "    return s.capitalize()\n"),
        # designed: subtle (upper-cases first letters but never lowers the rest)
        _item("L44", title_case,
              "def title_case(s):\n"
              "    return ' '.join(w[:1].upper() + w[1:] for w in s.split())\n"),
        # -- safe_div ----------------------------------------------------------
        # designed: correct
        _item("L45", safe_div,
              "def safe_div(a, b):\n"
              "    if b == 0:\n"
              "        return None\n"
              "    return a / b\n"),
        # designed: subtle (0 instead of None for the zero divisor)
        _item("L46", safe_div,
              "def safe_div(a, b):\n"
              "    if b == 0:\n"
              "        return 0\n"
              "    return a / b\n"),
        # designed: subtle (integer division; also crashes on b == 0)
        _item("L47", safe_div,
              "def safe_div(a, b):\n"
              "    return a // b\n"),
        # designed: clearly wrong (always None)
        _item("L48", safe_div,
              "def safe_div(a, b):\n"
              "    return None\n"),
    )
