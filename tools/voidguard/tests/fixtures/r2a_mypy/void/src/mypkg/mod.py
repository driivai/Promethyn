from mypkg import helper  # first-party import: unresolvable without mypy_path


def f() -> int:
    return helper.g()
