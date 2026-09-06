"""Bounded data-only wire format. Never deserialize candidate Python objects.

Shared encoder code is staged in the disposable workspace, but only the
trusted parent's decoder/comparator has authority. Child copies are untrusted.
"""

from __future__ import annotations

import json
import re
from typing import Any, NoReturn

MAX_BYTES = 1_000_000
MAX_DEPTH = 32
MAX_NODES = 20_000


def _reject_number(value: str) -> NoReturn:
    raise ValueError("wire numbers must be tagged strings")


def dumps(value: Any) -> str:
    budget = [MAX_NODES]

    def encode(obj: Any, depth: int = 0) -> Any:
        budget[0] -= 1
        if depth > MAX_DEPTH or budget[0] < 0:
            raise ValueError("value exceeds structural limits")
        kind = type(obj)
        if obj is None:
            return ["none", ""]
        if kind is bool:
            return ["bool", "true" if obj else "false"]
        if kind is int:
            if obj.bit_length() > 13_000:
                raise ValueError("integer too large")
            return ["int", str(obj)]
        if kind is float:
            return ["float", obj.hex()]
        if kind is str:
            return ["str", obj]
        if kind is bytes:
            return ["bytes", obj.hex()]
        if kind in (list, tuple):
            return [kind.__name__, [encode(x, depth + 1) for x in obj]]
        if kind is dict:
            return [
                "dict",
                [[encode(k, depth + 1), encode(v, depth + 1)] for k, v in obj.items()],
            ]
        raise ValueError("unsupported value type: " + kind.__name__)

    wire = json.dumps(encode(value), ensure_ascii=True, separators=(",", ":"))
    if len(wire) > MAX_BYTES:
        raise ValueError("wire data too large")
    return wire


def loads(wire: str) -> Any:
    if type(wire) is not str or len(wire) > MAX_BYTES or not wire.isascii():
        raise ValueError("wire data must be bounded ASCII JSON")
    tree = json.loads(
        wire,
        parse_int=_reject_number,
        parse_float=_reject_number,
        parse_constant=_reject_number,
    )
    budget = [MAX_NODES]

    def decode(node: Any, depth: int = 0) -> Any:
        budget[0] -= 1
        if depth > MAX_DEPTH or budget[0] < 0:
            raise ValueError("value exceeds structural limits")
        if type(node) is not list or len(node) != 2 or type(node[0]) is not str:
            raise ValueError("invalid tagged value")
        tag, value = node
        if tag in ("list", "tuple", "dict"):
            if type(value) is not list:
                raise ValueError("invalid container")
            if tag == "dict":
                result: dict[Any, Any] = {}
                for pair in value:
                    if type(pair) is not list or len(pair) != 2:
                        raise ValueError("invalid mapping entry")
                    key = decode(pair[0], depth + 1)
                    item = decode(pair[1], depth + 1)
                    if key in result:
                        raise ValueError("duplicate mapping key")
                    result[key] = item
                return result
            items = [decode(x, depth + 1) for x in value]
            return tuple(items) if tag == "tuple" else items
        if type(value) is not str:
            raise ValueError("invalid scalar")
        if tag == "none" and value == "":
            return None
        if tag == "bool" and value in ("true", "false"):
            return value == "true"
        if (
            tag == "int"
            and len(value) <= 4096
            and re.fullmatch(r"-?(0|[1-9][0-9]*)", value)
        ):
            return int(value)
        if tag == "float" and len(value) <= 64:
            return float.fromhex(value)
        if tag == "str":
            return value
        if tag == "bytes":
            return bytes.fromhex(value)
        raise ValueError("invalid scalar tag or value")

    return decode(tree)
