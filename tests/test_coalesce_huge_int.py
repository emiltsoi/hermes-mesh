"""A JSON row whose integer literal exceeds the interpreter's digit limit must not break the scan.

On Python >= 3.11 json.loads raises a plain ValueError (int-to-str limit) rather than JSONDecodeError,
so a guard on JSONDecodeError alone let one row abort pending() for the whole peer.
"""
import json
import sys

from hermes_mesh.coalesce import Coalescer


def test_pending_survives_a_row_with_an_oversized_integer(tmp_path):
    c = Coalescer(str(tmp_path))
    good = {"received_at": 1.0, "sender": "kore", "body": "hello"}
    huge = '{"received_at": ' + "9" * 5000 + ', "sender": "kore", "body": "boom"}'
    with open(c._path("kore"), "w", encoding="utf-8") as fh:
        fh.write(huge + "\n")
        fh.write(json.dumps(good) + "\n")

    items = c.pending("kore")          # must not raise

    if hasattr(sys, "get_int_max_str_digits") and sys.get_int_max_str_digits():
        assert [i["body"] for i in items] == ["hello"]
    else:
        assert len(items) == 2
