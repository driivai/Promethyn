import os
import pytest

_REQUIRE_HW = (os.environ.get("NEVER_SET_FLAG", "") or "").lower() in {"1", "true"}


def _real_hardware():
    if not _REQUIRE_HW:
        pytest.skip("hardware run is opt-in; set NEVER_SET_FLAG=1")


def test_on_real_hardware():
    _real_hardware()
    assert True


@pytest.mark.skipif(not os.environ.get("DOC_ONLY_FLAG"), reason="needs DOC_ONLY_FLAG")
def test_documented_manual_path():
    assert True
