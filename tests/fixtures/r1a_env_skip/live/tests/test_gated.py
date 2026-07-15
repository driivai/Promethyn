import os
import pytest


@pytest.mark.skipif(not os.environ.get("LIVE_FLAG"), reason="needs LIVE_FLAG")
def test_with_live_flag():
    assert True


@pytest.mark.skipif("CI" not in os.environ, reason="runs only on CI")
def test_platform_provided_ci_var():
    assert True
