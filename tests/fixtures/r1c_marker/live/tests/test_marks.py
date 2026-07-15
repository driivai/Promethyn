import pytest


@pytest.mark.slow
def test_slow_path():
    assert True


@pytest.mark.unit
def test_unit_path():
    assert True
