import pytest

from extract import chrome_epoch_to_iso, unix_to_iso
import analyzer


def test_chrome_epoch_to_iso_returns_string():
    # 0 should return empty string safely
    assert isinstance(chrome_epoch_to_iso(0), str)


def test_unix_to_iso_valid():
    s = unix_to_iso(0)
    assert isinstance(s, str)


def test_analyzer_run_callable():
    assert callable(analyzer.run)
