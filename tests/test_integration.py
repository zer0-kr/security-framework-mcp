from __future__ import annotations

import subprocess
import sys

import pytest


def test_comprehensive_integration():
    result = subprocess.run(
        [sys.executable, "tests/test_comprehensive.py"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert "0 failed" in result.stdout, f"Integration tests failed:\n{result.stdout[-500:]}"
    assert result.returncode == 0
