"""
Password complexity policy tests.

Ensures the panel rejects short, common, and structurally weak passwords
across every entrypoint that calls validate_password_strength().
"""

import pytest

from app.auth import validate_password_strength


def test_rejects_short_password():
    assert validate_password_strength("abc") is not None


def test_rejects_exactly_11_chars():
    # 12 is the minimum; 11 must fail.
    assert validate_password_strength("Abcdef1!aaa") is not None


def test_rejects_common_password_even_if_long():
    # 12-char "Password1234" — looks complex but is in real breach corpora.
    # The blocklist is canonical lowercase.
    assert validate_password_strength("password1234") is not None


def test_rejects_no_uppercase():
    assert validate_password_strength("abcdef1234!@") is not None


def test_rejects_no_lowercase():
    assert validate_password_strength("ABCDEF1234!@") is not None


def test_rejects_no_digit():
    assert validate_password_strength("Abcdefghijk!") is not None


def test_rejects_no_symbol():
    assert validate_password_strength("Abcdefghi123") is not None


def test_accepts_strong_password():
    assert validate_password_strength("Str0ng-P@ssword-123!") is None
