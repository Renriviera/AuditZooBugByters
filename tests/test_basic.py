"""Basic smoke tests for AuditZoo.

These tests ensure the package is properly installed and importable.
"""


def test_import_auditzoo():
    """Test that auditzoo package can be imported."""
    import auditzoo

    assert auditzoo is not None
