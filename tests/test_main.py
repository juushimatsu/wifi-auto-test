from main import reset_runtime_state


def test_reset_runtime_state_clears_captures_and_database(tmp_path):
    captures = tmp_path / "captures"
    captures.mkdir()
    (captures / "old.pcapng").write_text("capture")
    nested = captures / "nested"
    nested.mkdir()
    (nested / "old.cap").write_text("capture")

    db_path = tmp_path / "wifi_auto_test.db"
    db_path.write_text("db")
    (tmp_path / "wifi_auto_test.db-wal").write_text("wal")
    (tmp_path / "wifi_auto_test.db-shm").write_text("shm")

    reset_runtime_state(str(captures), db_path=str(db_path))

    assert captures.exists()
    assert list(captures.iterdir()) == []
    assert not db_path.exists()
    assert not (tmp_path / "wifi_auto_test.db-wal").exists()
    assert not (tmp_path / "wifi_auto_test.db-shm").exists()
