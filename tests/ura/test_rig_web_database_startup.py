import sqlite3

from experiments.rig_web_app import server
from experiments.rig_web_app.storage import ConsoleDB


def test_database_startup_does_not_scan_all_pages(tmp_path, monkeypatch):
    statements = []
    connect = sqlite3.connect

    def observed(*args, **kwargs):
        connection = connect(*args, **kwargs)
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(sqlite3, "connect", observed)
    database = ConsoleDB(tmp_path / "console.db")
    assert database.healthy
    database.close()
    assert not any("quick_check" in sql.lower() or "integrity_check" in sql.lower()
                   for sql in statements)


def test_database_scan_is_explicit_and_does_not_start_the_app(tmp_path, monkeypatch, capsys):
    database = ConsoleDB(tmp_path / "console.db")
    database.close()

    def forbidden(**kwargs):
        raise AssertionError("Maintenance must not start jobs or the web server")

    monkeypatch.setattr(server, "RigWebApp", forbidden)
    assert server.main(["--state-dir", str(tmp_path), "--check-database"]) == 0
    assert '"status": "ok"' in capsys.readouterr().out


def test_explicit_database_scan_reports_corruption(tmp_path, capsys):
    (tmp_path / "console.db").write_bytes(b"not a database")
    assert server.main(["--state-dir", str(tmp_path), "--check-database"]) == 1
    assert '"status": "failed"' in capsys.readouterr().out
    database = ConsoleDB(tmp_path / "console.db")
    assert not database.healthy
    assert database.load_jobs() is None
