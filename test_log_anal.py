from pathlib import Path
import pytest
from main import *


def test_parse_log_line_valid():
    line = ("2025-03-26 12:31:47,000 ERROR django.request: Internal Server Error: "
            "/api/v1/reviews/ [192.168.1.36] - ValueError: Invalid input data")
    result = parse_log_line(line)
    assert result == ("/api/v1/reviews/", "ERROR")

def test_parse_log_line_invalid():
    # относится к бд, поэтому None.
    line = "2025-03-26 12:31:47,000 ERROR django.db.backends: SELECT * FROM table;"
    result = parse_log_line(line)
    assert result is None

@pytest.fixture
def temp_log_file(tmp_path: Path) -> Path:
    content = (
        "2025-03-26 12:31:47,000 ERROR django.request: Internal Server Error: /api/v1/reviews/ [192.168.1.36] - ValueError: Invalid input data\n"
        "2025-03-26 12:36:02,000 INFO django.request: GET /api/v1/products/ 204 OK [192.168.1.46]\n"
        "2025-03-26 12:33:06,000 INFO django.request: GET /admin/dashboard/ 201 OK [192.168.1.21]\n"
        "2025-03-26 12:28:26,000 INFO django.request: GET /api/v1/auth/login/ 200 OK [192.168.1.58]\n"
        "2025-03-26 12:31:47,000 ERROR django.db.backends: SELECT * FROM table;\n"
    )
    file = tmp_path / "temp.log"
    file.write_text(content, encoding="utf-8")
    return file

def test_process_log_file(temp_log_file: Path):
    stats = process_log_file(str(temp_log_file))
    expected = {
        "/api/v1/reviews/": Counter({"ERROR": 1}),
        "/api/v1/products/": Counter({"INFO": 1}),
        "/admin/dashboard/": Counter({"INFO": 1}),
        "/api/v1/auth/login/": Counter({"INFO": 1}),
    }
    assert stats == expected

def test_process_logs(tmp_path: Path):
    content1 = (
        "2025-03-26 12:31:47,000 ERROR django.request: Internal Server Error: /api/v1/reviews/ [192.168.1.36] - ValueError: Invalid input data\n"
        "2025-03-26 12:36:02,000 INFO django.request: GET /api/v1/products/ 204 OK [192.168.1.46]\n"
    )
    content2 = (
        "2025-03-26 12:33:06,000 INFO django.request: GET /admin/dashboard/ 201 OK [192.168.1.21]\n"
        "2025-03-26 12:28:26,000 INFO django.request: GET /api/v1/auth/login/ 200 OK [192.168.1.58]\n"
    )
    file1 = tmp_path / "file1.log"
    file2 = tmp_path / "file2.log"
    file1.write_text(content1, encoding="utf-8")
    file2.write_text(content2, encoding="utf-8")
    stats = process_logs([str(file1), str(file2)])
    expected = {
        "/api/v1/reviews/": Counter({"ERROR": 1}),
        "/api/v1/products/": Counter({"INFO": 1}),
        "/admin/dashboard/": Counter({"INFO": 1}),
        "/api/v1/auth/login/": Counter({"INFO": 1}),
    }
    assert stats == expected

def test_print_report_handlers(capsys):
    stats = {
        "/api/v1/reviews/": Counter({"ERROR": 2, "INFO": 1}),
        "/api/v1/products/": Counter({"INFO": 3, "WARNING": 1}),
    }
    print_report_handlers(stats)
    captured = capsys.readouterr().out
    assert "HANDLER" in captured
    assert "/api/v1/reviews/" in captured
    assert "/api/v1/products/" in captured
    assert "Total requests:" in captured

def test_print_report_by_level(capsys):
    stats = {
        "/api/v1/reviews/": Counter({"ERROR": 2, "INFO": 1}),
        "/api/v1/products/": Counter({"INFO": 3, "WARNING": 1}),
    }
    print_report_by_level(stats)
    captured = capsys.readouterr().out
    for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        assert level in captured

def test_main(monkeypatch, tmp_path, capsys):
    content = (
        "2025-03-26 12:31:47,000 ERROR django.request: Internal Server Error: /api/v1/reviews/ [192.168.1.36] - ValueError: Invalid input data\n"
        "2025-03-26 12:36:02,000 INFO django.request: GET /api/v1/products/ 204 OK [192.168.1.46]\n"
    )
    file = tmp_path / "main_temp.log"
    file.write_text(content, encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["main.py", str(file), "--report", "by_level"])
    main()
    captured = capsys.readouterr().out
    assert "Отчёт по уровням логирования:" in captured
