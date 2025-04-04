import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional, Tuple, Dict, List

import pytest
from concurrent.futures import ProcessPoolExecutor, as_completed

# --- Код, который тестируем (обычно он импортируется из модуля, но здесь приведён полностью) ---

def parse_log_line(line: str) -> Optional[Tuple[str, str]]:
    """
    Парсит строку лога для модуля django.request и возвращает кортеж (handler, level).
    В логах после 'django.request:' могут встречаться префиксы вроде 'GET' или 'Internal Server Error:'.
    Функция ищет первое вхождение подстроки, начинающейся с '/', и считает её handler (например, "/api/v1/reviews/").
    Если строка не соответствует ожидаемому формату, возвращает None.
    """
    pattern = re.compile(
        r'^(?P<datetime>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})\s+'
        r'(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+'
        r'django\.request:\s+'
        r'(?:.*?)(?P<handler>/\S+)'
    )
    match = pattern.match(line)
    if match:
        handler = match.group('handler')
        level = match.group('level')
        return handler, level
    return None

def process_log_file(path: str) -> Dict[str, Counter]:
    """
    Обрабатывает один файл логов, возвращая статистику по хендлерам и уровням логов.
    """
    local_stats: Dict[str, Counter] = defaultdict(Counter)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed:
                    handler, level = parsed
                    local_stats[handler][level] += 1
    except FileNotFoundError:
        print(f"Файл не найден: {path}", file=sys.stderr)
    except Exception as e:
        print(f"Ошибка при чтении файла {path}: {e}", file=sys.stderr)
    return local_stats

def process_logs(file_paths: List[str]) -> Dict[str, Counter]:
    """
    Обрабатывает список файлов логов параллельно, собирая статистику по handler и уровням логирования.
    """
    stats: Dict[str, Counter] = defaultdict(Counter)
    with ProcessPoolExecutor() as executor:
        futures = {executor.submit(process_log_file, path): path for path in file_paths}
        for future in as_completed(futures):
            local_stats = future.result()
            for handler, counter in local_stats.items():
                stats[handler].update(counter)
    return stats

def print_report_handlers(stats: Dict[str, Counter]) -> None:
    """
    Выводит отчёт в табличном виде:
      - Общее количество обработанных запросов (total requests)
      - Заголовок таблицы с колонками: HANDLER, DEBUG, INFO, WARNING, ERROR, CRITICAL
      - Строки для каждого handler
      - Итоговая строка с суммой по каждому уровню логирования
    """
    total_requests = sum(sum(level_counts.values()) for level_counts in stats.values())
    print(f"Total requests: {total_requests}\n")

    log_levels_order = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

    header_format = "{:<20}" + "".join(["{:>8}" for _ in log_levels_order])
    row_format = "{:<20}" + "".join(["{:>8}" for _ in log_levels_order])

    print(header_format.format("HANDLER", *log_levels_order))

    totals = {lvl: 0 for lvl in log_levels_order}
    for handler in sorted(stats.keys()):
        row_data = []
        for level in log_levels_order:
            count = stats[handler].get(level, 0)
            row_data.append(count)
            totals[level] += count
        print(row_format.format(handler, *row_data))

    print()
    sum_row = [totals[lvl] for lvl in log_levels_order]
    print(row_format.format("", *sum_row))

def print_report_by_level(stats: Dict[str, Counter]) -> None:
    """
    Выводит суммарную статистику по уровням логирования для всех handler.
    """
    level_totals: Counter = Counter()
    for counter in stats.values():
        level_totals.update(counter)
    print("Отчёт по уровням логирования:")
    for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        print(f"{level:>8}: {level_totals.get(level, 0)}")

REPORTS = {
    'handlers': print_report_handlers,
    'by_level': print_report_by_level,
}

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="Анализ логов django.request и формирование отчётов."
    )
    parser.add_argument(
        'log_files',
        nargs='+',
        help='Пути к лог-файлам (например, app1.log app2.log app3.log)'
    )
    parser.add_argument(
        '--report',
        choices=list(REPORTS.keys()),
        default='handlers',
        help=f"Тип отчёта. Доступные варианты: {', '.join(REPORTS.keys())}."
    )
    args = parser.parse_args()
    stats = process_logs(args.log_files)
    REPORTS[args.report](stats)

# Тесты

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
    # Создаем два временных файла с логами
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
    # Передадим искусственную статистику и проверим вывод
    stats = {
        "/api/v1/reviews/": Counter({"ERROR": 2, "INFO": 1}),
        "/api/v1/products/": Counter({"INFO": 3, "WARNING": 1}),
    }
    print_report_handlers(stats)
    captured = capsys.readouterr().out
    # Проверяем наличие заголовка, строк с handler и итоговой строки
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
    # Проверяем, что вывод содержит все уровни логирования
    for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        assert level in captured

def test_main(monkeypatch, tmp_path, capsys):
    # Создаем временный лог-файл
    content = (
        "2025-03-26 12:31:47,000 ERROR django.request: Internal Server Error: /api/v1/reviews/ [192.168.1.36] - ValueError: Invalid input data\n"
        "2025-03-26 12:36:02,000 INFO django.request: GET /api/v1/products/ 204 OK [192.168.1.46]\n"
    )
    file = tmp_path / "main_temp.log"
    file.write_text(content, encoding="utf-8")
    # Подменяем аргументы командной строки
    monkeypatch.setattr(sys, "argv", ["main.py", str(file), "--report", "by_level"])
    # Вызываем main
    main()
    captured = capsys.readouterr().out
    # Проверяем, что в выводе присутствует отчёт по уровням
    assert "Отчёт по уровням логирования:" in captured
