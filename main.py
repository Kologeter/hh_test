import argparse
import re
import sys
from collections import defaultdict, Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Optional, Tuple, Dict, List

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
    Обрабатывает один файл логов, возвращая статистику по handler и уровням логирования.
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
    Доп задание сделать обработку параллеьно.
    Здесь это супер неэффективно ахахахахах, как и малтифрединг
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

    # Формат: HANDLER - шириной 20 символов, остальные колонки по 8 символов, выравнивание по правому краю.
    header_format = "{:<20}" + "".join(["{:>8}" for _ in log_levels_order])
    row_format = "{:<20}" + "".join(["{:>8}" for _ in log_levels_order])

    # Заголовок
    print(header_format.format("HANDLER", *log_levels_order))

    totals = {lvl: 0 for lvl in log_levels_order}
    for handler in sorted(stats.keys()):
        row_data = []
        for level in log_levels_order:
            count = stats[handler].get(level, 0)
            row_data.append(count)
            totals[level] += count
        print(row_format.format(handler, *row_data))

    # Итоговая строка
    print()
    sum_row = [totals[lvl] for lvl in log_levels_order]
    print(row_format.format("", *sum_row))

# Пример дополнительного отчёта: суммарная статистика по уровням логирования (без разбивки по handler)
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

# Словарь отчетов. Для добавления нового отчёта достаточно написать новую функцию и добавить ее сюда.
REPORTS = {
    'handlers': print_report_handlers,
    'by_level': print_report_by_level,
}

def main() -> None:
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

if __name__ == "__main__":
    main()
