#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скрипт мониторинга доступности сайтов.

Что делает:
  - читает список сайтов и настройки из config.yaml;
  - для каждого сайта делает HTTP-проверку (с повторами при ошибке,
    чтобы не поднимать тревогу из-за случайного разового сбоя);
  - проверяет HTTP-код, время ответа, наличие контрольного текста
    и срок действия SSL-сертификата;
  - хранит текущее состояние (UP/DOWN) каждого сайта в state.json —
    это и есть "память" между запусками, так как сам GitHub Actions
    ничего между запусками не помнит, а файл коммитится обратно в репозиторий;
  - при смене состояния UP -> DOWN и DOWN -> UP шлёт сообщение в Telegram;
  - если состояние не изменилось (сайт всё ещё лежит) — уведомление
    повторно НЕ отправляется, чтобы не спамить;
  - дописывает каждую проверку в history.csv для истории/статистики.

Скрипт запускается по расписанию через GitHub Actions (см. .github/workflows/monitor.yml).
"""

import csv
import json
import os
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import yaml

try:
    from zoneinfo import ZoneInfo  # доступно в стандартной библиотеке с Python 3.9
except ImportError:  # на всякий случай, если запускают на очень старом Python
    ZoneInfo = None

# ---------------------------------------------------------------
# Пути к файлам (все — рядом со скриптом, в корне репозитория)
# ---------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.yaml")
STATE_FILE = os.path.join(BASE_DIR, "state.json")
HISTORY_FILE = os.path.join(BASE_DIR, "history.csv")

HISTORY_HEADER = [
    "datetime",       # дата и время проверки (локальный часовой пояс из конфига)
    "site",           # имя сайта
    "status",         # UP или DOWN (итог после повторных проверок)
    "http_code",      # HTTP-код ответа (может быть пустым при timeout/DNS-ошибке)
    "response_time_sec",  # время ответа в секундах
    "error_type",     # тип ошибки (пусто, если всё ок)
]

# Секреты Telegram берутся ТОЛЬКО из переменных окружения (GitHub Secrets),
# в коде и конфиге их быть не должно.
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# Человекочитаемые описания типов ошибок для сообщений в Telegram
ERROR_DESCRIPTIONS = {
    "timeout": "превышено время ожидания ответа (timeout)",
    "dns_error": "ошибка DNS (не удалось определить адрес сайта)",
    "connection_error": "ошибка соединения (сайт не отвечает)",
    "ssl_error": "ошибка SSL-сертификата",
    "content_missing": "контрольный текст не найден на странице",
}


# =================================================================
# Работа с файлами: конфиг, состояние, история
# =================================================================

def load_config():
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_state():
    """Загружает состояние прошлых проверок. Если файла ещё нет — вернёт пустой словарь."""
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            # если файл вдруг битый - не падаем, начинаем состояние заново
            return {}


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")


def append_history(rows, max_rows):
    """Дописывает строки в history.csv и обрезает файл, если он стал слишком большим."""
    file_exists = os.path.exists(HISTORY_FILE)
    with open(HISTORY_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(HISTORY_HEADER)
        writer.writerows(rows)
    _trim_history(max_rows)


def _trim_history(max_rows):
    if not max_rows:
        return
    with open(HISTORY_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    if len(lines) <= max_rows + 1:  # +1 - это строка заголовка
        return
    header = lines[0]
    data = lines[-max_rows:]
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        f.writelines([header] + data)


# =================================================================
# Telegram
# =================================================================

def send_telegram(text, thread_id=None):
    """
    Отправляет сообщение в Telegram. Если секреты не заданы — просто печатает в лог.
    thread_id — id конкретной темы (Topic) внутри группы, если в группе включены темы
    и нужно писать в конкретную тему, а не в "Общую". Берётся из config.yaml
    (telegram_message_thread_id).
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("ВНИМАНИЕ: TELEGRAM_BOT_TOKEN или TELEGRAM_CHAT_ID не заданы. "
              "Сообщение не отправлено, вывожу его здесь:")
        print(text)
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": text}
    if thread_id:
        data["message_thread_id"] = thread_id
    try:
        resp = requests.post(url, data=data, timeout=15)
        if resp.status_code != 200:
            print(f"Ошибка отправки в Telegram: HTTP {resp.status_code} {resp.text}")
    except requests.RequestException as e:
        print(f"Не удалось отправить сообщение в Telegram: {e}")


# =================================================================
# Проверка SSL-сертификата
# =================================================================

def get_ssl_days_left(hostname, port=443, timeout=10):
    """
    Подключается к сайту по TLS и смотрит срок действия сертификата.
    Возвращает количество дней до истечения, либо None если проверить не удалось
    (например, сам HTTPS недоступен - это будет видно и по основной проверке).
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        if not not_after:
            return None
        expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        expire_date = expire_date.replace(tzinfo=timezone.utc)
        days_left = (expire_date - datetime.now(timezone.utc)).days
        return days_left
    except Exception:
        return None


# =================================================================
# Основная HTTP-проверка одного сайта
# =================================================================

def classify_connection_error(exc):
    """Определяет тип ошибки соединения по тексту исключения requests."""
    if isinstance(exc, requests.exceptions.SSLError):
        return "ssl_error"
    if isinstance(exc, requests.exceptions.ConnectionError):
        msg = str(exc).lower()
        dns_markers = (
            "name or service not known",   # Linux
            "nodename nor servname",       # macOS
            "getaddrinfo failed",          # Windows / общее
            "temporary failure in name resolution",
        )
        if any(marker in msg for marker in dns_markers):
            return "dns_error"
        return "connection_error"
    return "connection_error"


def check_once(site, cfg):
    """
    Выполняет ОДНУ попытку проверки сайта.
    Возвращает dict: ok (bool), http_code, response_time (сек), error_type.
    """
    url = site["url"]
    check_text = (site.get("check_text") or "").strip()
    timeout = cfg.get("request_timeout_seconds", 10)
    slow_threshold = cfg.get("slow_response_seconds", 5)

    result = {"ok": False, "http_code": None, "response_time": None, "error_type": None}

    start = time.monotonic()
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "SiteMonitorBot/1.0"})
        elapsed = round(time.monotonic() - start, 2)
        result["response_time"] = elapsed
        result["http_code"] = resp.status_code

        # 1. Проверяем HTTP-код: всё, что не 200-399, считаем потенциальной ошибкой
        if not (200 <= resp.status_code < 400):
            if 400 <= resp.status_code < 500:
                result["error_type"] = "http_4xx"
            else:
                result["error_type"] = "http_5xx"
            return result

        # 2. Проверяем наличие контрольного текста (ловим "200 OK, но на самом деле ошибка")
        if check_text and check_text not in resp.text:
            result["error_type"] = "content_missing"
            return result

        # 3. Проверяем скорость ответа
        if elapsed > slow_threshold:
            result["error_type"] = "slow_response"
            return result

        result["ok"] = True
        return result

    except requests.exceptions.Timeout:
        result["response_time"] = round(time.monotonic() - start, 2)
        result["error_type"] = "timeout"
        return result
    except requests.exceptions.RequestException as e:
        result["response_time"] = round(time.monotonic() - start, 2)
        result["error_type"] = classify_connection_error(e)
        return result


def check_site_with_retries(site, cfg):
    """
    Делает первую проверку и, если она неудачна, ещё несколько повторных
    попыток с небольшим интервалом — чтобы не бить тревогу из-за случайного
    разового сбоя (сетевая рябь, кратковременный таймаут и т.п.).

    Если хотя бы одна из попыток успешна - считаем сайт рабочим.
    Если все попытки неудачны - возвращаем результат последней попытки
    и общее число сделанных попыток.
    """
    retry_count = max(1, int(cfg.get("retry_count", 3)))
    retry_interval = cfg.get("retry_interval_seconds", 15)

    result = check_once(site, cfg)
    attempts = 1
    if result["ok"]:
        return result, attempts

    for _ in range(retry_count - 1):
        time.sleep(retry_interval)
        attempts += 1
        result = check_once(site, cfg)
        if result["ok"]:
            return result, attempts

    return result, attempts


# =================================================================
# Формирование текстов сообщений
# =================================================================

def now_local(cfg):
    tz_name = cfg.get("timezone", "UTC")
    if ZoneInfo is not None:
        try:
            return datetime.now(ZoneInfo(tz_name))
        except Exception:
            pass
    return datetime.now(timezone.utc)


def describe_error(result):
    et = result["error_type"]
    if et in ("http_4xx", "http_5xx"):
        return f"HTTP {result['http_code']}"
    if et == "slow_response":
        return f"слишком медленный ответ ({result['response_time']} сек)"
    return ERROR_DESCRIPTIONS.get(et, et or "неизвестная ошибка")


def build_down_message(site, result, attempts, cfg):
    lines = [
        f"🔴 {site['name']} недоступен",
        f"Время: {now_local(cfg).strftime('%d.%m.%Y %H:%M')}",
        f"URL: {site['url']}",
        f"Ошибка: {describe_error(result)}",
    ]
    if result["response_time"] is not None:
        lines.append(f"Время ответа: {result['response_time']} сек")
    lines.append(f"Повторных проверок: {attempts}")
    return "\n".join(lines)


def build_up_message(site, result, down_since_iso, cfg):
    down_since = datetime.fromisoformat(down_since_iso)
    duration_min = max(0, int((datetime.now(timezone.utc) - down_since).total_seconds() // 60))
    lines = [
        f"🟢 {site['name']} снова работает",
        f"Недоступность длилась: {duration_min} мин.",
        f"HTTP: {result['http_code']}",
    ]
    if result["response_time"] is not None:
        lines.append(f"Время ответа: {result['response_time']} сек")
    return "\n".join(lines)


# =================================================================
# Основной цикл
# =================================================================

def default_site_state():
    return {
        "status": "UNKNOWN",   # UNKNOWN | UP | DOWN
        "down_since": None,    # ISO-время (UTC), когда сайт упал
        "notified_down": False,  # уже отправляли уведомление о падении для текущего инцидента?
        "ssl_warned": False,   # уже отправляли предупреждение о скором истечении SSL?
    }


def main():
    cfg = load_config()
    state = load_state()
    history_rows = []
    thread_id = cfg.get("telegram_message_thread_id")

    for site in cfg["sites"]:
        name = site["name"]
        url = site["url"]
        site_state = {**default_site_state(), **state.get(name, {})}

        result, attempts = check_site_with_retries(site, cfg)

        history_rows.append([
            now_local(cfg).strftime("%Y-%m-%d %H:%M:%S"),
            name,
            "UP" if result["ok"] else "DOWN",
            result["http_code"] if result["http_code"] is not None else "",
            result["response_time"] if result["response_time"] is not None else "",
            result["error_type"] or "",
        ])

        if result["ok"]:
            # Сайт отвечает нормально
            if site_state["status"] == "DOWN" and site_state["notified_down"]:
                # Было подтверждённое падение - шлём отдельное сообщение о восстановлении
                send_telegram(build_up_message(site, result, site_state["down_since"], cfg), thread_id)
            site_state["status"] = "UP"
            site_state["down_since"] = None
            site_state["notified_down"] = False
        else:
            # Сайт не отвечает нормально (после всех повторных попыток)
            if site_state["status"] != "DOWN":
                site_state["down_since"] = datetime.now(timezone.utc).isoformat()
            if not site_state["notified_down"]:
                send_telegram(build_down_message(site, result, attempts, cfg), thread_id)
                site_state["notified_down"] = True
            # если notified_down уже True - значит, уведомление уже уходило
            # для этого инцидента, повторно не спамим
            site_state["status"] = "DOWN"

        # Проверка SSL-сертификата (независимо от основного статуса, только для https)
        if url.startswith("https://"):
            hostname = urlparse(url).hostname
            days_left = get_ssl_days_left(hostname)
            warning_days = cfg.get("ssl_expiry_warning_days", 14)
            if days_left is not None:
                if days_left < warning_days:
                    if not site_state["ssl_warned"]:
                        send_telegram(
                            f"⚠️ {name}: SSL-сертификат истекает через {days_left} дн.\n"
                            f"URL: {url}",
                            thread_id,
                        )
                        site_state["ssl_warned"] = True
                else:
                    # сертификат обновили / срок нормальный - сбрасываем флаг,
                    # чтобы при следующем приближении срока предупреждение снова пришло
                    site_state["ssl_warned"] = False

        state[name] = site_state

    append_history(history_rows, cfg.get("max_history_rows", 20000))
    save_state(state)


if __name__ == "__main__":
    main()
