#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Port Scanner – учебный инструмент для сканирования TCP-портов (TCP Connect).
Сохраняет историю сканирований в JSON-файл. Поддерживает сортировку таблиц,
экспорт результатов в CSV/JSON, цветовую подсветку состояния портов,
контекстное меню для копирования/вставки в поля ввода.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import queue
import json
import os
import socket
import sqlite3
import time
import urllib.request
from datetime import datetime
import ipaddress


# ==============================================================================
# Вспомогательные функции
# ==============================================================================
def parse_targets(target_str: str):
    """Разбирает строку в список IP-адресов (одиночные адреса и подсети)."""
    targets = []
    for part in target_str.replace(',', ' ').split():
        part = part.strip()
        if not part:
            continue
        try:
            network = ipaddress.IPv4Network(part, strict=False)
            targets.extend([str(host) for host in network.hosts()])
        except ValueError:
            try:
                ip = ipaddress.IPv4Address(part)
                targets.append(str(ip))
            except ValueError:
                raise ValueError(f"Некорректный адрес или сеть: {part}")
    return targets


def parse_ports(port_str: str):
    """Разбирает список портов вида 80,443,1000-1010 в валидированный список."""
    ports = []
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue

        if '-' in part:
            try:
                start, end = map(int, part.split('-', 1))
            except ValueError:
                raise ValueError(f"Некорректный диапазон портов: {part}")
            if start > end:
                raise ValueError(f"Начало диапазона больше конца: {part}")
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError(f"Порты должны быть в диапазоне 1-65535: {part}")
            ports.extend(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError:
                raise ValueError(f"Некорректный порт: {part}")
            if not (1 <= port <= 65535):
                raise ValueError(f"Порт вне диапазона 1-65535: {port}")
            ports.append(port)
    return ports


# ==============================================================================
# Рабочий поток сканирования (только TCP Connect)
# ==============================================================================
class ScannerWorker(threading.Thread):
    """Фоновый поток, выполняющий перебор портов."""

    def __init__(self, targets, ports, timeout, result_queue):
        super().__init__(daemon=True)
        self.targets = targets
        self.ports = ports
        self.timeout = timeout
        self.result_queue = result_queue
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        total = len(self.targets) * len(self.ports)
        current = 0
        for ip in self.targets:
            if self._stop_event.is_set():
                break
            for port in self.ports:
                if self._stop_event.is_set():
                    break
                current += 1
                state = self._tcp_connect(ip, port)
                self.result_queue.put(('result', ip, port, state, current, total))
        self.result_queue.put(('finished', None, None, None, total))

    def _tcp_connect(self, ip, port):
        """TCP Connect сканирование с различением closed/filtered."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return 'open'
            if result == 10061 or result == 111:
                return 'closed'
            return 'filtered'
        except socket.timeout:
            return 'filtered'
        except socket.gaierror:
            return 'invalid host'
        except Exception as e:
            return f'error: {e}'


# ==============================================================================
# Хранилище истории
# ==============================================================================
class ScanHistoryManager:
    """Управление историей сканирований (чтение/запись JSON-файла)."""

    def __init__(self, filename='scan_history.json'):
        self.filename = filename
        self.entries = []
        self.load()

    def load(self):
        if os.path.exists(self.filename):
            try:
                with open(self.filename, 'r', encoding='utf-8') as f:
                    self.entries = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                self.entries = []
        else:
            self.entries = []

    def save(self):
        with open(self.filename, 'w', encoding='utf-8') as f:
            json.dump(self.entries, f, ensure_ascii=False, indent=2)

    def add_entry(self, target_input, port_input, results):
        entry = {
            'id': len(self.entries) + 1,
            'datetime': datetime.now().isoformat(),
            'target': target_input,
            'ports': port_input,
            'scan_type': 'connect',
            'results': results
        }
        self.entries.append(entry)
        self.save()

    def delete_entry(self, index):
        if 0 <= index < len(self.entries):
            del self.entries[index]
            self.save()
            return True
        return False


class RequestHistoryManager:
    """Хранение истории сетевых запросов в SQLite."""

    def __init__(self, filename='request_history.db'):
        self.filename = filename
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.filename) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS request_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    request_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    payload TEXT,
                    status TEXT NOT NULL,
                    response_time_ms INTEGER,
                    response_preview TEXT
                )
            """)
            conn.commit()

    def add_entry(self, request_type, target, payload, status, response_time_ms, response_preview):
        with sqlite3.connect(self.filename) as conn:
            conn.execute("""
                INSERT INTO request_history (
                    created_at, request_type, target, payload, status, response_time_ms, response_preview
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(timespec='seconds'),
                request_type,
                target,
                payload,
                status,
                response_time_ms,
                response_preview
            ))
            conn.commit()

    def list_entries(self):
        with sqlite3.connect(self.filename) as conn:
            cursor = conn.execute("""
                SELECT id, created_at, request_type, target, payload, status, response_time_ms, response_preview
                FROM request_history
                ORDER BY id DESC
            """)
            rows = cursor.fetchall()
        return rows

    def clear(self):
        with sqlite3.connect(self.filename) as conn:
            conn.execute("DELETE FROM request_history")
            conn.commit()


class RequestWorker(threading.Thread):
    """Фоновый поток для выполнения одиночного сетевого запроса."""

    def __init__(self, request_type, target, payload, result_queue):
        super().__init__(daemon=True)
        self.request_type = request_type
        self.target = target
        self.payload = payload
        self.result_queue = result_queue

    def run(self):
        started = time.perf_counter()
        status, preview = self._execute()
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        self.result_queue.put(('request_finished', self.request_type, self.target, self.payload, status, elapsed_ms, preview))

    def _execute(self):
        try:
            if self.request_type == "DNS":
                host, aliases, ips = socket.gethostbyname_ex(self.target.strip())
                preview = f"host={host}; aliases={aliases}; ips={ips}"
                return "ok", preview

            if self.request_type == "HTTP":
                url = self.target.strip()
                if not (url.startswith("http://") or url.startswith("https://")):
                    url = "http://" + url
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=4) as resp:
                    body = resp.read(180).decode("utf-8", errors="replace").strip().replace("\n", " ")
                    preview = f"HTTP {resp.status}; {body[:150]}"
                    return "ok", preview

            if self.request_type == "TCP":
                host = self.target.strip()
                port = int(self.payload.strip() or "80")
                with socket.create_connection((host, port), timeout=3):
                    return "ok", f"TCP connect success to {host}:{port}"

            return "error", "Неизвестный тип запроса"
        except Exception as e:
            return "error", str(e)


# ==============================================================================
# Графический интерфейс пользователя
# ==============================================================================
class PortScannerApp:
    """Главное окно приложения."""

    MAX_TARGETS = 256
    MAX_PORTS   = 1024

    def __init__(self, root):
        self.root = root
        self.root.title("Анализатор сети")
        self.root.geometry("950x650")
        self.root.resizable(True, True)
        self.root.configure(bg='#d3d3d3')
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Стили
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("TFrame", background='#d3d3d3')
        self.style.configure("TLabel", background='#d3d3d3', font=("Segoe UI", 10))
        self.style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=6)
        self.style.configure("Treeview.Heading", font=("Segoe UI", 11, "bold"))
        self.style.configure("Treeview", font=("Segoe UI", 10), rowheight=25)
        self.style.map("TButton", background=[("active", "#b0b0b0")])

        # История
        self.history_manager = ScanHistoryManager()
        self.request_history_manager = RequestHistoryManager()

        # Переменные сканирования
        self.current_results = []
        self.scanner_thread = None
        self.result_queue = queue.Queue()
        self.scan_in_progress = False
        self.request_in_progress = False
        self.request_thread = None
        self.request_queue = queue.Queue()

        self.create_widgets()
        self.refresh_history_list()
        self.refresh_request_history()
        self.poll_queue()
        self.poll_request_queue()

    # --------------------------------------------------------------------------
    def create_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # ======================== Вкладка Сканирование ========================
        self.scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_frame, text="Сканирование")

        # Универсальные поля ввода с контекстным меню
        entry_kwargs = {
            'width': 60,
            'bg': '#ffffff',
            'font': ("Segoe UI", 10),
            'relief': tk.SUNKEN,
            'borderwidth': 1
        }

        # Цели
        ttk.Label(self.scan_frame, text="Цель (IP, подсеть):").grid(
            row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.target_entry = tk.Entry(self.scan_frame, **entry_kwargs)
        self.target_entry.insert(0, "88.218.121.98")
        self.target_entry.grid(row=0, column=1, columnspan=3, padx=5, pady=5, sticky=tk.W)
        self._add_context_menu_to_entry(self.target_entry)

        # Порты
        ttk.Label(self.scan_frame, text="Порты (напр. 22,80-443):").grid(
            row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.port_entry = tk.Entry(self.scan_frame, **entry_kwargs)
        self.port_entry.insert(0, "22,80,443")
        self.port_entry.grid(row=1, column=1, columnspan=3, padx=5, pady=5, sticky=tk.W)
        self._add_context_menu_to_entry(self.port_entry)

        # Кнопки управления
        btn_frame = ttk.Frame(self.scan_frame)
        btn_frame.grid(row=2, column=0, columnspan=4, pady=10, sticky=tk.W)

        self.start_btn = ttk.Button(btn_frame, text="▶ Сканировать", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(btn_frame, text="⏹ Остановить", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.export_csv_btn = ttk.Button(btn_frame, text="📥 CSV", command=self.export_current_csv)
        self.export_csv_btn.pack(side=tk.LEFT, padx=5)
        self.export_json_btn = ttk.Button(btn_frame, text="📥 JSON", command=self.export_current_json)
        self.export_json_btn.pack(side=tk.LEFT, padx=5)

        # Прогресс
        self.progress_var = tk.IntVar()
        self.progress = ttk.Progressbar(self.scan_frame, variable=self.progress_var, maximum=100)
        self.progress.grid(row=3, column=0, columnspan=4, sticky=tk.EW, padx=5, pady=5)

        # Таблица результатов
        table_frame = ttk.Frame(self.scan_frame)
        table_frame.grid(row=4, column=0, columnspan=4, sticky=tk.NSEW, padx=5, pady=5)
        self.scan_frame.rowconfigure(4, weight=1)
        self.scan_frame.columnconfigure(3, weight=1)

        self.scan_tree = self._create_result_table(table_frame)

        # ======================== Вкладка История =============================
        self.history_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.history_frame, text="История")

        # Левая панель
        hist_left = ttk.Frame(self.history_frame)
        hist_left.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

        ttk.Label(hist_left, text="История сканирований:").pack(anchor=tk.W)
        self.history_listbox = tk.Listbox(hist_left, width=45, height=20)
        self.history_listbox.pack(fill=tk.Y, expand=True)
        self.history_listbox.bind('<<ListboxSelect>>', self.on_history_select)
        self.history_listbox.bind('<Button-3>', self.show_history_context_menu)

        self.del_hist_btn = ttk.Button(hist_left, text="🗑 Удалить запись", command=self.delete_history_entry)
        self.del_hist_btn.pack(pady=(5, 0))

        # Правая панель
        hist_right = ttk.Frame(self.history_frame)
        hist_right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.hist_tree = self._create_result_table(hist_right)

        # ======================== Вкладка Запросы ============================
        self.request_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.request_frame, text="Запросы")

        ttk.Label(self.request_frame, text="Тип запроса:").grid(
            row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.request_type = tk.StringVar(value="DNS")
        self.request_type_box = ttk.Combobox(
            self.request_frame,
            textvariable=self.request_type,
            values=("DNS", "HTTP", "TCP"),
            state="readonly",
            width=10
        )
        self.request_type_box.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(self.request_frame, text="Цель (host/url):").grid(
            row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.request_target_entry = tk.Entry(self.request_frame, **entry_kwargs)
        self.request_target_entry.insert(0, "example.com")
        self.request_target_entry.grid(row=1, column=1, columnspan=3, sticky=tk.W, padx=5, pady=5)
        self._add_context_menu_to_entry(self.request_target_entry)

        ttk.Label(self.request_frame, text="Параметр (для TCP: порт):").grid(
            row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.request_payload_entry = tk.Entry(self.request_frame, **entry_kwargs)
        self.request_payload_entry.insert(0, "80")
        self.request_payload_entry.grid(row=2, column=1, columnspan=3, sticky=tk.W, padx=5, pady=5)
        self._add_context_menu_to_entry(self.request_payload_entry)

        req_btn_frame = ttk.Frame(self.request_frame)
        req_btn_frame.grid(row=3, column=0, columnspan=4, sticky=tk.W, padx=5, pady=8)

        self.request_btn = ttk.Button(req_btn_frame, text="▶ Выполнить запрос", command=self.start_request)
        self.request_btn.pack(side=tk.LEFT, padx=5)

        self.clear_request_history_btn = ttk.Button(
            req_btn_frame, text="🧹 Очистить историю запросов", command=self.clear_request_history
        )
        self.clear_request_history_btn.pack(side=tk.LEFT, padx=5)

        self.export_request_history_btn = ttk.Button(
            req_btn_frame, text="📤 Экспорт истории запросов", command=self.export_request_history
        )
        self.export_request_history_btn.pack(side=tk.LEFT, padx=5)

        self.request_status_var = tk.StringVar(value="Ожидание запроса...")
        ttk.Label(self.request_frame, textvariable=self.request_status_var).grid(
            row=4, column=0, columnspan=4, sticky=tk.W, padx=5, pady=5)

        request_columns = ("created_at", "type", "target", "status", "time", "preview")
        self.request_history_tree = ttk.Treeview(
            self.request_frame, columns=request_columns, show="headings", height=14
        )
        headings = {
            "created_at": "Время",
            "type": "Тип",
            "target": "Цель",
            "status": "Статус",
            "time": "Время, мс",
            "preview": "Ответ"
        }
        for c in request_columns:
            self.request_history_tree.heading(c, text=headings[c])
        self.request_history_tree.column("created_at", width=145, anchor="center")
        self.request_history_tree.column("type", width=70, anchor="center")
        self.request_history_tree.column("target", width=180, anchor="w")
        self.request_history_tree.column("status", width=80, anchor="center")
        self.request_history_tree.column("time", width=90, anchor="center")
        self.request_history_tree.column("preview", width=340, anchor="w")
        self.request_history_tree.grid(row=5, column=0, columnspan=4, sticky=tk.NSEW, padx=5, pady=5)

        request_scroll = ttk.Scrollbar(self.request_frame, orient=tk.VERTICAL, command=self.request_history_tree.yview)
        self.request_history_tree.configure(yscrollcommand=request_scroll.set)
        request_scroll.grid(row=5, column=4, sticky=tk.NS)

        self.request_frame.rowconfigure(5, weight=1)
        self.request_frame.columnconfigure(3, weight=1)

    # --------------------------------------------------------------------------
    def _add_context_menu_to_entry(self, entry_widget):
        """Добавляет контекстное меню с Копировать/Вырезать/Вставить на поле ввода."""
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Вырезать", command=lambda: entry_widget.event_generate('<<Cut>>'))
        menu.add_command(label="Копировать", command=lambda: entry_widget.event_generate('<<Copy>>'))
        menu.add_command(label="Вставить", command=lambda: entry_widget.event_generate('<<Paste>>'))

        def show_menu(event):
            menu.tk_popup(event.x_root, event.y_root)

        entry_widget.bind("<Button-3>", show_menu)

    # --------------------------------------------------------------------------
    def _create_result_table(self, parent):
        """Создаёт Treeview с колонками, тегами и скроллбаром."""
        columns = ("host", "port", "state")
        tv = ttk.Treeview(parent, columns=columns, show="headings", height=10)

        default_headings = {"host": "IP адрес", "port": "Порт", "state": "Состояние"}
        tv.heading_texts = default_headings

        tv.heading("host", text=default_headings["host"],
                   command=lambda: self.treeview_sort_column(tv, "host", False))
        tv.heading("port", text=default_headings["port"],
                   command=lambda: self.treeview_sort_column(tv, "port", False))
        tv.heading("state", text=default_headings["state"],
                   command=lambda: self.treeview_sort_column(tv, "state", False))

        tv.column("host", width=180, anchor="w")
        tv.column("port", width=100, anchor="center")
        tv.column("state", width=120, anchor="center")

        tv.tag_configure('open',     background='#c8e6c9')
        tv.tag_configure('closed',   background='#ffcdd2')
        tv.tag_configure('filtered', background='#fff9c4')
        tv.tag_configure('error',    background='#e1bee7')

        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=tv.yview)
        tv.configure(yscrollcommand=scrollbar.set)
        tv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        tv.bind("<Button-3>", lambda e: self.show_table_context_menu(e, tv))

        return tv

    # --------------------------------------------------------------------------
    def show_table_context_menu(self, event, tv):
        """Контекстное меню для Treeview с копированием данных."""
        row_id = tv.identify_row(event.y)
        if not row_id:
            return

        tv.selection_set(row_id)
        menu = tk.Menu(self.root, tearoff=0)
        vals = tv.item(row_id)['values']
        if vals and len(vals) == 3:
            ip, port, state = vals
            menu.add_command(label="Копировать IP", command=lambda: self.copy_to_clipboard(ip))
            menu.add_command(label="Копировать порт", command=lambda: self.copy_to_clipboard(str(port)))
            menu.add_command(label="Копировать состояние", command=lambda: self.copy_to_clipboard(state))
            menu.add_separator()
            menu.add_command(label="Копировать строку",
                             command=lambda: self.copy_to_clipboard(f"{ip}:{port} - {state}"))
        else:
            menu.add_command(label="Нет данных", state=tk.DISABLED)
        menu.post(event.x_root, event.y_root)

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()

    # --------------------------------------------------------------------------
    def treeview_sort_column(self, tv, col, reverse):
        rows = [(tv.set(k, col), k) for k in tv.get_children('')]
        try:
            rows.sort(key=lambda t: int(t[0]), reverse=reverse)
        except ValueError:
            rows.sort(reverse=reverse)

        for index, (val, k) in enumerate(rows):
            tv.move(k, '', index)

        for c in ("host", "port", "state"):
            tv.heading(c, text=tv.heading_texts[c])

        arrow = " ▲" if not reverse else " ▼"
        tv.heading(col, text=tv.heading_texts[col] + arrow)
        tv.heading(col, command=lambda: self.treeview_sort_column(tv, col, not reverse))

    # --------------------------------------------------------------------------
    def _get_state_tag(self, state):
        tags = {'open': 'open', 'closed': 'closed', 'filtered': 'filtered'}
        return tags.get(state, 'error')

    # ==========================================================================
    # Запуск и остановка сканирования
    # ==========================================================================
    def start_scan(self):
        if self.scan_in_progress:
            return

        target_str = self.target_entry.get().strip()
        try:
            targets = parse_targets(target_str)
        except ValueError as e:
            messagebox.showerror("Ошибка", str(e))
            return
        if len(targets) > self.MAX_TARGETS:
            messagebox.showwarning("Слишком много целей",
                                   f"Максимум {self.MAX_TARGETS} IP-адресов (сейчас {len(targets)}).")
            return

        port_str = self.port_entry.get().strip()
        try:
            ports = parse_ports(port_str)
        except ValueError as e:
            messagebox.showerror("Ошибка", str(e))
            return

        if not ports:
            messagebox.showerror("Ошибка", "Укажите хотя бы один порт")
            return
        if len(ports) > self.MAX_PORTS:
            messagebox.showwarning("Слишком много портов",
                                   f"Максимум {self.MAX_PORTS} портов (сейчас {len(ports)}).")
            return

        for row in self.scan_tree.get_children():
            self.scan_tree.delete(row)
        self.progress_var.set(0)
        total_jobs = len(targets) * len(ports)
        self.progress.config(maximum=total_jobs)
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.current_results = []
        self.scan_in_progress = True

        self.result_queue = queue.Queue()
        self.scanner_thread = ScannerWorker(
            targets, ports,
            timeout=1.5,
            result_queue=self.result_queue
        )
        self.scanner_thread.start()
        self.poll_queue()

    def stop_scan(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            self.scanner_thread.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.scan_in_progress = False

    def start_request(self):
        if self.request_in_progress:
            return
        request_type = self.request_type.get().strip()
        target = self.request_target_entry.get().strip()
        payload = self.request_payload_entry.get().strip()
        if not target:
            messagebox.showerror("Ошибка", "Укажите цель запроса")
            return

        self.request_in_progress = True
        self.request_btn.config(state=tk.DISABLED)
        self.request_status_var.set(f"Выполняется {request_type}-запрос к {target} ...")

        self.request_thread = RequestWorker(request_type, target, payload, self.request_queue)
        self.request_thread.start()

    # --------------------------------------------------------------------------
    def poll_queue(self):
        try:
            while True:
                msg = self.result_queue.get_nowait()
                if msg[0] == 'result':
                    _, ip, port, state, current, total = msg
                    tag = self._get_state_tag(state)
                    self.scan_tree.insert("", tk.END, values=(ip, port, state), tags=(tag,))
                    self.current_results.append({'host': ip, 'port': port, 'state': state})
                    self.progress_var.set(current)
                    self.progress.config(maximum=total)

                elif msg[0] == 'finished':
                    self.scan_in_progress = False
                    self.start_btn.config(state=tk.NORMAL)
                    self.stop_btn.config(state=tk.DISABLED)
                    if self.current_results:
                        self.history_manager.add_entry(
                            self.target_entry.get().strip(),
                            self.port_entry.get().strip(),
                            self.current_results
                        )
                        self.refresh_history_list()
                    messagebox.showinfo("Готово", "Сканирование завершено")
        except queue.Empty:
            pass
        if self.scan_in_progress:
            self.root.after(100, self.poll_queue)

    def poll_request_queue(self):
        try:
            while True:
                msg = self.request_queue.get_nowait()
                if msg[0] == "request_finished":
                    _, request_type, target, payload, status, elapsed_ms, preview = msg
                    self.request_history_manager.add_entry(request_type, target, payload, status, elapsed_ms, preview)
                    self.refresh_request_history()
                    human = "успешно" if status == "ok" else "с ошибкой"
                    self.request_status_var.set(f"{request_type}-запрос завершен {human} за {elapsed_ms} мс")
                    self.request_btn.config(state=tk.NORMAL)
                    self.request_in_progress = False
        except queue.Empty:
            pass

        self.root.after(120, self.poll_request_queue)

    # ==========================================================================
    # Экспорт результатов
    # ==========================================================================
    def _export_tree_to_csv(self, tree, filename):
        import csv
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Host", "Port", "State"])
            for row_id in tree.get_children():
                writer.writerow(tree.item(row_id)['values'])

    def _export_tree_to_json(self, tree, filename):
        data = []
        for row_id in tree.get_children():
            vals = tree.item(row_id)['values']
            data.append({'host': vals[0], 'port': vals[1], 'state': vals[2]})
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def export_current_csv(self):
        if not self.scan_tree.get_children():
            messagebox.showinfo("Нет данных", "Нет результатов для экспорта.")
            return
        filename = filedialog.asksaveasfilename(defaultextension=".csv",
                                                filetypes=[("CSV files", "*.csv")])
        if filename:
            self._export_tree_to_csv(self.scan_tree, filename)

    def export_current_json(self):
        if not self.scan_tree.get_children():
            messagebox.showinfo("Нет данных", "Нет результатов для экспорта.")
            return
        filename = filedialog.asksaveasfilename(defaultextension=".json",
                                                filetypes=[("JSON files", "*.json")])
        if filename:
            self._export_tree_to_json(self.scan_tree, filename)

    def export_history_entry(self, index):
        entry = self.history_manager.entries[index]
        filename = filedialog.asksaveasfilename(defaultextension=".json",
                                                filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv")])
        if not filename:
            return
        if filename.endswith('.csv'):
            import csv
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Host", "Port", "State"])
                for res in entry['results']:
                    writer.writerow([res['host'], res['port'], res['state']])
        else:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(entry, f, indent=2, ensure_ascii=False)

    # ==========================================================================
    # История и контекстное меню
    # ==========================================================================
    def refresh_history_list(self):
        self.history_listbox.delete(0, tk.END)
        for entry in self.history_manager.entries:
            dt = entry['datetime'][:19]
            label = f"{dt} | {entry['target']} | {entry['scan_type']}"
            self.history_listbox.insert(tk.END, label)

    def on_history_select(self, event):
        selection = self.history_listbox.curselection()
        if not selection:
            return
        index = selection[0]
        self._show_history_entry(index)

    def _show_history_entry(self, index):
        entry = self.history_manager.entries[index]
        for row in self.hist_tree.get_children():
            self.hist_tree.delete(row)
        for res in entry.get('results', []):
            tag = self._get_state_tag(res['state'])
            self.hist_tree.insert("", tk.END, values=(res['host'], res['port'], res['state']), tags=(tag,))

    def delete_history_entry(self):
        selection = self.history_listbox.curselection()
        if not selection:
            messagebox.showinfo("Внимание", "Выберите запись для удаления")
            return
        index = selection[0]
        if messagebox.askyesno("Подтверждение", "Удалить выбранную запись?"):
            self.history_manager.delete_entry(index)
            self.refresh_history_list()
            for row in self.hist_tree.get_children():
                self.hist_tree.delete(row)

    def show_history_context_menu(self, event):
        selection = self.history_listbox.curselection()
        if not selection:
            return
        index = selection[0]

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Просмотреть", command=lambda: self._show_history_entry(index))
        menu.add_command(label="Экспортировать JSON/CSV", command=lambda: self.export_history_entry(index))
        menu.add_separator()
        menu.add_command(label="Удалить", command=self.delete_history_entry)
        menu.post(event.x_root, event.y_root)

    # ==========================================================================
    # История сетевых запросов (SQLite)
    # ==========================================================================
    def refresh_request_history(self):
        for row in self.request_history_tree.get_children():
            self.request_history_tree.delete(row)

        for _, created_at, request_type, target, payload, status, response_time_ms, response_preview in self.request_history_manager.list_entries():
            status_text = "OK" if status == "ok" else "ERROR"
            self.request_history_tree.insert(
                "", tk.END,
                values=(created_at, request_type, target, status_text, response_time_ms, response_preview[:180])
            )

    def clear_request_history(self):
        if messagebox.askyesno("Подтверждение", "Удалить всю историю сетевых запросов?"):
            self.request_history_manager.clear()
            self.refresh_request_history()
            self.request_status_var.set("История запросов очищена.")

    def export_request_history(self):
        rows = self.request_history_manager.list_entries()
        if not rows:
            messagebox.showinfo("Нет данных", "История запросов пуста.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv")]
        )
        if not filename:
            return

        if filename.endswith(".csv"):
            import csv
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["id", "created_at", "request_type", "target", "payload", "status", "response_time_ms", "response_preview"])
                writer.writerows(rows)
        else:
            data = []
            for row in rows:
                data.append({
                    "id": row[0],
                    "created_at": row[1],
                    "request_type": row[2],
                    "target": row[3],
                    "payload": row[4],
                    "status": row[5],
                    "response_time_ms": row[6],
                    "response_preview": row[7]
                })
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

    def on_closing(self):
        if self.scan_in_progress:
            self.stop_scan()
            if self.scanner_thread:
                self.scanner_thread.join(timeout=2)
        if self.request_in_progress and self.request_thread:
            self.request_thread.join(timeout=2)
        self.root.destroy()


# ==============================================================================
# Точка входа
# ==============================================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()
