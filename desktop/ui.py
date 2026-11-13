"""Chinese desktop UI for real, bounded ProcessEvent observations.

The backend is imported only for device actions, so saved JSONL traces can be
reviewed without ADB. There is deliberately no simulated capture backend.
"""
from __future__ import annotations

import csv
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import traceback
from collections import deque
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import (
    QAbstractTableModel, QModelIndex, QPersistentModelIndex, QObject, QRunnable, QSettings,
    QSortFilterProxyModel, Qt, QThreadPool, QTimer, Signal, Slot,
)
from PySide6.QtGui import QColor, QFont, QCloseEvent
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QFrame,
    QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QMessageBox, QPushButton, QPlainTextEdit, QSpinBox, QSplitter, QStatusBar,
    QTableView, QTabWidget, QVBoxLayout, QWidget,
)

MAX_ROWS = 20_000
MAX_PENDING = 20_000
SETTINGS_ORGANIZATION = "UE4Trace"
SETTINGS_APPLICATION = "OpenSourceEventObserver"
CSV_FIELDS = (
    "seq", "call_id", "parent_id", "ts_us", "tid", "depth", "duration_us",
    "function", "object", "object_class", "function_addr", "object_addr", "caller_rva",
)


def asset_directory() -> Path:
    """PyInstaller onedir keeps deployable assets beside the executable."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "assets"
    return Path(__file__).resolve().parents[1] / "assets"


def saved_file_or_default(value: Any, default: str) -> str:
    """Ignore empty or stale preferences after moving a portable checkout."""
    candidate = value.strip() if isinstance(value, str) else ""
    return candidate if candidate and Path(candidate).is_file() else default


def default_profile_path(assets: Path) -> str:
    bundled = assets / "pubgmhd-1.39.13-arm64.json"
    if bundled.is_file() or getattr(sys, "frozen", False):
        return str(bundled)
    return str(Path(__file__).resolve().parents[1] / "profiles" / bundled.name)


def int_value(value: Any, default: int = 0) -> int:
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def valid_event(value: Any) -> bool:
    return isinstance(value, dict) and value.get("type") == "event" and all(
        key in value for key in ("ts_us", "tid", "function", "object")
    )


def read_jsonl(path: str, max_rows: int = MAX_ROWS) -> dict[str, Any]:
    """Keep the newest bounded events; never manufacture missing event fields."""
    rows: deque[dict[str, Any]] = deque(maxlen=max_rows)
    total = 0
    ignored = 0
    with open(path, "r", encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            if len(line) > 2 * 1024 * 1024:
                raise ValueError(f"第 {line_number} 行超过 2 MiB，无法作为事件载入。")
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"第 {line_number} 行不是有效 JSON：{exc.msg}") from exc
            if valid_event(value):
                rows.append(value)
                total += 1
            elif isinstance(value, dict) and value.get("type") != "event":
                ignored += 1
            else:
                raise ValueError(f"第 {line_number} 行缺少事件必需字段。")
    return {"rows": list(rows), "total": total, "ignored": ignored, "path": path}


def write_events(path: str, events: list[dict[str, Any]], fmt: str) -> int:
    """Export exactly the passed records, preserving original JSON fields."""
    destination = Path(path)
    handle, temporary_name = tempfile.mkstemp(prefix="." + destination.name + ".", suffix=".writing", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8-sig" if fmt == "csv" else "utf-8", newline="") as stream:
            if fmt == "csv":
                writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS, extrasaction="ignore")
                writer.writeheader()
                for event in events:
                    writer.writerow({key: event.get(key, "") for key in CSV_FIELDS})
            else:
                for event in events:
                    stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return len(events)


class EventTableModel(QAbstractTableModel):
    HEADERS = ("相对时间 / s", "线程", "深度", "耗时 / µs", "函数", "对象")

    def __init__(self, parent: QObject | None = None, max_rows: int = MAX_ROWS):
        super().__init__(parent)
        self.max_rows = max_rows
        self.rows: list[dict[str, Any]] = []
        self.by_call_id: dict[int, dict[str, Any]] = {}
        self.origin_us: int | None = None
        self.total_received = 0
        self.evicted = 0

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal and 0 <= section < len(self.HEADERS):
            return self.HEADERS[section]
        if role == Qt.ToolTipRole and orientation == Qt.Horizontal and section == 0:
            return "相对最早已观测调用的开始时间。记录在调用完成后到达，按接收顺序显示；父调用可晚于子调用出现。"
        return None

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self.rows):
            return None
        event = self.rows[index.row()]
        column = index.column()
        if role == Qt.UserRole:
            return event
        if role == Qt.DisplayRole:
            if column == 0:
                return f"{(int_value(event.get('ts_us')) - (self.origin_us or 0)) / 1_000_000:.6f}"
            if column == 1:
                return str(event.get("tid", "—"))
            if column == 2:
                return str(event.get("depth", "—"))
            if column == 3:
                duration = event.get("duration_us")
                return f"{float(duration):,.1f}" if isinstance(duration, (int, float)) else str(duration or "—")
            return str(event.get("function" if column == 4 else "object", "—"))
        if role == Qt.TextAlignmentRole:
            return int(Qt.AlignVCenter | (Qt.AlignRight if column < 4 else Qt.AlignLeft))
        if role == Qt.ToolTipRole:
            return str(event.get("function" if column == 4 else "object", "")) if column >= 4 else None
        if role == Qt.ForegroundRole and column == 2 and int_value(event.get("depth")) > 0:
            return QColor("#94613B")
        return None

    def append_events(self, values: list[dict[str, Any]]) -> None:
        if not values:
            return
        self.total_received += len(values)
        # Messages arrive when calls finish, so a parent may arrive after its
        # children despite having an earlier start timestamp.
        earliest = min(int_value(value.get("ts_us")) for value in values)
        origin_changed = self.origin_us is not None and earliest < self.origin_us
        if self.origin_us is None or origin_changed:
            self.origin_us = earliest
        excess_input = max(0, len(values) - self.max_rows)
        if excess_input:
            values = values[-self.max_rows:]
            self.evicted += excess_input
        remove = max(0, len(self.rows) + len(values) - self.max_rows)
        if remove:
            self.beginRemoveRows(QModelIndex(), 0, remove - 1)
            removed = self.rows[:remove]
            del self.rows[:remove]
            for item in removed:
                key = int_value(item.get("call_id"))
                if self.by_call_id.get(key) is item:
                    self.by_call_id.pop(key, None)
            self.evicted += remove
            self.endRemoveRows()
        start = len(self.rows)
        self.beginInsertRows(QModelIndex(), start, start + len(values) - 1)
        self.rows.extend(values)
        for item in values:
            if "call_id" in item:
                self.by_call_id[int_value(item["call_id"])] = item
        self.endInsertRows()
        if origin_changed and self.rows:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self.rows) - 1, 0), [Qt.DisplayRole])

    def clear(self) -> None:
        self.beginResetModel()
        self.rows.clear()
        self.by_call_id.clear()
        self.origin_us = None
        self.total_received = 0
        self.evicted = 0
        self.endResetModel()

    def parent_chain(self, event: dict[str, Any]) -> list[str]:
        chain: list[str] = []
        seen: set[int] = set()
        current = event
        for _ in range(128):
            call_id = int_value(current.get("call_id"))
            chain.append(f"#{call_id}  {current.get('function', '名称未解析')}  [线程 {current.get('tid', '—')}]")
            parent_id = int_value(current.get("parent_id"))
            if not parent_id:
                break
            if parent_id in seen:
                chain.append(f"[父调用 #{parent_id} 出现循环，停止展开]")
                break
            seen.add(parent_id)
            parent = self.by_call_id.get(parent_id)
            if parent is None:
                chain.append(f"[父调用 #{parent_id} 未保留：可能尚未完成、被过滤、限速或已移出缓冲]")
                break
            current = parent
        else:
            chain.append("[调用链超过 128 层，停止展开]")
        return list(reversed(chain))


class EventFilterModel(QSortFilterProxyModel):
    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self.needle = ""
        self.setDynamicSortFilter(True)

    def set_query(self, text: str) -> None:
        self.beginFilterChange()
        self.needle = text.strip().casefold()
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
        if not self.needle:
            return True
        model: EventTableModel = self.sourceModel()
        event = model.rows[row]
        return any(self.needle in str(event.get(key, "")).casefold()
                   for key in ("function", "object", "object_class", "tid", "call_id"))

    def visible_events(self) -> list[dict[str, Any]]:
        model: EventTableModel = self.sourceModel()
        return [dict(model.rows[self.mapToSource(self.index(row, 0)).row()]) for row in range(self.rowCount())]


class CallbackBridge(QObject):
    control = Signal(object)
    log = Signal(object)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self.pending: deque[dict[str, Any]] = deque()
        self.lock = threading.Lock()
        self.local_dropped = 0
        self.generation = 0

    def new_session(self) -> int:
        with self.lock:
            self.generation += 1
            self.pending.clear()
            self.local_dropped = 0
            return self.generation

    def receive(self, message: dict[str, Any], generation: int | None = None) -> None:
        with self.lock:
            current = self.generation
            if generation is not None and generation != current:
                return
            if valid_event(message):
                if len(self.pending) >= MAX_PENDING:
                    self.pending.popleft()
                    self.local_dropped += 1
                self.pending.append(message)
                return
        self.control.emit((current, message))

    def write_log(self, text: str, generation: int) -> None:
        self.log.emit((generation, text))

    def take(self, count: int = 3000) -> list[dict[str, Any]]:
        with self.lock:
            return [self.pending.popleft() for _ in range(min(count, len(self.pending)))]

    def reset(self) -> None:
        with self.lock:
            self.pending.clear()
            self.local_dropped = 0


class JobSignals(QObject):
    finished = Signal(object)


class BackgroundJob(QRunnable):
    def __init__(self, action: str, function: Callable[[], Any]):
        super().__init__()
        self.action = action
        self.function = function
        self.signals = JobSignals()

    def run(self) -> None:
        try:
            result = {"action": self.action, "ok": True, "value": self.function()}
        except Exception as exc:
            result = {"action": self.action, "ok": False, "message": str(exc), "traceback": traceback.format_exc()}
        self.signals.finished.emit(result)


STYLE = """
QMainWindow, QWidget#workspace { background: #EDF2F7; color: #243448; }
QWidget { font-family: 'Segoe UI', 'Microsoft YaHei UI'; font-size: 10pt; }
QFrame#topbar { background: #152B43; border: none; }
QLabel#appTitle { color: #FFFFFF; font-size: 18pt; font-weight: 650; }
QLabel#appSubtitle { color: #B8CADA; font-size: 9pt; }
QLabel#stateBadge { background: #28415A; color: #E5EEF6; border-radius: 4px; padding: 7px 13px; font-weight: 600; }
QLabel#sectionLabel { color: #263F59; font-size: 11pt; font-weight: 600; }
QLabel#hint { color: #566A7F; font-size: 9pt; }
QLabel#warning { color: #85522D; background: #F5EEE6; padding: 7px 9px; border-left: 3px solid #AE7548; }
QFrame#connection { background: #F8FAFC; border: 1px solid #D2DCE6; border-radius: 5px; }
QLineEdit, QComboBox, QSpinBox { background: #FFFFFF; color: #243448; border: 1px solid #BFCEDB; border-radius: 3px; padding: 5px 7px; min-height: 22px; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border: 1px solid #2875B9; }
QComboBox::drop-down { border-left: 1px solid #D5DFE8; width: 22px; }
QPushButton { background: #FFFFFF; color: #28435E; border: 1px solid #B7C7D6; border-radius: 3px; padding: 7px 12px; font-weight: 500; }
QPushButton:hover { background: #E5EFF8; border-color: #6F9AC1; }
QPushButton:pressed { background: #D5E5F3; }
QPushButton:disabled { color: #91A0AF; background: #EDF1F5; border-color: #D3DDE5; }
QPushButton#primary { background: #246CAB; color: white; border-color: #246CAB; }
QPushButton#primary:hover { background: #1D5C94; }
QPushButton#primary:disabled { background: #ADC2D4; border-color: #ADC2D4; color: #F1F5F8; }
QPushButton#pause { color: #8B542D; border-color: #BA916F; }
QTableView { background: white; alternate-background-color: #F4F7FA; border: 1px solid #CDDAE5; selection-background-color: #D5E7F6; selection-color: #143D60; gridline-color: #E9EFF4; }
QTableView::item { padding: 3px 6px; border-bottom: 1px solid #EDF2F6; }
QHeaderView::section { background: #E6EDF4; color: #354F68; border: none; border-bottom: 1px solid #C3D1DE; border-right: 1px solid #D4DFE8; padding: 8px 6px; font-weight: 600; }
QTabWidget::pane { border: 1px solid #CEDAE4; background: #FFFFFF; }
QTabBar::tab { background: #DFE7EF; color: #536B80; padding: 7px 15px; margin-right: 2px; border-top-left-radius: 3px; border-top-right-radius: 3px; }
QTabBar::tab:selected { background: white; color: #246CAB; border-top: 2px solid #246CAB; }
QPlainTextEdit { background: white; color: #334C63; border: none; padding: 7px; font-family: 'Consolas', 'Microsoft YaHei UI'; font-size: 9pt; }
QSplitter::handle { background: #D7E1EB; }
QStatusBar { background: #E3EBF3; color: #536B80; border-top: 1px solid #CDDAE5; }
QCheckBox { color: #476078; spacing: 6px; }
"""


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UE4 事件观察器")
        self.resize(1360, 900)
        self.setMinimumSize(1040, 700)
        self.settings = QSettings(SETTINGS_ORGANIZATION, SETTINGS_APPLICATION)
        self.assets_dir = asset_directory()
        self.client: Any = None
        self.state = "disconnected"
        self.busy = ""
        self._closing = False
        self._connection_lost = False
        self._jobs: dict[str, BackgroundJob] = {}
        self.thread_pool = QThreadPool(self)
        self.thread_pool.setMaxThreadCount(1)
        self.bridge = CallbackBridge(self)
        self.bridge.control.connect(self.on_control, Qt.QueuedConnection)
        self.bridge.log.connect(self.on_backend_log, Qt.QueuedConnection)
        self.native_stats: dict[str, Any] = {}
        self.last_info: dict[str, Any] = {}
        self._build_ui()
        self.setStyleSheet(STYLE)
        self.flush_timer = QTimer(self)
        self.flush_timer.timeout.connect(self.flush_events)
        self.flush_timer.start(100)
        self.update_controls()
        self.update_stats()
        self.append_log("尚未连接设备。选择 ADB、设备和配置后，先检查版本，再连接并准备。")

    def _build_ui(self) -> None:
        workspace = QWidget(objectName="workspace")
        outer = QVBoxLayout(workspace)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        top = QFrame(objectName="topbar")
        top_layout = QHBoxLayout(top)
        top_layout.setContentsMargins(22, 14, 22, 14)
        titles = QVBoxLayout()
        titles.setSpacing(2)
        titles.addWidget(QLabel("UE4 事件观察器", objectName="appTitle"))
        titles.addWidget(QLabel("ProcessEvent 调用记录与父调用链", objectName="appSubtitle"))
        top_layout.addLayout(titles)
        top_layout.addStretch()
        self.state_label = QLabel("未连接", objectName="stateBadge")
        top_layout.addWidget(self.state_label)
        outer.addWidget(top)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(18, 14, 18, 12)
        layout.setSpacing(10)

        connection = QFrame(objectName="connection")
        grid = QGridLayout(connection)
        grid.setContentsMargins(12, 10, 12, 10)
        grid.setHorizontalSpacing(9)
        grid.setVerticalSpacing(8)
        self.adb_edit = QLineEdit()
        bundled_adb = self.assets_dir / "adb" / "adb.exe"
        default_adb = str(bundled_adb) if bundled_adb.exists() else (shutil.which("adb") or "")
        self.adb_edit.setText(saved_file_or_default(self.settings.value("adb_path"), default_adb))
        self.adb_edit.setPlaceholderText("选择 adb.exe")
        self.adb_browse = QPushButton("浏览…")
        self.adb_browse.clicked.connect(self.choose_adb)
        self.devices = QComboBox()
        self.devices.setMinimumWidth(240)
        self.devices.addItem("点击刷新，查找已授权设备", None)
        self.refresh_button = QPushButton("刷新设备")
        self.refresh_button.clicked.connect(self.refresh_devices)
        grid.addWidget(QLabel("ADB"), 0, 0)
        grid.addWidget(self.adb_edit, 0, 1)
        grid.addWidget(self.adb_browse, 0, 2)
        grid.addWidget(QLabel("设备"), 0, 3)
        grid.addWidget(self.devices, 0, 4)
        grid.addWidget(self.refresh_button, 0, 5)
        self.profile_edit = QLineEdit(saved_file_or_default(self.settings.value("profile_path"), default_profile_path(self.assets_dir)))
        self.profile_browse = QPushButton("浏览…")
        self.profile_browse.clicked.connect(self.choose_profile)
        self.inspect_button = QPushButton("检查版本")
        self.inspect_button.clicked.connect(self.inspect_device)
        self.connect_button = QPushButton("连接并准备")
        self.connect_button.setObjectName("primary")
        self.connect_button.clicked.connect(self.connect_device)
        grid.addWidget(QLabel("配置"), 1, 0)
        grid.addWidget(self.profile_edit, 1, 1)
        grid.addWidget(self.profile_browse, 1, 2)
        grid.addWidget(self.inspect_button, 1, 4)
        grid.addWidget(self.connect_button, 1, 5)
        grid.setColumnStretch(1, 3)
        grid.setColumnStretch(4, 2)
        self.info_label = QLabel("等待检查：包名、版本、PID、架构与模块基址", objectName="hint")
        self.info_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.info_label.setWordWrap(True)
        grid.addWidget(self.info_label, 2, 0, 1, 6)
        layout.addWidget(connection)

        capture = QHBoxLayout()
        capture.setSpacing(8)
        capture.addWidget(QLabel("采集过滤"))
        self.include_edit = QLineEdit()
        self.include_edit.setPlaceholderText("包含函数或对象名称（留空为全部）")
        self.include_edit.setClearButtonEnabled(True)
        self.exclude_edit = QLineEdit()
        self.exclude_edit.setPlaceholderText("排除名称")
        self.exclude_edit.setClearButtonEnabled(True)
        capture.addWidget(self.include_edit, 2)
        capture.addWidget(self.exclude_edit, 1)
        capture.addWidget(QLabel("上限 / 秒"))
        self.max_rate = QSpinBox()
        self.max_rate.setRange(1, 10_000)
        self.max_rate.setValue(1000)
        self.max_rate.setSingleStep(100)
        self.max_rate.setToolTip("设备端每秒最大输出事件数；超出部分计入丢弃统计。")
        capture.addWidget(self.max_rate)
        self.start_button = QPushButton("开始采集")
        self.start_button.setObjectName("primary")
        self.start_button.clicked.connect(self.start_capture)
        self.pause_button = QPushButton("暂停")
        self.pause_button.setObjectName("pause")
        self.pause_button.clicked.connect(self.pause_capture)
        self.disconnect_button = QPushButton("断开")
        self.disconnect_button.clicked.connect(self.disconnect_device)
        capture.addWidget(self.start_button)
        capture.addWidget(self.pause_button)
        capture.addWidget(self.disconnect_button)
        layout.addLayout(capture)

        warning = QLabel("仅记录经过 ProcessEvent 的反射 / 蓝图分发；不包含全部原生 C++ 调用。过滤、限速和缓冲淘汰可能造成调用链缺项。", objectName="warning")
        warning.setWordWrap(True)
        layout.addWidget(warning)

        table_toolbar = QHBoxLayout()
        table_toolbar.addWidget(QLabel("调用记录", objectName="sectionLabel"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("筛选已保留记录：函数、对象、线程或调用 ID")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.setMaximumWidth(450)
        table_toolbar.addWidget(self.search_edit, 1)
        self.autoscroll = QCheckBox("跟随最新")
        self.autoscroll.setChecked(True)
        table_toolbar.addWidget(self.autoscroll)
        table_toolbar.addStretch()
        self.open_button = QPushButton("打开 JSONL")
        self.open_button.clicked.connect(self.load_offline)
        self.export_button = QPushButton("导出当前筛选…")
        self.export_button.clicked.connect(self.export_visible)
        self.clear_button = QPushButton("清空记录")
        self.clear_button.clicked.connect(self.clear_events)
        table_toolbar.addWidget(self.open_button)
        table_toolbar.addWidget(self.export_button)
        table_toolbar.addWidget(self.clear_button)
        layout.addLayout(table_toolbar)

        self.model = EventTableModel(self)
        self.proxy = EventFilterModel(self)
        self.proxy.setSourceModel(self.model)
        self.search_edit.textChanged.connect(self.on_view_filter)
        splitter = QSplitter(Qt.Vertical)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.setEditTriggers(QTableView.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(28)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        for column, width in enumerate((128, 80, 60, 112, 410, 350)):
            self.table.setColumnWidth(column, width)
        header.setSectionResizeMode(QHeaderView.Interactive)
        self.table.selectionModel().selectionChanged.connect(self.show_selection)
        splitter.addWidget(self.table)
        self.tabs = QTabWidget()
        detail_page = QWidget()
        detail_layout = QHBoxLayout(detail_page)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        details_split = QSplitter(Qt.Horizontal)
        self.detail_text = QPlainTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setPlaceholderText("选择一条事件，查看原始字段、地址与耗时。")
        self.chain_text = QPlainTextEdit()
        self.chain_text.setReadOnly(True)
        self.chain_text.setPlaceholderText("父调用链只根据已记录的 call_id / parent_id 关联。")
        details_split.addWidget(self.detail_text)
        details_split.addWidget(self.chain_text)
        details_split.setSizes([600, 600])
        detail_layout.addWidget(details_split)
        self.tabs.addTab(detail_page, "事件详情与父调用链")
        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.document().setMaximumBlockCount(1500)
        self.tabs.addTab(self.log_text, "诊断日志")
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([440, 180])
        layout.addWidget(splitter, 1)
        self.stats_label = QLabel("设备统计：未连接    本地保留 0 / 20,000", objectName="hint")
        self.stats_label.setWordWrap(True)
        layout.addWidget(self.stats_label)
        outer.addWidget(body, 1)
        self.setCentralWidget(workspace)
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("就绪。先在手机开启 USB 调试并确认授权。")

    def choose_adb(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择 ADB", self.adb_edit.text(), "ADB (adb.exe);;所有文件 (*)")
        if path:
            self.adb_edit.setText(path)

    def choose_profile(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择版本配置", self.profile_edit.text(), "JSON 配置 (*.json)")
        if path:
            self.profile_edit.setText(path)

    def _backend_classes(self):
        try:
            from .backend import AdbBridge, PhoneTraceClient
        except ImportError:
            try:
                from backend import AdbBridge, PhoneTraceClient
            except ImportError as exc:
                raise RuntimeError("缺少设备后端。请使用完整安装目录；仍可打开 JSONL 离线查看。") from exc
        return AdbBridge, PhoneTraceClient

    def _configuration(self) -> tuple[str, str, str]:
        adb = self.adb_edit.text().strip()
        serial = self.devices.currentData()
        profile = self.profile_edit.text().strip()
        if not adb:
            raise ValueError("请选择 adb.exe，再刷新设备。")
        if not serial:
            raise ValueError("请选择状态为 device 的手机；未授权时请在手机确认 USB 调试。")
        if not Path(profile).is_file():
            raise ValueError("配置文件不存在，请选择与当前游戏版本匹配的 JSON 配置。")
        self.settings.setValue("adb_path", adb)
        self.settings.setValue("profile_path", profile)
        self.settings.setValue("serial", serial)
        return adb, str(serial), profile

    def _make_client(self, config: tuple[str, str, str], generation: int):
        _, client_type = self._backend_classes()
        adb, serial, profile = config
        return client_type(adb, serial, str(self.assets_dir), profile,
                           lambda message: self.bridge.receive(message, generation),
                           lambda text: self.bridge.write_log(text, generation))

    def _launch(self, action: str, function: Callable[[], Any], label: str) -> None:
        if self.busy:
            return
        self.busy = action
        job = BackgroundJob(action, function)
        self._jobs[action] = job
        job.signals.finished.connect(self.on_job_finished, Qt.QueuedConnection)
        self.status.showMessage(label)
        self.update_controls()
        self.thread_pool.start(job)

    @Slot()
    def refresh_devices(self) -> None:
        adb = self.adb_edit.text().strip()
        if not adb:
            self.report_error("请选择 adb.exe，再刷新设备。")
            return
        self.settings.setValue("adb_path", adb)
        def action():
            bridge_type, _ = self._backend_classes()
            return bridge_type(adb).list_devices()
        self._launch("devices", action, "正在检查 ADB 连接…")

    @Slot()
    def inspect_device(self) -> None:
        try:
            config = self._configuration()
        except ValueError as exc:
            self.report_error(str(exc))
            return
        generation = self.bridge.new_session()
        self._launch("inspect", lambda: self._make_client(config, generation).inspect(), "正在核对游戏版本与模块…")

    @Slot()
    def connect_device(self) -> None:
        try:
            config = self._configuration()
        except ValueError as exc:
            self.report_error(str(exc))
            return
        generation = self.bridge.new_session()
        self._connection_lost = False
        def action():
            client = self._make_client(config, generation)
            try:
                info = client.connect()
                return {"client": client, "info": info}
            except Exception:
                try:
                    client.disconnect()
                except Exception:
                    pass
                raise
        self._launch("connect", action, "正在检查、部署并准备观察器，请稍候…")

    @Slot()
    def start_capture(self) -> None:
        if self.client is None or self.state not in ("ready", "paused"):
            return
        client = self.client
        include, exclude, rate = self.include_edit.text().strip(), self.exclude_edit.text().strip(), self.max_rate.value()
        self._launch("start", lambda: client.start(include=include, exclude=exclude, max_rate=rate), "正在开始采集…")

    @Slot()
    def pause_capture(self) -> None:
        if self.client is not None and self.state == "recording":
            self._launch("pause", self.client.pause, "正在暂停采集…")

    @Slot()
    def disconnect_device(self) -> None:
        if self.client is not None:
            self._launch("disconnect", self.client.disconnect, "正在停止记录并断开…")

    @Slot(object)
    def on_job_finished(self, result: dict[str, Any]) -> None:
        action = result["action"]
        self.busy = ""
        self._jobs.pop(action, None)
        if not result["ok"]:
            self.report_error(result["message"] or "操作失败，请查看诊断日志。")
            if action == "connect":
                self.state = "disconnected"
            if action == "disconnect":
                self.client = None
                self.state = "disconnected"
        else:
            value = result.get("value")
            if action == "devices":
                self.devices.clear()
                preferred = str(self.settings.value("serial", ""))
                for device in value or []:
                    state = device.get("state", "unknown")
                    serial = str(device.get("serial", ""))
                    label = f"{device.get('model') or 'Android'}  ·  {serial}  ({state})"
                    self.devices.addItem(label, serial if state == "device" else None)
                    if state != "device":
                        item = self.devices.model().item(self.devices.count() - 1)
                        if item is not None:
                            item.setEnabled(False)
                if not value:
                    self.devices.addItem("未发现设备，请检查 USB 或无线调试连接", None)
                else:
                    preferred_index = self.devices.findData(preferred)
                    usable = next((i for i in range(self.devices.count()) if self.devices.itemData(i)), -1)
                    self.devices.setCurrentIndex(preferred_index if preferred_index >= 0 else usable)
                self.status.showMessage(f"ADB 检查完成：{len(value or [])} 台设备。")
            elif action == "inspect":
                self._display_info(value)
                self.append_log("版本检查完成：" + json.dumps(value, ensure_ascii=False))
                self.status.showMessage("检查完成。配置匹配后可连接并准备。")
            elif action == "connect":
                self.client = value["client"]
                self.state = "disconnected" if self._connection_lost else "ready"
                self._display_info(value.get("info") or {})
                if self._connection_lost:
                    self.append_log("准备期间连接已中断，正在清理连接。")
                    self.disconnect_device()
                else:
                    self.clear_events()
                    self.native_stats.clear()
                    self.append_log("连接并准备完成，尚未开始记录。")
                    self.status.showMessage("已准备。设置过滤与速率后开始采集。")
            elif action == "start":
                if self.client is not None and not self._connection_lost:
                    self.state = "recording"
                    self.append_log("已开始采集。")
                    self.status.showMessage("正在采集实际 ProcessEvent 调用。")
            elif action == "pause":
                if self.client is not None and not self._connection_lost:
                    self.state = "paused"
                    self.append_log("已暂停采集；现有记录保留。")
                    self.status.showMessage("已暂停。可修改采集过滤后继续。")
            elif action == "disconnect":
                self.client = None
                self.state = "disconnected"
                self.append_log("已断开设备。")
                self.status.showMessage("已断开；保留的记录仍可查看和导出。")
            elif action == "import":
                self.clear_events()
                self.model.append_events(value["rows"])
                self.model.total_received = value["total"]
                self.model.evicted = max(0, value["total"] - len(value["rows"]))
                self.state = "offline"
                self.native_stats.clear()
                self.info_label.setText("离线记录：" + value["path"])
                self.append_log(f"已读取 {value['total']:,} 条真实文件记录，保留最新 {len(value['rows']):,} 条；忽略 {value['ignored']} 行非事件消息。")
                self.status.showMessage("离线查看：未连接手机。")
            elif action == "export":
                self.append_log(f"已导出 {value['count']:,} 条记录到 {value['path']}")
                self.status.showMessage(f"导出完成：{value['count']:,} 条记录。")
        self.update_controls()
        self.update_stats()
        if self._closing:
            if self.client is not None:
                self.disconnect_device()
            else:
                self.close()

    def _display_info(self, info: dict[str, Any]) -> None:
        self.last_info = info
        match = info.get("profile_match")
        match_text = "匹配" if match is True else "不匹配" if match is False else "未确认"
        self.info_label.setText(
            f"{info.get('package', '包名未知')}    版本 {info.get('version_name', '—')} ({info.get('version_code', '—')})    "
            f"PID {info.get('pid', '—')}    {info.get('abi', '架构未知')}    模块基址 {info.get('base', '—')}    配置：{match_text}"
        )

    @Slot(object)
    def on_control(self, message: dict[str, Any] | tuple) -> None:
        if isinstance(message, tuple):
            generation, message = message
            if generation != self.bridge.generation:
                return
        kind = message.get("type")
        if kind == "stats":
            self.native_stats = dict(message)
            self.update_stats()
        elif kind == "error":
            self.report_error(str(message.get("message", "设备报告错误。")))
        elif kind == "disconnected":
            self.flush_events(drain=True)
            self._connection_lost = True
            self.client = None
            self.state = "disconnected"
            self.append_log(str(message.get("message", "设备连接已结束。")))
            self.update_controls()
        elif kind == "hello":
            self.append_log(f"观察器已响应：PID {message.get('pid', '—')}，协议 {message.get('protocol', '—')}。")

    @Slot(object)
    def on_backend_log(self, payload: tuple[int, str]) -> None:
        generation, text = payload
        if generation == self.bridge.generation:
            self.append_log(text)

    @Slot(str)
    def append_log(self, text: str) -> None:
        self.log_text.appendPlainText(f"[{time.strftime('%H:%M:%S')}] {text}")

    def report_error(self, text: str) -> None:
        self.append_log("错误：" + text)
        self.status.showMessage(text)
        self.tabs.setCurrentIndex(1)

    @Slot()
    def flush_events(self, drain: bool = False) -> None:
        values = self.bridge.take(MAX_PENDING if drain else 3000)
        if values:
            selection = self.table.selectionModel()
            selected = selection.selectedRows()
            original = QPersistentModelIndex(self.proxy.mapToSource(selected[0])) if selected else None
            selection.blockSignals(True)
            try:
                self.model.append_events(values)
                if original is not None and not original.isValid():
                    # Qt may move a removed selection to its neighbour. Never
                    # silently replace the call the user was inspecting.
                    selection.clearSelection()
                    self.table.setCurrentIndex(QModelIndex())
            finally:
                selection.blockSignals(False)
            if self.autoscroll.isChecked():
                self.table.scrollToBottom()
            self.show_selection()
            self.update_stats()

    @Slot(str)
    def on_view_filter(self, text: str) -> None:
        self.proxy.set_query(text)
        self.update_stats()

    @Slot()
    def show_selection(self, *_args) -> None:
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            self.detail_text.clear()
            self.chain_text.clear()
            return
        index = self.proxy.mapToSource(selected[0])
        if 0 <= index.row() < len(self.model.rows):
            event = self.model.rows[index.row()]
            self.detail_text.setPlainText(json.dumps(event, ensure_ascii=False, indent=2))
            chain = self.model.parent_chain(event)
            self.chain_text.setPlainText("父调用 → 当前调用\n\n" + "\n".join("  " * i + value for i, value in enumerate(chain)))

    @Slot()
    def clear_events(self) -> None:
        self.bridge.reset()
        self.model.clear()
        self.detail_text.clear()
        self.chain_text.clear()
        self.update_stats()

    def update_stats(self) -> None:
        retained = len(self.model.rows)
        local = f"本地已收 {self.model.total_received:,}    保留 {retained:,} / 20,000    当前筛选 {self.proxy.rowCount():,}    已淘汰 {self.model.evicted:,}"
        stats = self.native_stats
        if stats:
            device = f"设备累计：命中 {int_value(stats.get('seen')):,}    输出 {int_value(stats.get('emitted')):,}    丢弃 {int_value(stats.get('dropped')):,}    排队 {int_value(stats.get('queued')):,}"
        else:
            device = "设备统计：离线" if self.state == "offline" else "设备统计：尚未收到"
        if self.bridge.local_dropped:
            local += f"    桌面待处理队列丢弃 {self.bridge.local_dropped:,}"
        self.stats_label.setText(device + "\n" + local)
        self.export_button.setEnabled(not self.busy and self.proxy.rowCount() > 0 and not self._closing)

    def update_controls(self) -> None:
        idle = not self.busy
        connected = self.client is not None
        labels = {"disconnected": "未连接", "ready": "已准备", "recording": "采集中", "paused": "已暂停", "offline": "离线查看"}
        busy_labels = {"devices": "查找设备中", "inspect": "检查中", "connect": "准备中", "start": "启动中", "pause": "暂停中", "disconnect": "断开中", "import": "载入中", "export": "导出中"}
        self.state_label.setText(busy_labels.get(self.busy, labels.get(self.state, self.state)))
        for widget in (self.adb_edit, self.adb_browse, self.devices, self.refresh_button, self.profile_edit, self.profile_browse, self.inspect_button, self.connect_button):
            widget.setEnabled(idle and not connected and not self._closing)
        editable_filter = idle and self.state != "recording" and not self._closing
        for widget in (self.include_edit, self.exclude_edit, self.max_rate):
            widget.setEnabled(editable_filter)
        self.start_button.setEnabled(idle and connected and self.state in ("ready", "paused") and not self._closing)
        self.start_button.setText("继续采集" if self.state == "paused" else "开始采集")
        self.pause_button.setEnabled(idle and connected and self.state == "recording" and not self._closing)
        self.disconnect_button.setEnabled(idle and connected and not self._closing)
        self.open_button.setEnabled(idle and not connected and not self._closing)
        self.clear_button.setEnabled(idle and not self._closing)
        self.export_button.setEnabled(idle and self.proxy.rowCount() > 0 and not self._closing)

    @Slot()
    def load_offline(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "打开事件记录", "", "JSONL 记录 (*.jsonl *.ndjson);;所有文件 (*)")
        if path:
            self._launch("import", lambda: read_jsonl(path), "正在读取离线记录…")

    @Slot()
    def export_visible(self) -> None:
        path, chosen = QFileDialog.getSaveFileName(self, "导出当前筛选记录", "ue4-events.jsonl", "JSONL 原始事件 (*.jsonl);;CSV 表格 (*.csv)")
        if not path:
            return
        fmt = "csv" if "CSV" in chosen or path.lower().endswith(".csv") else "jsonl"
        if not Path(path).suffix:
            path += "." + fmt
        values = self.proxy.visible_events()
        self._launch("export", lambda: {"count": write_events(path, values, fmt), "path": path}, "正在导出筛选记录快照…")

    def closeEvent(self, event: QCloseEvent) -> None:
        self.settings.setValue("adb_path", self.adb_edit.text().strip())
        self.settings.setValue("profile_path", self.profile_edit.text().strip())
        if self.busy or self.client is not None:
            event.ignore()
            self._closing = True
            self.status.showMessage("正在结束当前操作并断开设备…")
            if not self.busy:
                self.disconnect_device()
            self.update_controls()
            return
        self.flush_timer.stop()
        event.accept()


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(SETTINGS_APPLICATION)
    app.setOrganizationName(SETTINGS_ORGANIZATION)
    app.setFont(QFont("Microsoft YaHei UI", 10))
    window = MainWindow()
    window.show()
    if len(sys.argv) > 1 and Path(sys.argv[1]).is_file():
        path = str(Path(sys.argv[1]).resolve())
        QTimer.singleShot(0, lambda: window._launch("import", lambda: read_jsonl(path), "正在读取离线记录…"))
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
