"""Offline UI regression tests. All event fixtures are explicitly test data."""
import csv
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication

try:
    from . import ui as ui_module
except ImportError:
    import ui as ui_module

EventTableModel = ui_module.EventTableModel
EventFilterModel = ui_module.EventFilterModel
MainWindow = ui_module.MainWindow
read_jsonl = ui_module.read_jsonl
write_events = ui_module.write_events


def fixture(number, parent=0, name="TEST_ONLY.Function"):
    return {"type": "event", "seq": number, "call_id": number, "parent_id": parent,
            "ts_us": 1_000_000 + number * 100, "tid": 42, "depth": 0,
            "duration_us": 1.25, "function": name, "object": "TEST_ONLY.Object"}


class UiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.temp = tempfile.TemporaryDirectory()
        QSettings.setDefaultFormat(QSettings.IniFormat)
        QSettings.setPath(QSettings.IniFormat, QSettings.UserScope, cls.temp.name)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_bounded_model_parent_chain_and_filter(self):
        model = EventTableModel(max_rows=3)
        model.append_events([fixture(1), fixture(2, 1), fixture(3, 2)])
        self.assertEqual(model.rowCount(), 3)
        self.assertEqual(len(model.parent_chain(model.rows[-1])), 3)
        model.append_events([fixture(4, 3, "TEST_ONLY.Tick")])
        self.assertEqual([event["call_id"] for event in model.rows], [2, 3, 4])
        self.assertEqual(model.evicted, 1)
        self.assertNotIn(1, model.by_call_id)
        self.assertIn("未保留", model.parent_chain(model.rows[-1])[0])
        proxy = EventFilterModel()
        proxy.setSourceModel(model)
        proxy.set_query("tick")
        self.assertEqual(proxy.rowCount(), 1)
        self.assertEqual(proxy.visible_events()[0]["call_id"], 4)
        proxy.set_query("does not exist")
        self.assertEqual(proxy.rowCount(), 0)
        proxy.set_query("")
        self.assertEqual(proxy.rowCount(), 3)

    def test_jsonl_csv_roundtrip_and_limit(self):
        rows = [fixture(i) for i in range(1, 7)]
        root = Path(self.temp.name)
        jsonl = root / "fixtures.jsonl"
        csv_path = root / "fixtures.csv"
        self.assertEqual(write_events(str(jsonl), rows, "jsonl"), 6)
        loaded = read_jsonl(str(jsonl), 3)
        self.assertEqual(loaded["total"], 6)
        self.assertEqual([event["call_id"] for event in loaded["rows"]], [4, 5, 6])
        self.assertEqual(write_events(str(csv_path), loaded["rows"], "csv"), 3)
        with open(csv_path, encoding="utf-8-sig", newline="") as stream:
            exported = list(csv.DictReader(stream))
        self.assertEqual(exported[0]["function"], "TEST_ONLY.Function")
        self.assertEqual(exported[-1]["call_id"], "6")
        self.assertFalse((root / "fixtures.csv.writing").exists())

    def test_bad_jsonl_reports_line(self):
        path = Path(self.temp.name) / "invalid.jsonl"
        path.write_text(json.dumps(fixture(1)) + "\nnot-json\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "第 2 行"):
            read_jsonl(str(path))

    def test_offscreen_window_state_and_callback_batch(self):
        window = MainWindow()
        window.show()
        self.app.processEvents()
        self.assertFalse(window.start_button.isEnabled())
        self.assertFalse(window.pause_button.isEnabled())
        self.assertTrue(window.open_button.isEnabled())
        window.bridge.receive(fixture(1))
        self.assertEqual(window.model.rowCount(), 0)
        window.flush_events()
        self.assertEqual(window.model.rowCount(), 1)
        self.assertTrue(window.export_button.isEnabled())
        window.clear_events()
        self.assertEqual(window.model.rowCount(), 0)
        window.close()
        self.app.processEvents()

    def test_background_start_is_serialized_and_close_disconnects(self):
        class ExplicitTestClient:
            def __init__(self):
                self.starts = 0
                self.disconnects = 0
                self.worker_thread = None

            def start(self, **kwargs):
                self.starts += 1
                self.worker_thread = threading.get_ident()
                time.sleep(0.02)

            def disconnect(self):
                self.disconnects += 1

        def wait_for(predicate):
            end = time.monotonic() + 2
            while not predicate() and time.monotonic() < end:
                self.app.processEvents()
                time.sleep(0.005)
            self.assertTrue(predicate())

        window = MainWindow()
        window.show()
        client = ExplicitTestClient()
        window.client = client
        window.state = "ready"
        window.update_controls()
        window.start_capture()
        window.start_capture()
        self.assertFalse(window.start_button.isEnabled())
        wait_for(lambda: not window.busy)
        self.assertEqual(client.starts, 1)
        self.assertNotEqual(client.worker_thread, threading.get_ident())
        self.assertEqual(window.state, "recording")
        window.close()
        wait_for(lambda: not window.isVisible())
        self.assertEqual(client.disconnects, 1)

    def test_disconnect_during_start_does_not_restore_recording(self):
        window = MainWindow()
        window.state = "ready"
        window.client = object()
        window.on_control({"type": "disconnected", "message": "TEST_ONLY disconnection"})
        window.on_job_finished({"action": "start", "ok": True, "value": None})
        self.assertEqual(window.state, "disconnected")
        self.assertIsNone(window.client)
        self.assertFalse(window.start_button.isEnabled())
        window.close()

    def test_later_completed_parent_rebases_relative_time(self):
        model = EventTableModel()
        child = fixture(2, 1)
        parent = fixture(1)
        model.append_events([child])
        self.assertEqual(model.data(model.index(0, 0)), "0.000000")
        changed = []
        model.dataChanged.connect(lambda *args: changed.append(True))
        model.append_events([parent])
        self.assertEqual(model.data(model.index(0, 0)), "0.000100")
        self.assertEqual(model.data(model.index(1, 0)), "0.000000")
        self.assertTrue(changed)
        self.assertEqual(len(model.parent_chain(child)), 2)

    def test_export_failure_preserves_existing_file_and_unrelated_temp(self):
        path = Path(self.temp.name) / "keep.jsonl"
        path.write_text("existing data", encoding="utf-8")
        unrelated = path.with_name(path.name + ".writing")
        unrelated.write_text("unrelated data", encoding="utf-8")
        bad = fixture(1)
        bad["unsupported"] = object()
        with self.assertRaises(TypeError):
            write_events(str(path), [bad], "jsonl")
        self.assertEqual(path.read_text(encoding="utf-8"), "existing data")
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "unrelated data")
        self.assertEqual(list(path.parent.glob(".keep.jsonl.*.writing")), [])

    def test_stale_callbacks_cannot_disconnect_new_session(self):
        window = MainWindow()
        old = window.bridge.new_session()
        window.bridge.receive({"type": "disconnected", "message": "OLD TEST CALLBACK"}, old)
        current = window.bridge.new_session()
        window.state = "ready"
        window.client = object()
        window.bridge.receive(fixture(1), old)
        window.bridge.receive(fixture(2), current)
        self.app.processEvents()
        self.assertEqual(window.state, "ready")
        self.assertIsNotNone(window.client)
        window.flush_events()
        self.assertEqual([event["call_id"] for event in window.model.rows], [2])
        window.client = None
        window.close()

    def test_selection_survives_rolling_buffer_and_clears_when_evicted(self):
        window = MainWindow()
        window.model.max_rows = 3
        window.autoscroll.setChecked(False)
        for number in (1, 2, 3):
            window.bridge.receive(fixture(number))
        window.flush_events()
        window.table.selectRow(1)
        self.assertEqual(json.loads(window.detail_text.toPlainText())["call_id"], 2)
        window.bridge.receive(fixture(4))
        window.flush_events()
        self.assertEqual(json.loads(window.detail_text.toPlainText())["call_id"], 2)
        window.bridge.receive(fixture(5))
        window.flush_events()
        self.assertFalse(window.detail_text.toPlainText())
        window.close()

    def test_disconnection_drains_all_pending_events(self):
        window = MainWindow()
        for number in range(1, 4001):
            window.bridge.receive(fixture(number))
        window.on_control({"type": "disconnected", "message": "TEST_ONLY disconnection"})
        self.assertEqual(window.model.rowCount(), 4000)
        self.assertEqual(window.bridge.take(), [])
        window.close()

    def test_failed_connect_keeps_existing_records(self):
        window = MainWindow()
        window.model.append_events([fixture(7)])
        window._configuration = lambda: ("TEST_ONLY_ADB", "TEST_ONLY_DEVICE", "TEST_ONLY_PROFILE")
        window._make_client = lambda *args: (_ for _ in ()).throw(ValueError("TEST_ONLY failure"))
        window.connect_device()
        deadline = time.monotonic() + 2
        while window.busy and time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(0.005)
        self.assertFalse(window.busy)
        self.assertEqual(window.model.rows[0]["call_id"], 7)
        window.close()


if __name__ == "__main__":
    unittest.main()
