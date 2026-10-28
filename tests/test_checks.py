import unittest

from examguard.checks import (
    check_dockless, check_menu_bar, check_private_api, check_processes,
    check_tcc, check_windows, read_tcc, run_all, scan_memory_file,
    scan_symbols, is_system_path,
)


def win(**kw):
    base = {"pid": 100, "owner": "SomeApp", "name": "Invisible Window",
            "layer": 3, "onscreen": True, "sharing": 0, "alpha": 1.0,
            "bounds": [0, 0, 100, 100]}
    base.update(kw)
    return base


class WindowTests(unittest.TestCase):
    def test_flags_capture_excluded_window(self):
        out = check_windows([win()], self_pid=999)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "high")
        self.assertEqual(out[0].evidence["pid"], 100)

    def test_ignores_shared_window(self):
        self.assertEqual(check_windows([win(sharing=1)], 999), [])

    def test_ignores_offscreen_hidden_transparent_and_negative_layer(self):
        for kw in ({"onscreen": False}, {"alpha": 0.0}, {"layer": -1}):
            self.assertEqual(check_windows([win(**kw)], 999), [], kw)

    def test_ignores_self_and_system_owners(self):
        self.assertEqual(check_windows([win(pid=5)], self_pid=5), [])
        self.assertEqual(check_windows([win(owner="Window Server")], 999), [])


class ProcessTests(unittest.TestCase):
    def test_flags_screencapture(self):
        out = check_processes([
            {"pid": 1, "comm": "/usr/sbin/screencapture"},
            {"pid": 2, "comm": "/bin/zsh"},
        ])
        self.assertEqual([f.subject for f in out], ["screencapture"])

    def test_ignores_normal(self):
        self.assertEqual(check_processes([{"pid": 2, "comm": "/bin/zsh"}]), [])


class PrivateApiTests(unittest.TestCase):
    def test_scan_symbols(self):
        blob = b"\x00CoreBrightness\x00KeyboardBrightnessClient\x00junk"
        self.assertEqual(scan_symbols(blob),
                         ["CoreBrightness", "KeyboardBrightnessClient"])
        self.assertEqual(scan_symbols(b"nothing here"), [])

    def test_flags_app_with_private_symbol(self):
        out = check_private_api([
            {"name": "Suspicious", "executable": "/Applications/Suspicious.app/Contents/MacOS/Suspicious",
             "symbols": ["IOHIDSystem"], "policy": "accessory"},
        ])
        self.assertEqual(len(out), 1)
        self.assertIn("IOHIDSystem", out[0].detail)

    def test_ignores_system_app_and_clean_app(self):
        self.assertEqual(check_private_api([
            {"name": "Apple", "executable": "/System/Applications/X.app/Contents/MacOS/X",
             "symbols": ["CoreBrightness"]},
        ]), [])
        self.assertEqual(check_private_api([
            {"name": "Clean", "executable": "/Applications/Clean.app/Contents/MacOS/Clean",
             "symbols": []},
        ]), [])

    def test_is_system_path(self):
        self.assertTrue(is_system_path("/System/Applications/Mail.app"))
        self.assertFalse(is_system_path("/Applications/Mail.app"))


class DocklessTests(unittest.TestCase):
    def test_flags_accessory_app(self):
        out = check_dockless([{"name": "Menu", "executable": "/Applications/Menu.app/x",
                               "policy": "accessory"}])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "info")

    def test_ignores_regular_and_system(self):
        self.assertEqual(check_dockless([
            {"name": "R", "executable": "/Applications/R.app/x", "policy": "regular"},
            {"name": "S", "executable": "/System/Applications/S.app/x", "policy": "accessory"},
        ]), [])


class TccTests(unittest.TestCase):
    def setUp(self):
        import sqlite3
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute(
            "CREATE TABLE access (service TEXT, client TEXT, client_type INT, auth_value INT)"
        )

    def tearDown(self):
        self.conn.close()

    def _insert(self, service, client, auth_value=2, client_type=0):
        self.conn.execute("INSERT INTO access VALUES (?,?,?,?)",
                          (service, client, client_type, auth_value))
        self.conn.commit()

    def test_reads_only_interesting_services(self):
        self._insert("kTCCServiceScreenCapture", "com.a.b")
        self._insert("kTCCServiceMicrophone", "com.a.b")
        rows = read_tcc(self.conn)
        self.assertEqual([r["service"] for r in rows], ["kTCCServiceScreenCapture"])

    def test_missing_table_is_empty(self):
        import sqlite3
        self.assertEqual(read_tcc(sqlite3.connect(":memory:")), [])

    def test_both_grants_is_high(self):
        self._insert("kTCCServiceScreenCapture", "com.cheat.app")
        self._insert("kTCCServiceAccessibility", "com.cheat.app")
        out = check_tcc(read_tcc(self.conn))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "high")

    def test_single_grant_is_info(self):
        self._insert("kTCCServiceScreenCapture", "com.zoom.app")
        out = check_tcc(read_tcc(self.conn))
        self.assertEqual(out[0].severity, "info")

    def test_denied_grant_ignored(self):
        self._insert("kTCCServiceScreenCapture", "com.a.b", auth_value=0)
        self.assertEqual(check_tcc(read_tcc(self.conn)), [])


def item(pid=10, idx=0, title="", desc="", path="/Applications/X.app/Contents/MacOS/X",
         app="X"):
    return {"pid": pid, "index": idx, "title": title, "desc": desc,
            "path": path, "app": app}


class MenuBarTests(unittest.TestCase):
    def test_impostor_system_wording(self):
        out = check_menu_bar([], [item(desc="Wi-Fi")])
        self.assertEqual(out[0].check, "menu-bar-impostor")
        self.assertEqual(out[0].severity, "high")

    def test_dynamic_value_is_info(self):
        before = [item(title="3")]
        after = [item(title="5")]
        out = check_menu_bar(before, after)
        self.assertEqual(out[0].check, "menu-bar-dynamic")
        self.assertEqual(out[0].severity, "info")
        self.assertIn("3", out[0].subject)

    def test_stable_third_party_item_not_flagged(self):
        self.assertEqual(check_menu_bar([item(title="Sync")], [item(title="Sync")]), [])

    def test_system_app_ignored(self):
        out = check_menu_bar([], [item(desc="Battery",
                                       path="/System/Applications/X.app/Contents/MacOS/X")])
        self.assertEqual(out, [])


class MemoryScanTests(unittest.TestCase):
    def test_finds_token_across_chunk_boundary(self):
        import os
        import tempfile
        from examguard import checks as c
        old = c.MEMORY_CHUNK
        c.MEMORY_CHUNK = 8
        try:
            blob = b"xx" + b"IOHIDSystem" + b"yy"
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(blob)
                name = f.name
            try:
                self.assertEqual(c.scan_memory_file(name), ["IOHIDSystem"])
            finally:
                os.unlink(name)
        finally:
            c.MEMORY_CHUNK = old

    def test_clean_dump(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 100)
            name = f.name
        try:
            self.assertEqual(scan_memory_file(name), [])
        finally:
            os.unlink(name)


class RunAllTests(unittest.TestCase):
    def test_report_aggregates_and_counts_high(self):
        r = run_all(
            windows=[win()],
            procs=[{"pid": 1, "comm": "screencapture"}],
            apps=[{"name": "A", "executable": "/Applications/A.app/x",
                   "symbols": ["CoreBrightness"], "policy": "accessory"}],
            self_pid=999,
        )
        self.assertEqual(r.high_count, 3)
        self.assertEqual(len(r.findings), 4)  # + dockless info
        self.assertEqual(r.as_dict()["summary"], {"high": 3, "total": 4})

    def test_clean_machine(self):
        r = run_all([], [], [], self_pid=1)
        self.assertEqual(r.high_count, 0)
        self.assertEqual(r.findings, [])


if __name__ == "__main__":
    unittest.main()
