import unittest

from examguard.checks import (
    check_dockless, check_private_api, check_processes, check_windows,
    run_all, scan_symbols, is_system_path,
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
