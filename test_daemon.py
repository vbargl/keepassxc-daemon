"""Integration tests using only disposable, encrypted fixture databases."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pty
import secrets
import selectors
import signal
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("keepassxc_daemon.py")
spec = importlib.util.spec_from_file_location("bridge", SCRIPT)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class DaemonTest(unittest.TestCase):
    def create_database(self, path, password):
        result = subprocess.run(
            ["keepassxc-cli", "db-create", "-p", "-t", "100", str(path)],
            input=(password + "\n" + password + "\n").encode(), capture_output=True,
        )
        self.assertEqual(result.returncode, 0, "fixture creation failed")

    def set_entry(self, path, password, entry, value, operation="add"):
        result = subprocess.run(
            ["keepassxc-cli", operation, "-p", str(path), entry],
            input=(password + "\n" + value + "\n").encode(), capture_output=True,
        )
        self.assertEqual(result.returncode, 0, "fixture update failed")

    def wait_for(self, terminal, process, token):
        output = b""
        selector = selectors.DefaultSelector()
        selector.register(terminal, selectors.EVENT_READ)
        deadline = time.monotonic() + 15
        try:
            while token not in output:
                self.assertLess(time.monotonic(), deadline, "daemon startup timed out")
                if selector.select(.1):
                    try:
                        output += os.read(terminal, 65536)
                    except OSError:
                        self.fail("daemon exited during startup")
                self.assertIsNone(process.poll(), "daemon exited during startup")
        finally:
            selector.close()

    def launch(self, database, path, password):
        master, slave = pty.openpty()
        process = subprocess.Popen(
            [sys.executable, str(SCRIPT), "--socket", str(path), "serve", str(database)],
            stdin=slave, stdout=slave, stderr=slave,
        )
        os.close(slave)
        try:
            self.wait_for(master, process, b"Database password (hidden): ")
            os.write(master, password.encode() + b"\n")
            self.wait_for(master, process, b"Ready: ")
        except BaseException:
            process.terminate()
            process.wait(timeout=5)
            os.close(master)
            raise
        return process, master

    def test_end_to_end(self):
        with tempfile.TemporaryDirectory(prefix="keepassxc-daemon-test-") as directory:
            root = Path(directory)
            database = root / 'test "quoted" db.kdbx'
            path = root / "runtime" / "cli.sock"
            password = secrets.token_urlsafe(32)
            secret = secrets.token_urlsafe(32) + ' "quoted" \\ tail'
            entry = 'Wi-Fi "office" \\ laptop'
            created = subprocess.run(
                ["keepassxc-cli", "db-create", "-p", "-t", "100", str(database)],
                input=(password + "\n" + password + "\n").encode(), capture_output=True,
            )
            self.assertEqual(created.returncode, 0, "fixture database creation failed")
            added = subprocess.run(
                ["keepassxc-cli", "add", "-p", str(database), entry],
                input=(password + "\n" + secret + "\n").encode(), capture_output=True,
            )
            self.assertEqual(added.returncode, 0, "fixture entry creation failed")
            process, terminal = self.launch(database, path, password)
            cli_pid = None
            try:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
                first = bridge.exchange(path, {"op": "status"})
                cli_pid = first["cli_pid"]
                self.assertTrue(first["unlocked"])
                self.assertEqual(first["pid"], process.pid)

                result = bridge.exchange(path, {"op": "search", "query": "Wi-Fi"})
                self.assertEqual(result["entries"], ["/" + entry])
                self.assertNotIn(secret, json.dumps(result))
                self.assertEqual(bridge.exchange(path, {"op": "search", "query": "absent"})["entries"], [])
                self.assertEqual(bridge.exchange(path, {"op": "search", "query": "x" * 2000})["entries"], [])

                # Secret values are checked in memory, never printed by the test.
                fetched = bridge.exchange(path, {"op": "get", "entry": "/" + entry})
                self.assertTrue(fetched["value"] == secret, "secret transport changed the value")
                for _ in range(5):
                    self.assertTrue(bridge.exchange(path, {"op": "get", "entry": entry})["value"] == secret)
                with self.assertRaises(bridge.BridgeError):
                    bridge.exchange(path, {"op": "get", "entry": entry, "attribute": "NonexistentField"})
                with self.assertRaises(bridge.BridgeError):
                    bridge.exchange(path, {"op": "get", "entry": "nonexistent"})
                with self.assertRaises(bridge.BridgeError):
                    bridge.exchange(path, {"op": "search", "query": "Wi-Fi\nrm Wi-Fi"})
                with self.assertRaises(bridge.BridgeError):
                    bridge.exchange(path, {"op": "execute", "command": "rm anything"})

                digest = hashlib.sha256(secret.encode()).hexdigest()
                child_code = (
                    "import os,hashlib; "
                    "assert hashlib.sha256(os.environ['FIXTURE_PASSWORD'].encode()).hexdigest()=="
                    + repr(digest) + "; print('consumed without printing the secret')"
                )
                ran = subprocess.run(
                    [sys.executable, str(SCRIPT), "--socket", str(path), "run",
                     "--entry", entry, "--env", "FIXTURE_PASSWORD", "--",
                     sys.executable, "-c", child_code], capture_output=True,
                )
                self.assertEqual(ran.returncode, 0, "secret injection into child failed")
                self.assertEqual(ran.stdout.strip(), b"consumed without printing the secret")
                self.assertNotIn(secret.encode(), ran.stdout + ran.stderr)
                self.assertEqual(bridge.exchange(path, {"op": "status"})["cli_pid"], cli_pid)

                second = subprocess.run(
                    [sys.executable, str(SCRIPT), "--socket", str(path), "serve", str(database)],
                    stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
                )
                self.assertEqual(second.returncode, 1)
                self.assertEqual(bridge.exchange(path, {"op": "status"})["pid"], process.pid)

                # Malformed and oversized requests must not disrupt the session.
                for request in (b"not-json\n", b"[]\n", b"x" * 65537):
                    with socket.socket(socket.AF_UNIX) as connection:
                        connection.settimeout(5)
                        connection.connect(str(path))
                        connection.sendall(request)
                        try:
                            connection.recv(4096)
                        except ConnectionResetError:
                            pass
                self.assertEqual(bridge.exchange(path, {"op": "status"})["cli_pid"], cli_pid)
                bridge.exchange(path, {"op": "stop"})
                self.assertEqual(process.wait(timeout=5), 0)
                self.assertFalse(path.exists())
                with self.assertRaises(ProcessLookupError):
                    os.kill(cli_pid, 0)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
                os.close(terminal)

            # Restart needs another unlock, then supports reads without per-read passwords.
            process, terminal = self.launch(database, path, password)
            try:
                self.assertEqual(bridge.exchange(path, {"op": "search", "query": "Wi-Fi"})["entries"], ["/" + entry])
                process.send_signal(signal.SIGHUP)
                self.assertEqual(process.wait(timeout=5), 0)
                self.assertFalse(path.exists())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                os.close(terminal)

            with self.assertRaises(bridge.SessionError):
                bridge.Session(database, secrets.token_urlsafe(32))
            self.assertFalse(path.exists())

    def test_reload_saved_edits_replacement_and_failures(self):
        with tempfile.TemporaryDirectory(prefix="keepassxc-daemon-test-") as directory:
            root = Path(directory)
            database, path = root / "database.kdbx", root / "runtime" / "cli.sock"
            password, first, updated = (secrets.token_urlsafe(32) for _ in range(3))
            self.create_database(database, password)
            self.set_entry(database, password, "Router", first)
            process, terminal = self.launch(database, path, password)
            try:
                original = bridge.exchange(path, {"op": "status"})
                self.assertTrue(original["auto_reload"])
                self.assertTrue(bridge.exchange(path, {"op": "get", "entry": "Router"})["value"] == first)

                # A save by another CLI/GUI process must be visible on the next read.
                self.set_entry(database, password, "Router", updated, operation="edit")
                self.assertTrue(bridge.exchange(path, {"op": "get", "entry": "Router"})["value"] == updated)
                changed = bridge.exchange(path, {"op": "status"})
                self.assertEqual(changed["pid"], original["pid"])
                self.assertNotEqual(changed["cli_pid"], original["cli_pid"])
                self.assertGreater(changed["reload_count"], original["reload_count"])
                with self.assertRaises(ProcessLookupError):
                    os.kill(original["cli_pid"], 0)

                # Clear prior lifecycle output, then require an automatic reload
                # without sending any client request after an atomic replacement.
                selector = selectors.DefaultSelector()
                selector.register(terminal, selectors.EVENT_READ)
                while selector.select(0):
                    os.read(terminal, 65536)
                selector.close()
                replacement = root / "replacement.kdbx"
                shutil.copyfile(database, replacement)
                self.set_entry(replacement, password, "New entry", secrets.token_urlsafe(32))
                os.replace(replacement, database)
                self.wait_for(terminal, process, b"Database reloaded.")
                self.assertEqual(bridge.exchange(path, {"op": "search", "query": "New entry"})["entries"], ["/New entry"])

                before = bridge.exchange(path, {"op": "status"})
                manual = subprocess.run(
                    [sys.executable, str(SCRIPT), "--socket", str(path), "reload"],
                    capture_output=True, timeout=15,
                )
                self.assertEqual(manual.returncode, 0)
                after = json.loads(manual.stdout)
                self.assertTrue(after["reloaded"])
                self.assertEqual(after["reload_count"], before["reload_count"] + 1)

                saved_ciphertext = database.read_bytes()
                database.write_bytes(b"invalid database fixture")
                for _ in range(2):
                    with self.assertRaises(bridge.BridgeError):
                        bridge.exchange(path, {"op": "get", "entry": "Router"})
                failed = bridge.exchange(path, {"op": "status"})
                self.assertFalse(failed["unlocked"])
                self.assertTrue(failed["reload_error"])
                self.assertEqual(failed["reload_count"], after["reload_count"])
                # Retry explicitly also fails closed, without ending the daemon.
                with self.assertRaises(bridge.BridgeError):
                    bridge.exchange(path, {"op": "reload"})
                database.write_bytes(saved_ciphertext)
                self.assertTrue(bridge.exchange(path, {"op": "get", "entry": "Router"})["value"] == updated)
                self.assertTrue(bridge.exchange(path, {"op": "status"})["unlocked"])

                hidden = root / "temporarily-moved.kdbx"
                database.rename(hidden)
                with self.assertRaises(bridge.BridgeError):
                    bridge.exchange(path, {"op": "search", "query": "Router"})
                self.assertFalse(bridge.exchange(path, {"op": "status"})["unlocked"])
                hidden.rename(database)
                self.assertEqual(bridge.exchange(path, {"op": "search", "query": "Router"})["entries"], ["/Router"])

                # Changed unlock factors must not fall back to old credentials.
                self.create_database(replacement, secrets.token_urlsafe(32))
                os.replace(replacement, database)
                with self.assertRaises(bridge.BridgeError):
                    bridge.exchange(path, {"op": "get", "entry": "Router"})
                self.assertFalse(bridge.exchange(path, {"op": "status"})["unlocked"])
                bridge.exchange(path, {"op": "stop"})
                self.assertEqual(process.wait(timeout=5), 0)
                self.assertFalse(path.exists())
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
                os.close(terminal)

    def test_unlock_password_is_wiped(self):
        password = bridge.UnlockPassword(secrets.token_urlsafe(32))
        retained_buffer = password.value
        self.assertTrue(any(retained_buffer))
        password.close()
        self.assertFalse(any(retained_buffer))
        self.assertIsNone(password.address)

    def test_database_change_during_reload_closes_candidate(self):
        with tempfile.TemporaryDirectory(prefix="keepassxc-daemon-test-") as directory:
            database = Path(directory) / "database.kdbx"
            password = secrets.token_urlsafe(32)
            self.create_database(database, password)
            with redirect_stdout(io.StringIO()):
                manager = bridge.ReloadingSession(database, password)
                original_pid = manager.process.pid
                candidates = []
                session_class = bridge.Session

                def racing_session(*args):
                    candidate = session_class(*args)
                    candidates.append(candidate)
                    info = database.stat()
                    os.utime(database, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000))
                    return candidate

                try:
                    with patch.object(bridge, "Session", side_effect=racing_session):
                        self.assertFalse(manager.refresh(force=True))
                    self.assertTrue(manager.reload_error)
                    self.assertEqual(manager.process.pid, original_pid)
                    self.assertIsNotNone(candidates[0].process.poll())
                    self.assertTrue(manager.refresh())
                    self.assertIsNone(manager.reload_error)
                finally:
                    manager.close()


if __name__ == "__main__":
    unittest.main()
