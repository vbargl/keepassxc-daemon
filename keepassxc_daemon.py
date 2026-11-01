#!/usr/bin/env python3
"""Read-only local bridge to one unlocked keepassxc-cli interactive session."""
import argparse
import ctypes
import fcntl
import getpass
import json
import os
from pathlib import Path
import re
import resource
import secrets
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

LIMIT = 4 * 1024 * 1024


class BridgeError(Exception):
    pass


class SessionError(BridgeError):
    pass


def protect_process():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Linux: also keep this bridge process out of ordinary ptrace dumps.
    if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) != 0:
        raise BridgeError("Could not disable process dumps")


def argument(value):
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise BridgeError("Expected a nonempty string of at most 4096 characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise BridgeError("Control characters are not allowed in command arguments")
    # KeePassXC's REPL uses its own double-quote/backslash parser, not a shell.
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


class UnlockPassword:
    """Retain the unlock factor in locked memory, and wipe it on shutdown."""
    def __init__(self, password):
        self.value = bytearray(password.encode("utf-8"))
        self.address = None
        self.libc = ctypes.CDLL(None)
        if self.value:
            self.address = ctypes.addressof(ctypes.c_char.from_buffer(self.value))
            if self.libc.mlock(ctypes.c_void_p(self.address), ctypes.c_size_t(len(self.value))) != 0:
                ctypes.memset(self.address, 0, len(self.value))
                raise BridgeError("Could not lock unlock-password memory")

    def close(self):
        if self.address is not None:
            ctypes.memset(self.address, 0, len(self.value))
            self.libc.munlock(ctypes.c_void_p(self.address), ctypes.c_size_t(len(self.value)))
            self.address = None


class Session:
    def __init__(self, database, password, key_file=None, yubikey=None):
        command = ["keepassxc-cli", "open", "-q"]
        if key_file:
            command += ["--key-file", str(key_file)]
        if yubikey:
            command += ["--yubikey", yubikey]
        command += ["--", str(database)]
        self.process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0,
            # Readline otherwise crops echoed commands at the terminal width,
            # even with pipe IO. Keep our bounded requests well below that width.
            env=dict(os.environ, LC_ALL="C", TERM="dumb", COLUMNS="65536", INPUTRC="/dev/null"),
        )
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ, "out")
        self.selector.register(self.process.stderr, selectors.EVENT_READ, "err")
        self.pending = b""
        try:
            encoded = password.encode("utf-8") if isinstance(password, str) else password
            self.process.stdin.write(encoded)
            self.process.stdin.write(b"\n")
            self.process.stdin.flush()
            encoded = None
            password = None
            # Do not send REPL commands until unlocking finishes: the password
            # reader can otherwise buffer them before readline takes over.
            output = b""
            deadline = time.monotonic() + 120
            while not output.endswith(b"> "):
                for stream, data in self.read(deadline):
                    if stream == "out":
                        output += data
                    if len(output) > LIMIT:
                        raise SessionError("Unexpected CLI startup output")
            self.prompt = output
            if len(self.prompt) > 4096:
                raise SessionError("Database prompt is too long")
            self.pending = output
            self.execute("help")  # Validate framing before opening the socket.
        except BaseException:
            self.close()
            raise

    def read(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SessionError("CLI timed out; open the database again")
        events = self.selector.select(remaining)
        if not events:
            raise SessionError("CLI timed out; open the database again")
        chunks = []
        for key, _ in events:
            data = os.read(key.fileobj.fileno(), 65536)
            if not data:
                raise SessionError("CLI exited; check the password and database unlock factors")
            chunks.append((key.data, data))
        return chunks

    def execute(self, command):
        marker = "__keepassxc_boundary_" + secrets.token_hex(24)
        wire = command.encode("utf-8")
        self.process.stdin.write(wire + b"\n" + marker.encode() + b"\n")
        self.process.stdin.flush()
        output, errors = self.pending, b""
        self.pending = b""
        deadline = time.monotonic() + 30
        boundary = marker.encode() + b"\n"
        while boundary not in errors:
            for stream, data in self.read(deadline):
                if stream == "out":
                    output += data
                else:
                    errors += data
            if len(output) + len(errors) > LIMIT:
                raise SessionError("CLI response too large; open the database again")
        # The diagnostic is emitted after stdout has been flushed. Drain stdout
        # until its echoed marker arrives; later prompts stay in pending.
        delimiter = self.prompt + boundary
        while delimiter not in output:
            for stream, data in self.read(deadline):
                if stream == "out":
                    output += data
            if len(output) > LIMIT:
                raise SessionError("CLI response too large; open the database again")
        payload, self.pending = output.split(delimiter, 1)
        prefix = self.prompt + wire + b"\n"
        if not payload.startswith(prefix):
            raise SessionError("CLI framing changed; open the database again")
        # Only the deliberately unknown marker command may produce a diagnostic.
        diagnostics = [line for line in errors.splitlines() if line and marker.encode() not in line]
        if command.startswith("search -- ") and diagnostics == [b"No results for that search term."]:
            return ""
        if diagnostics:
            raise BridgeError("CLI request failed; check the entry path or attribute")
        return payload[len(prefix):].decode("utf-8").removesuffix("\n")

    def close(self):
        try:
            if self.process.poll() is None:
                self.process.stdin.write(b"exit\n")
                self.process.stdin.flush()
                self.process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        finally:
            self.selector.close()
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()


class ReloadingSession:
    def __init__(self, database, password, key_file=None, yubikey=None):
        self.database = database.absolute()
        self.password = UnlockPassword(password)
        self.key_file = key_file
        self.yubikey = yubikey
        self.session = None
        self.loaded_fingerprint = None
        self.failed_fingerprint = None
        self.reload_count = 0
        self.reload_error = None
        try:
            self.refresh(force=True)
            if self.reload_error:
                raise BridgeError(self.reload_error)
        except BaseException:
            self.close()
            raise

    @property
    def process(self):
        return self.session.process

    def fingerprint(self):
        info = self.database.stat()
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def refresh(self, force=False):
        try:
            fingerprint = self.fingerprint()
        except OSError:
            self.reload_error = "Database unavailable; reads paused until it can be reloaded"
            return False
        if not force:
            if fingerprint == self.loaded_fingerprint and self.reload_error is None:
                return False
            if fingerprint == self.failed_fingerprint:
                return False
        self.failed_fingerprint = fingerprint
        candidate = None
        if self.session is not None:
            print("Reloading database from disk.", flush=True)
        try:
            candidate = Session(self.database, self.password.value, self.key_file, self.yubikey)
            if self.fingerprint() != fingerprint:
                raise BridgeError("Database changed during reload")
        except BaseException as error:
            if candidate is not None:
                candidate.close()
            if not isinstance(error, (BridgeError, OSError, ValueError)):
                raise
            self.reload_error = "Database reload failed; reads paused. Retry reload after saving, or use open if unlock factors changed"
            return False
        previous = self.session
        self.session = candidate
        self.loaded_fingerprint = fingerprint
        self.failed_fingerprint = None
        self.reload_error = None
        if previous is not None:
            self.reload_count += 1
            previous.close()
            print("Database reloaded.", flush=True)
        return True

    def execute(self, command):
        self.refresh()
        if self.reload_error:
            raise BridgeError(self.reload_error)
        return self.session.execute(command)

    def status(self):
        return {
            "database_open": True,
            "unlocked": self.reload_error is None,
            "pid": os.getpid(),
            "cli_pid": self.process.pid,
            "auto_reload": True,
            "reload_count": self.reload_count,
            "reload_error": self.reload_error,
        }

    def close(self):
        try:
            if self.session is not None:
                self.session.close()
        finally:
            self.password.close()


def default_socket():
    return Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "keepassxc-daemon" / "cli.sock"


def exchange(path, request):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(150)
        connection.connect(str(path))
        with connection.makefile("rwb") as stream:
            stream.write(json.dumps(request).encode() + b"\n")
            stream.flush()
            raw = stream.readline(LIMIT + 1)
    if not raw.endswith(b"\n") or len(raw) > LIMIT:
        raise BridgeError("Invalid daemon response")
    response = json.loads(raw)
    if not response.get("ok"):
        raise BridgeError(response.get("error", "Daemon request failed"))
    return response


def open_request(request):
    """Validate opening parameters without echoing secret input in errors."""
    database = request.get("database")
    argument(database)
    database = Path(database)
    if not database.is_absolute() or not database.is_file():
        raise BridgeError("Database must be an existing absolute file path")
    key_file = request.get("key_file")
    if key_file is not None:
        argument(key_file)
        key_file = Path(key_file)
        if not key_file.is_absolute() or not key_file.is_file():
            raise BridgeError("Key file must be an existing absolute file path")
    yubikey = request.get("yubikey")
    if yubikey is not None:
        argument(yubikey)
    password = request.pop("password", None)
    if not isinstance(password, str) or len(password) > 4096 or any(c in password for c in "\r\n"):
        raise BridgeError("Expected a single-line unlock password")
    return ReloadingSession(database, password, key_file, yubikey)


def serve(args):
    os.umask(0o077)
    directory = args.socket.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise BridgeError("Socket directory must belong to you and have mode 0700")
    lock = os.open(directory / "daemon.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock)
        raise BridgeError("A daemon is already using this socket directory") from None
    session = None
    bound = False
    listener = socket.socket(socket.AF_UNIX)
    try:
        if args.socket.exists() or args.socket.is_symlink():
            info = args.socket.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                raise BridgeError("Refusing to replace a non-socket or another user's socket")
            args.socket.unlink()
        listener.bind(str(args.socket))
        bound = True
        os.chmod(args.socket, 0o600)
        listener.listen(4)
        listener.settimeout(1)
        print(f"Ready: {args.socket}\nUse open to unlock a database from another terminal.", flush=True)
        running = True
        while running:
            if session is not None:
                session.refresh()
                if session.process.poll() is not None:
                    session.close()
                    session = None
                    print("Database session closed. Use open to unlock it again.", flush=True)
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(5)
                peer = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                if struct.unpack("3i", peer)[1] != os.getuid():
                    continue
                with connection.makefile("rwb") as stream:
                    try:
                        raw = stream.readline(65537)
                        if len(raw) > 65536 or not raw.endswith(b"\n"):
                            raise BridgeError("Invalid request")
                        request = json.loads(raw)
                        raw = None
                        operation = request.get("op")
                        if session is not None and session.process.poll() is not None:
                            session.close()
                            session = None
                        if operation == "open":
                            candidate = open_request(request)
                            previous = session
                            session = candidate
                            if previous is not None:
                                previous.close()
                            print("Database opened.", flush=True)
                            response = {"opened": True, **session.status()}
                        elif operation == "status":
                            if session is None:
                                response = {
                                    "database_open": False, "unlocked": False,
                                    "pid": os.getpid(), "cli_pid": None,
                                    "auto_reload": True, "reload_count": 0, "reload_error": None,
                                }
                            else:
                                session.refresh()
                                response = session.status()
                        elif operation == "stop":
                            response = {"stopped": True}
                            running = False
                        elif operation not in {"reload", "search", "get"}:
                            raise BridgeError("Unsupported operation")
                        elif session is None:
                            raise BridgeError("No database is open; use the open command first")
                        elif operation == "reload":
                            session.refresh(force=True)
                            if session.reload_error:
                                raise BridgeError(session.reload_error)
                            response = {"reloaded": True, **session.status()}
                        elif operation == "search":
                            query = argument(request.get("query"))
                            result = session.execute("search -- " + query)
                            response = {"entries": result.splitlines() if result else []}
                        elif operation == "get":
                            entry = argument(request.get("entry"))
                            attribute = argument(request.get("attribute", "Password"))
                            response = {"value": session.execute("show -s -a " + attribute + " -- " + entry)}
                        response["ok"] = True
                    except SessionError as error:
                        response = {"ok": False, "error": str(error)}
                        if session is not None:
                            session.close()
                            session = None
                    except BridgeError as error:
                        response = {"ok": False, "error": str(error)}
                    except (ValueError, AttributeError, TypeError, OSError):
                        response = {"ok": False, "error": "Invalid request or disconnected CLI"}
                    finally:
                        raw = None
                        request = None
                    try:
                        stream.write(json.dumps(response).encode() + b"\n")
                        stream.flush()
                    except OSError:
                        pass
                    response = None
    finally:
        listener.close()
        if bound:
            args.socket.unlink(missing_ok=True)
        if session:
            session.close()
        os.close(lock)


def main():
    protect_process()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, default=default_socket())
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("serve", help="Serve without a database or terminal input")
    opening = commands.add_parser("open", help="Unlock a database on the running daemon")
    opening.add_argument("database", type=Path)
    opening.add_argument("--key-file", type=Path)
    opening.add_argument("--yubikey", help="KeePassXC YubiKey slot[:serial]")
    commands.add_parser("status", help="Check connection without reading an entry")
    commands.add_parser("reload", help="Reload the saved database using the in-memory unlock password")
    search = commands.add_parser("search", help="Search entries; output paths/titles only")
    search.add_argument("query")
    run = commands.add_parser("run", help="Pass a selected field to a child process environment")
    run.add_argument("--entry", required=True)
    run.add_argument("--attribute", default="Password")
    run.add_argument("--env", required=True, dest="variable")
    run.add_argument("command", nargs=argparse.REMAINDER)
    commands.add_parser("stop", help="Close the unlocked session and remove its socket")
    args = parser.parse_args()
    if args.operation == "serve":
        def interrupted(*_):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, interrupted)
        # Preserve nohup's inherited SIGHUP ignore when launched in the background.
        if signal.getsignal(signal.SIGHUP) != signal.SIG_IGN:
            signal.signal(signal.SIGHUP, interrupted)
        serve(args)
    elif args.operation == "open":
        if not sys.stdin.isatty():
            raise BridgeError("Run open in a terminal to enter the password privately")
        database = args.database.expanduser().absolute()
        key_file = args.key_file.expanduser().absolute() if args.key_file else None
        if not database.is_file() or (key_file is not None and not key_file.is_file()):
            raise BridgeError("Database or key file does not exist")
        status = exchange(args.socket, {"op": "status"})
        if "database_open" not in status:
            parser.error("The running daemon needs upgrading; restart it with serve before using open")
        password = getpass.getpass("Database password (hidden): ")
        request = {
            "op": "open", "database": str(database), "password": password,
            "key_file": str(key_file) if key_file else None, "yubikey": args.yubikey,
        }
        password = None
        try:
            response = exchange(args.socket, request)
        finally:
            request.clear()
        print(json.dumps(response))
    elif args.operation == "run":
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not command or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.variable):
            raise BridgeError("Specify a valid environment variable and a command after --")
        response = exchange(args.socket, {"op": "get", "entry": args.entry, "attribute": args.attribute})
        value = response.pop("value")
        environment = dict(os.environ)
        environment[args.variable] = value
        value = None
        result = subprocess.run(command, env=environment)
        environment.pop(args.variable, None)
        return result.returncode
    else:
        request = {"op": args.operation}
        if args.operation == "search":
            request["query"] = args.query
        print(json.dumps(exchange(args.socket, request), ensure_ascii=False))
    return 0


def cli():
    try:
        return main()
    except KeyboardInterrupt:
        return 0
    except (BridgeError, OSError, ValueError):
        # Never print exception payloads from requests, CLI output, or secrets.
        print("KeePassXC bridge failed. Check the socket, database, unlock factors, and command arguments.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(cli())
