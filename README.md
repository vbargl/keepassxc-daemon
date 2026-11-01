# keepassxc-daemon

A read-only Linux daemon that keeps one `keepassxc-cli` session unlocked and makes
it available over a private Unix socket. Start the server without a database or
terminal input, then unlock a database from a separate terminal client. Subsequent
requests can search entry titles or pass a selected field directly to a process.

Saved database changes reload automatically. The daemon checks the file every
second while idle and before reading an entry. It handles both normal saves and
atomic file replacements, and has a manual `reload` command.

## Requirements

- Linux, Python 3.11 or later, and `keepassxc-cli` on `PATH`.
- A password-protected KeePass database; optional key-file and YubiKey factors are
  forwarded to the CLI. Passwordless databases are not supported.

There are no third-party Python runtime dependencies. The integration tests use
disposable encrypted databases and have been run with KeePassXC CLI 2.7.12.

This is an independent wrapper, not an official KeePassXC component.

## Install

Install with `pipx`:

```sh
pipx install git+https://github.com/vbargl/keepassxc-daemon.git
```

Or run the source directly:

```sh
git clone https://github.com/vbargl/keepassxc-daemon.git
cd keepassxc-daemon
python3 keepassxc_daemon.py --help
```

For the commands below, substitute `python3 keepassxc_daemon.py` for
`keepassxc-daemon` when running from source.

## Start the server

Run as your normal user, in the foreground or under a user service manager:

```sh
keepassxc-daemon serve
```

`serve` takes no database argument, never prompts, and does not read stdin. Once
it prints `Ready:`, the private socket is listening. Initially no database is open.
It stays running after an `open` client disconnects or a CLI database session exits.

For a shell background launch that survives terminal hangup:

```sh
nohup keepassxc-daemon serve </dev/null >/dev/null 2>&1 &
```

It can also run as a `systemd --user` service whose `ExecStart` invokes
`keepassxc-daemon serve`. Database selection and unlocking belong in the client,
not the service unit or its environment.

## Open a database

In another terminal:

```sh
keepassxc-daemon open "/path/to/database.kdbx"
```

Enter the database password at the hidden prompt in this client terminal. The
client sends it to the running server through the private Unix socket and exits
after opening succeeds. All later requests reuse the server's unlocked session.
Relative database and key-file paths are resolved in the client's working directory.

For additional unlock factors:

```sh
keepassxc-daemon open "/path/to/database.kdbx" --key-file "/path/to/keyfile"
keepassxc-daemon open "/path/to/database.kdbx" --yubikey 1
```

One database is open at a time. Another `open` replaces the existing session only
after the new database unlocks successfully. A failed `open` leaves an existing
session in place. After a backend session exits, use `open` again; the server does
not need restarting.

The master password is retained in a memory-locked buffer for automatic reloads.
It travels from client to server over the Unix socket, then to each CLI session
through an anonymous pipe. It is never saved in a file, log, environment variable,
or command argument. The retained buffer is zeroed on shutdown or when replacing
the open database. Core dumps are disabled and ordinary process dumps are disabled.

## Search and status

From another terminal:

```sh
keepassxc-daemon status
keepassxc-daemon search alza
keepassxc-daemon search '*'
```

Search accepts KeePassXC search syntax and returns entry paths/titles, including
non-web entries. It prints no password values. No matches produces an empty list.

`status` reads no entries. Its JSON response includes `database_open`, `unlocked`,
`auto_reload`, `reload_count`, `reload_error`, and the daemon and CLI process IDs.
Before `open`, `database_open` and `unlocked` are false and `cli_pid` is null.
Search, secret reads and reload require an open database. The daemon process ID
stays the same across opens and reloads; the CLI process ID changes.

## Reload saved changes

Automatic reload is enabled by default. To force a refresh even when the file's
metadata is unchanged:

```sh
keepassxc-daemon reload
```

A replacement session must unlock successfully and read a file whose metadata
remains stable during loading before it can replace the previous session.
If loading fails, the old snapshot is not served: searches and secret reads pause,
and `status` reports `unlocked: false` with a `reload_error`. The daemon retries
after another file change, or when explicitly asked to reload.

If you change the database password or required unlock factors, use `open` again
to enter the new factors. Hardware that requires touch confirmation
may require another touch during a reload. The bridge itself never writes the
database and never changes its unlock factors.

## Use one selected secret

There is no client command that prints a secret. `run` retrieves one field and
passes it to the environment of a child process:

```sh
keepassxc-daemon run --entry "/Servers/example" --env SERVICE_PASSWORD -- your-command
```

Replace the entry, variable name and command with the intended operation. The
default field is `Password`; select another field with `--attribute "Custom field"`.
Use a child command that consumes the value without printing or recording it.
The bridge does not fetch any field until requested. Attachment exports and
database edits are not exposed by this wrapper.

## Stop

Press Ctrl+C in the server terminal, or run:

```sh
keepassxc-daemon stop
```

The server exits any open CLI session, reaps the process, wipes its retained unlock
password, and removes the socket. After starting the server again, use `open` to
unlock a database. `stop` also works before any database has been opened.

The daemon has an independent unlocked session: locking KeePassXC Desktop does
not lock this daemon. SSH agent integration, browser integration, Secret Service,
Auto-Type, and remote sync remain desktop app responsibilities.

## Local API

The default socket is `$XDG_RUNTIME_DIR/keepassxc-daemon/cli.sock`, falling back to
`/run/user/<uid>/keepassxc-daemon/cli.sock`. The directory is mode 0700, the socket is
mode 0600, and peer UID checks restrict access to the same Unix user. There is no
TCP listener. The empty `daemon.lock` file holds a lock and contains no secrets.

To override the socket, place `--socket PATH` before the subcommand on both sides.
Its directory must belong to you with mode 0700.

Send one JSON request per connection, terminated by a newline:

```json
{"op":"status"}
{"op":"open","database":"/absolute/path/database.kdbx","password":"<provided privately by the client>"}
{"op":"search","query":"router"}
{"op":"get","entry":"/Servers/example","attribute":"Password"}
{"op":"reload"}
{"op":"stop"}
```

Responses have `ok: true` and operation-specific fields, or `ok: false` and an
`error`. `open` returns `opened` and the status fields; it accepts optional
`key_file` (an absolute path) and `yubikey`. Do not put real `open` requests in chat
or logs. `search` returns `entries`; `get` returns `value`; `reload` returns
`reloaded` and the status fields. `get` sends the selected secret over the private
socket to the calling program. Do not put raw `get` responses in chat or logs.

The API exposes these operations only, not arbitrary CLI commands. Requests are
serialized. Control characters in command arguments are rejected. Framing errors
and timeouts during entry reads close the database session rather than reuse an
uncertain CLI stream; the server stays available for another `open`. Reload errors
pause reads while allowing status, retry, open and stop.

Any process running as your Unix user can use this socket. Isolation is between
Unix users, not between applications sharing the same user account.

## Development

```sh
python3 -m unittest -v
```

Tests create disposable encrypted databases with generated fixture credentials.
They cover persistent access, quoting and framing, secret injection into a child,
local permissions, invalid requests, cleanup, saved edits, atomic replacement,
manual reload, reload races, missing/corrupt databases, changed unlock factors,
password-buffer wiping, startup without a terminal/database, separate interactive
opens, database replacement, failed opens and surviving terminal hangup under
`nohup`. They do not open your real database or print fixture passwords.

Licensed under MIT; see [LICENSE](LICENSE).
