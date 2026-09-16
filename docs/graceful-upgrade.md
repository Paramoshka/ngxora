# Graceful upgrade experiment

This branch exposes stock Pingora 0.9.0 process handoff on Linux. It does **not**
provide a safe automatic replacement for `restart_required` configuration changes.
Routing snapshots and SIGHUP retain their existing behavior.

## Manual handoff

Use a dedicated directory accessible only to the service owner. Both processes
must use the same absolute Unix socket path; its parent must already exist.
Pingora opens this coordination socket in the receiving process.
Relative `--upgrade-sock` paths are rejected by the CLI, including with `--check`.

1. Start the old process with `ngxora --upgrade-sock /run/ngxora/upgrade.sock old.conf`.
2. Validate the new file with `ngxora --check new.conf`.
3. Start the replacement with `ngxora --upgrade --upgrade-sock /run/ngxora/upgrade.sock new.conf`.
4. Once the receiver has opened the coordination socket, send `SIGQUIT` to the
   **old PID**. The receiver waits only about six seconds for the transfer.
5. Check actual traffic on the new process and its administrative endpoints.

The receiver socket's existence and the `Bootstrap done` log are **not** application
readiness acknowledgements. `--check` does not prove that new ports can be bound.
Do not send SIGQUIT if the replacement has already failed.

After transfer, both generations can accept traffic for about five seconds.
The old process then stops accepting and gives existing work a 300-second grace
period, followed by runtime shutdown (up to another five seconds). Old requests
are not migrated to the new process. Connections lasting beyond the grace period
can be interrupted. A protocol change such as HTTP to HTTPS can fail during the
overlap because the old and new acceptors expect different protocols.

Each process reads its own configuration file. In-memory gRPC changes, counters,
rate-limit state and other process-local state are not transferred. The experiment
does not coordinate concurrent control-plane updates or background reconcilers.

## Control-plane handoff

At the start of SIGQUIT upgrade, ngxora closes the old gRPC listener and all its
connections, including incomplete TLS handshakes. It also closes the API on normal
process shutdown. The old HTTP proxy can continue draining existing requests.
An already executing ApplySnapshot may finish; losing its response does not imply
that the update was rolled back.

The replacement retries an occupied gRPC address once per second while running
with `--upgrade`, without an overall timeout. Shutdown cancels this wait. Other
errors stop the API task and are logged; they are not retried. Without `--upgrade`,
an occupied address is reported immediately. The `listening` message is emitted
only after bind succeeds; waiting is logged initially and at most every 30 seconds.

TCP retains mTLS. UDS requires a directory owned by the service UID with owner-only
access (`0700`). Missing directories are created with that mode; existing directory
permissions are never changed automatically. Ancestors must be owned by the service
UID or root and may not be group/other writable unless sticky (e.g. `/tmp`). This
prevents other users from connecting between bind and socket chmod to `0600`, or
replacing the socket directory during ownership checks. A public path such as
`/tmp/control.sock` is rejected; use `/run/ngxora/control.sock` in a private directory.

A neighboring `.lock` file serializes ownership. Leave this lock file in place:
its existence does not mean the API is running, and the OS releases the lock on
process exit. Cooperating processes wait for live listeners; abandoned sockets are
removed on the next bind. Regular files and symlinks at the socket path are rejected.
Both generations need access to the same directory and lock file. Root and processes
with the service UID are trusted and must respect this locking protocol: inode
checks do not provide atomic conditional unlink against those processes.

Temporary API unavailability is expected. The controller must reconnect and send
its latest desired snapshot to the new process, retrying transport failures with
backoff. Existing controller retry behavior is not changed by this implementation.
HTTP `/readyz` still reports configuration/TLS readiness, not gRPC availability.

## Observed boundaries

| Scenario | Behavior |
| --- | --- |
| Existing HTTP/TLS ports, metrics | Listening sockets can be passed to the new process. |
| Added/removed ports and HTTP/TLS replacement | New topology works after handoff; removed sockets must be released. |
| Invalid text configuration before transfer | Replacement exits; old process continues if SIGQUIT is not sent. |
| Missing receiver or receiver killed before/after transfer | Old process still enters shutdown; there is no automatic rollback. |
| New configured port is occupied | The listener service fails after transfer; the old process does not resume accepting. |
| gRPC TCP uses the same address | Old connections are closed; replacement retries until the address becomes available. |
| gRPC UDS uses the same path | Old connections are closed; replacement waits for ownership and binds its own socket. |

The failure tests characterize these limitations deliberately; their passing does
not provide a rollback guarantee for failed process handoff.

## Verification

`cargo test --locked --test graceful_upgrade` runs two/three real ngxora processes
with isolated temporary configs and local sockets. It checks requests held across
handoff (HTTP/1, TLS HTTP/2, WebSocket), continuous HTTP and metrics traffic,
topology changes, controller reconnect and ApplySnapshot, occupied gRPC address
retries and failure cases. One test waits through
the actual default grace period and checks port release after process exit, so the
suite takes approximately five minutes. It is included in `make test-e2e` and CI's
`make test`. Set `NGXORA_TEST_BIN` to run against an extracted image binary.

Before automatic SIGHUP-driven upgrade can be considered, a separate stage must
define application readiness, the accepted failure behavior after socket transfer
and the authoritative configuration source. Automatic process replacement and
controller-side retries are not implemented here.
