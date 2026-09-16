# Graceful upgrade experiment

This branch exposes stock Pingora 0.9.0 process handoff on Linux. It does **not**
provide a safe automatic replacement for `restart_required` configuration changes.
Routing snapshots and SIGHUP retain their existing behavior.

## Manual handoff

Use a dedicated directory accessible only to the service owner. Both processes
must use the same absolute Unix socket path; its parent must already exist.
Pingora opens this coordination socket in the receiving process.

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

## Observed boundaries

| Scenario | Behavior |
| --- | --- |
| Existing HTTP/TLS ports, metrics | Listening sockets can be passed to the new process. |
| Added/removed ports and HTTP/TLS replacement | New topology works after handoff; removed sockets must be released. |
| Invalid text configuration before transfer | Replacement exits; old process continues if SIGQUIT is not sent. |
| Missing receiver or receiver killed before/after transfer | Old process still enters shutdown; there is no automatic rollback. |
| New configured port is occupied | The listener service fails after transfer; the old process does not resume accepting. |
| gRPC TCP uses the same address | Replacement control plane fails to bind, while its HTTP proxy can still serve traffic. |
| gRPC UDS uses the same path | New process replaces the socket path; existing controller channels remain attached to the old process. |

The failure tests characterize these limitations deliberately; their passing does
not certify production-safe reload. Keep the previous listener-lifecycle
experiment saved until a replacement meets the required failure guarantees.

## Verification

`cargo test --locked --test graceful_upgrade` runs two/three real ngxora processes
with isolated temporary configs and local sockets. It checks requests held across
handoff (HTTP/1, TLS HTTP/2, WebSocket), continuous HTTP and metrics traffic,
topology changes, control-plane behavior and failure cases. One test waits through
the actual default grace period and checks port release after process exit, so the
suite takes approximately five minutes. It is included in `make test-e2e` and CI's
`make test`. Set `NGXORA_TEST_BIN` to run against an extracted image binary.

Before automatic SIGHUP-driven upgrade can be considered, a separate stage must
solve application readiness, failure handling after socket transfer, control-plane
handoff and the authoritative configuration source. These are not implemented here.
