# Security Dependency Updates

## Goal

Remove the actionable Go and Rust findings from the supplied vulnerability
report with the smallest compatible dependency update, and enable Dependabot
to keep the repository current.

## Scope

- Update the Go SDK toolchain declaration from Go 1.26.3 to the security-fixed
  Go 1.26.6 release.
- Update vulnerable Go modules (`google.golang.org/grpc`, `golang.org/x/net`,
  `golang.org/x/text`, `golang.org/x/sys`, and OpenTelemetry) to current
  compatible releases at or above the fixed versions from the report. Allow
  `go mod tidy` to update their required indirect dependencies.
- Update the Rust lockfile to `time` 0.3.47 or newer within 0.3 and
  `quinn-proto` 0.11.15 or newer within 0.11.
- Add weekly Dependabot checks for Cargo, the Go SDK, Docker, and GitHub
  Actions.
- Exclude the ignored `sdk/go/bin/` generator binaries from the Docker build
  context.

## Important Finding

The reported `stdlib go1.25.7` is not selected by `sdk/go/go.mod`, which already
declares Go 1.26.3. It comes from the ignored local binaries
`sdk/go/bin/protoc-gen-go` and `sdk/go/bin/protoc-gen-go-grpc`, both built with
the host's Go 1.25.7. They are not copied into the final scratch image, but the
directory is currently present in the Docker build context and can be found by
a local directory scan. Adding it to `.dockerignore` prevents that accidental
input; local directory scans must also exclude ignored build tools or rebuild
them with Go 1.26.6.

## Non-goals

- Do not perform a broad update of unrelated minor or major dependencies.
- Do not upgrade Pingora solely to remove Rust `protobuf` 2.28.0.
- Do not commit generated SDK tool binaries from `sdk/go/bin/`.

Rust `protobuf` 2.28.0 remains covered by the existing Grype VEX entry. It is
pulled through Pingora's Prometheus stack, where ngxora only serializes its own
metrics and does not parse untrusted protobuf payloads. Updating ngxora's
direct Prometheus dependency alone would not remove Pingora's copy.

## Dependabot Configuration

Create `.github/dependabot.yml` with weekly update checks for:

- Cargo at `/`;
- Go modules at `/sdk/go`;
- Docker at `/`;
- GitHub Actions at `/`.

Keep the configuration simple and let each ecosystem create its normal update
PRs. Major updates remain visible for explicit review rather than being
silently ignored or automatically merged.

## Verification

1. Run `go mod tidy` and `go test ./...` in `sdk/go` with Go 1.26.6.
2. Run the Rust workspace tests with the repository's Rust toolchain.
3. Confirm the resolved versions in `go.mod`, `go.sum`, and `Cargo.lock` meet
   every fixed-version floor in the supplied report.
4. Run formatting and diff checks.
5. Build and rescan the container image when Docker and Grype are available.

If the local machine cannot obtain Go 1.26.6, use Go's toolchain download
support for the SDK checks and report any environment limitation explicitly.
