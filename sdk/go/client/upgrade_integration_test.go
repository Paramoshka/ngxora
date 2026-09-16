//go:build integration && linux

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	controlv1 "github.com/paramoshka/ngxora/sdk/go/ngxora/control/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type ngxoraProcess struct {
	cmd     *exec.Cmd
	logPath string
	done    <-chan struct{}
}

func startNgxora(t *testing.T, binary, dir, name, config string, upgrade bool) *ngxoraProcess {
	t.Helper()
	configPath := filepath.Join(dir, name+".conf")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, name+".log")
	output, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--grpc-uds", filepath.Join(dir, "control.sock"), "--upgrade-sock", filepath.Join(dir, "upgrade.sock")}
	if upgrade {
		args = append(args, "--upgrade")
	}
	args = append(args, configPath)
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(), "RUST_LOG=info")
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		if closeErr := output.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(done) }()
	p := &ngxoraProcess{cmd: cmd, logPath: logPath, done: done}
	t.Cleanup(func() {
		select {
		case <-done:
			if waitErr != nil {
				t.Errorf("ngxora exited unexpectedly: %v", waitErr)
			}
		default:
			if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Error(err)
			}
			<-done
		}
		if err := output.Close(); err != nil {
			t.Error(err)
		}
		if t.Failed() {
			t.Log(p.logs(t))
		}
	})
	return p
}

func (p *ngxoraProcess) logs(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(p.logPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 16384 {
		return string(data[:4096]) + "\n... [log truncated] ...\n" + string(data[len(data)-12288:])
	}
	return string(data)
}

func (p *ngxoraProcess) wait(t *testing.T, description string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-p.done:
			t.Fatalf("ngxora exited while waiting for %s:\n%s", description, p.logs(t))
		default:
		}
		if check() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s:\n%s", description, p.logs(t))
}

func TestGracefulUpgradeRestoresDesiredSnapshot(t *testing.T) {
	binary := os.Getenv("NGXORA_TEST_BIN")
	if binary == "" {
		t.Fatal("integration test requires NGXORA_TEST_BIN; run make test-e2e")
	}
	var err error
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	dir := socketDirectory(t)
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("http { server { listen %s; server_name localhost; location / { return 302 https://bootstrap.example/; } } }", address)
	old := startNgxora(t, binary, dir, "old", config, false)
	old.wait(t, "old API", func() bool { return strings.Contains(old.logs(t), "gRPC control plane listening") })

	target := (&url.URL{Scheme: "unix", Path: filepath.Join(dir, "control.sock")}).String()
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	rpc := controlv1.NewControlPlaneClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	desired, err := rpc.GetSnapshot(ctx, &controlv1.GetSnapshotRequest{})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	desired.Version = "desired-before-upgrade"
	for _, host := range desired.VirtualHosts {
		for _, route := range host.Routes {
			route.Action = &controlv1.Route_DirectResponse{DirectResponse: &controlv1.DirectResponse{Status: 201}}
		}
	}
	c, err := NewUDS(filepath.Join(dir, "control.sock"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	set(t, c, desired)
	_, clientDone := runClient(t, c)
	transport := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	httpClient := &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	servesDesired := func() bool {
		select {
		case err := <-clientDone:
			t.Fatalf("sync client stopped: %v", err)
		default:
		}
		request, err := http.NewRequest(http.MethodGet, "http://"+address+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "localhost"
		response, err := httpClient.Do(request)
		if err != nil {
			return false
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
		return response.StatusCode == 201 && c.Status().Synced
	}
	old.wait(t, "initial desired route", servesDesired)

	next := startNgxora(t, binary, dir, "new", config, true)
	next.wait(t, "upgrade receiver", func() bool {
		_, err := os.Stat(filepath.Join(dir, "upgrade.sock"))
		return err == nil
	})
	if err := old.cmd.Process.Signal(syscall.SIGQUIT); err != nil {
		t.Fatal(err)
	}
	next.wait(t, "replacement API", func() bool { return strings.Contains(next.logs(t), "gRPC control plane listening") })
	old.wait(t, "old acceptors stopped", func() bool { return strings.Contains(old.logs(t), "Broadcast graceful shutdown complete") })
	// No second SetSnapshot, and no Kubernetes event: only the SDK loop restores state.
	next.wait(t, "restored desired route", servesDesired)
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	active, err := rpc.GetSnapshot(ctx, &controlv1.GetSnapshotRequest{})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if active.Version != desired.Version {
		t.Fatalf("replacement version = %q", active.Version)
	}
}
