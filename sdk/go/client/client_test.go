package client

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	controlv1 "github.com/paramoshka/ngxora/sdk/go/ngxora/control/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type testServer struct {
	controlv1.UnimplementedControlPlaneServer
	mu            sync.Mutex
	snapshot      *controlv1.ConfigSnapshot
	gets, applies int
	getHook       func(context.Context) error
	applyHook     func(context.Context, *controlv1.ConfigSnapshot) (*controlv1.ApplyResult, error)
}

func (s *testServer) GetSnapshot(ctx context.Context, _ *controlv1.GetSnapshotRequest) (*controlv1.ConfigSnapshot, error) {
	s.mu.Lock()
	s.gets++
	s.mu.Unlock()
	if s.getHook != nil {
		if err := s.getHook(ctx); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return proto.Clone(s.snapshot).(*controlv1.ConfigSnapshot), nil
}

func (s *testServer) ApplySnapshot(ctx context.Context, next *controlv1.ConfigSnapshot) (*controlv1.ApplyResult, error) {
	s.mu.Lock()
	s.applies++
	s.mu.Unlock()
	if s.applyHook != nil {
		return s.applyHook(ctx, next)
	}
	return s.accept(next), nil
}

func (s *testServer) accept(next *controlv1.ConfigSnapshot) *controlv1.ApplyResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot = proto.Clone(next).(*controlv1.ConfigSnapshot)
	return &controlv1.ApplyResult{Applied: true, ActiveVersion: next.Version, ActiveGeneration: uint64(s.applies)}
}

func (s *testServer) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gets, s.applies
}

func socketDirectory(t *testing.T) string {
	t.Helper()
	// Short paths are needed for the Unix socket path-length limit.
	dir, err := os.MkdirTemp("", "ngxora-sdk-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func serve(t *testing.T, path string, s *testServer) func() {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	controlv1.RegisterControlPlaneServer(server, s)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			server.Stop()
			if err := <-done; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				t.Error(err)
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func newTestClient(t *testing.T, path string) *Client {
	t.Helper()
	c, err := NewUDS(path, Options{PollInterval: 20 * time.Millisecond, RPCTimeout: 100 * time.Millisecond, RetryMin: 10 * time.Millisecond, RetryMax: 40 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func set(t *testing.T, c *Client, snapshot *controlv1.ConfigSnapshot) {
	t.Helper()
	if err := c.SetSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
}

func runClient(t *testing.T, c *Client) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	exited := make(chan struct{})
	go func() { defer close(exited); done <- c.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
			t.Error("client did not stop")
		}
	})
	return cancel, done
}

func eventually(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not reached before deadline")
}

func TestSnapshotCopyVersionAndNoRedundantApply(t *testing.T) {
	path := filepath.Join(socketDirectory(t), "control.sock")
	s := &testServer{snapshot: &controlv1.ConfigSnapshot{Version: "bootstrap"}}
	serve(t, path, s)
	c := newTestClient(t, path)
	runClient(t, c)
	// No desired state means no attempt to overwrite bootstrap configuration.
	time.Sleep(50 * time.Millisecond)
	if gets, applies := s.counts(); gets != 0 || applies != 0 {
		t.Fatal(gets, applies)
	}
	next := &controlv1.ConfigSnapshot{Version: "v1", Http: &controlv1.HttpOptions{KeepaliveRequests: 10}}
	set(t, c, next)
	next.Http.KeepaliveRequests = 999
	eventually(t, func() bool { gets, _ := s.counts(); return c.Status().Synced && gets >= 4 })
	s.mu.Lock()
	actual := s.snapshot.Http.KeepaliveRequests
	s.mu.Unlock()
	if actual != 10 {
		t.Fatal("input was not copied:", actual)
	}
	if _, applies := s.counts(); applies != 1 {
		t.Fatal("redundant applies:", applies)
	}
	if err := c.SetSnapshot(next); err == nil {
		t.Fatal("accepted different contents with the same version")
	}
	if err := c.SetSnapshot(nil); err == nil {
		t.Fatal("accepted nil snapshot")
	}
	if err := c.SetSnapshot(&controlv1.ConfigSnapshot{}); err == nil {
		t.Fatal("accepted empty version")
	}
	if state := c.Status(); !state.Synced || state.ConfirmedVersion != "v1" {
		t.Fatal(state)
	}
	// A manual change is corrected even with no new SetSnapshot call.
	s.accept(&controlv1.ConfigSnapshot{Version: "manual"})
	eventually(t, func() bool { _, applies := s.counts(); return applies == 2 && c.Status().Synced })
}

func TestLateServerReplacementAndLatestDesired(t *testing.T) {
	path := filepath.Join(socketDirectory(t), "control.sock")
	c := newTestClient(t, path)
	set(t, c, &controlv1.ConfigSnapshot{Version: "v1"})
	runClient(t, c)
	eventually(t, func() bool { return c.Status().LastError != nil })
	s := &testServer{snapshot: &controlv1.ConfigSnapshot{Version: "bootstrap"}}
	stop := serve(t, path, s)
	eventually(t, func() bool { return c.Status().Synced })
	stop()
	eventually(t, func() bool { return !c.Status().Synced })
	set(t, c, &controlv1.ConfigSnapshot{Version: "v2"})
	set(t, c, &controlv1.ConfigSnapshot{Version: "v3"})
	replacement := &testServer{snapshot: &controlv1.ConfigSnapshot{Version: "bootstrap"}}
	stopReplacement := serve(t, path, replacement)
	eventually(t, func() bool { return c.Status().Synced && c.Status().ConfirmedVersion == "v3" })
	if _, applies := replacement.counts(); applies != 1 {
		t.Fatal("queued obsolete snapshots:", applies)
	}
	stopReplacement()
	third := &testServer{snapshot: &controlv1.ConfigSnapshot{Version: "bootstrap"}}
	serve(t, path, third)
	// A fast restart may be hidden by grpc-go reconnect. Polling still detects lost state.
	eventually(t, func() bool { _, applies := third.counts(); return applies == 1 && c.Status().Synced })
}

func TestLostApplyResponseIsConfirmedWithoutReapply(t *testing.T) {
	path := filepath.Join(socketDirectory(t), "control.sock")
	s := &testServer{snapshot: &controlv1.ConfigSnapshot{Version: "bootstrap"}}
	s.applyHook = func(_ context.Context, next *controlv1.ConfigSnapshot) (*controlv1.ApplyResult, error) {
		s.accept(next)
		return nil, status.Error(codes.Unavailable, "response lost after commit")
	}
	serve(t, path, s)
	c := newTestClient(t, path)
	set(t, c, &controlv1.ConfigSnapshot{Version: "v1"})
	runClient(t, c)
	eventually(t, func() bool { return c.Status().Synced })
	if _, applies := s.counts(); applies != 1 {
		t.Fatal("reapplied committed snapshot:", applies)
	}
}

func TestNewDesiredDuringApplyDiscardsOldResult(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rejection"}[rejected], func(t *testing.T) {
			path := filepath.Join(socketDirectory(t), "control.sock")
			entered, release := make(chan struct{}), make(chan struct{})
			s := &testServer{snapshot: &controlv1.ConfigSnapshot{Version: "bootstrap"}}
			s.applyHook = func(ctx context.Context, next *controlv1.ConfigSnapshot) (*controlv1.ApplyResult, error) {
				if next.Version == "v1" {
					close(entered)
					select {
					case <-release:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					if rejected {
						return &controlv1.ApplyResult{Message: "old snapshot rejected"}, nil
					}
				}
				return s.accept(next), nil
			}
			serve(t, path, s)
			c := newTestClient(t, path)
			set(t, c, &controlv1.ConfigSnapshot{Version: "v1"})
			runClient(t, c)
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("apply did not start")
			}
			set(t, c, &controlv1.ConfigSnapshot{Version: "v2"})
			if c.Status().Synced {
				t.Fatal("new desired prematurely acknowledged")
			}
			close(release)
			eventually(t, func() bool { state := c.Status(); return state.Synced && state.ConfirmedVersion == "v2" })
		})
	}
}

func TestPermanentErrorsStopAndAllowRestart(t *testing.T) {
	for _, kind := range []string{"invalid", "rejected", "restart", "wrong-version"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(socketDirectory(t), "control.sock")
			s := &testServer{snapshot: &controlv1.ConfigSnapshot{Version: "bootstrap"}}
			s.applyHook = func(_ context.Context, next *controlv1.ConfigSnapshot) (*controlv1.ApplyResult, error) {
				if next.Version == "fixed" {
					return s.accept(next), nil
				}
				switch kind {
				case "invalid":
					return nil, status.Error(codes.InvalidArgument, "invalid snapshot")
				case "restart":
					return &controlv1.ApplyResult{RestartRequired: true, Message: "listeners changed"}, nil
				case "wrong-version":
					return &controlv1.ApplyResult{Applied: true, ActiveVersion: "unexpected"}, nil
				default:
					return &controlv1.ApplyResult{Message: "validation failed"}, nil
				}
			}
			serve(t, path, s)
			c := newTestClient(t, path)
			set(t, c, &controlv1.ConfigSnapshot{Version: "bad"})
			_, done := runClient(t, c)
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("missing error")
				}
				var restart *RestartRequiredError
				if kind == "restart" && !errors.As(err, &restart) {
					t.Fatal("missing typed restart error:", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("permanent error retried")
			}
			if _, applies := s.counts(); applies != 1 {
				t.Fatal(applies)
			}
			if state := c.Status(); state.Synced || state.LastError == nil {
				t.Fatal(state)
			}
			set(t, c, &controlv1.ConfigSnapshot{Version: "fixed"})
			runClient(t, c)
			eventually(t, func() bool { return c.Status().Synced })
		})
	}
}

func TestDeadlineAndCancellation(t *testing.T) {
	path := filepath.Join(socketDirectory(t), "control.sock")
	s := &testServer{snapshot: &controlv1.ConfigSnapshot{Version: "bootstrap"}}
	s.getHook = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	serve(t, path, s)
	c := newTestClient(t, path)
	set(t, c, &controlv1.ConfigSnapshot{Version: "v1"})
	cancel, done := runClient(t, c)
	eventually(t, func() bool { gets, _ := s.counts(); return gets >= 2 })
	if err := c.Run(context.Background()); err == nil {
		t.Fatal("concurrent Run accepted")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt RPC")
	}
	if c.Status().Synced {
		t.Fatal("stopped client remains synced")
	}
}

func TestInvalidOptions(t *testing.T) {
	for _, path := range []string{"", "relative.sock", "/tmp/nul\x00.sock"} {
		if _, err := NewUDS(path, Options{}); err == nil {
			t.Fatal("accepted path:", path)
		}
	}
	for _, opts := range []Options{{RPCTimeout: -1}, {PollInterval: -1}, {RetryMin: time.Second, RetryMax: time.Millisecond}, {RetryMax: time.Duration(1<<63 - 1)}} {
		if _, err := NewUDS("/tmp/control.sock", opts); err == nil {
			t.Fatal("accepted options:", opts)
		}
	}
}

func TestRetryBackoffAndCancellationDuringWait(t *testing.T) {
	path := filepath.Join(socketDirectory(t), "control.sock")
	var mu sync.Mutex
	var attempts []time.Time
	s := &testServer{snapshot: &controlv1.ConfigSnapshot{Version: "bootstrap"}}
	s.getHook = func(context.Context) error {
		mu.Lock()
		attempts = append(attempts, time.Now())
		mu.Unlock()
		return status.Error(codes.Unavailable, "temporarily unavailable")
	}
	serve(t, path, s)
	c, err := NewUDS(path, Options{RetryMin: 100 * time.Millisecond, RetryMax: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	set(t, c, &controlv1.ConfigSnapshot{Version: "v1"})
	cancel, done := runClient(t, c)
	eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(attempts) >= 4
	})
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("retry wait did not honor cancellation")
	}
	mu.Lock()
	defer mu.Unlock()
	for i := 1; i < 4; i++ {
		minimum := 80 * time.Millisecond
		if i > 1 {
			minimum = 160 * time.Millisecond
		}
		if gap := attempts[i].Sub(attempts[i-1]); gap < minimum {
			t.Fatalf("retry %d too early: %s < %s", i, gap, minimum)
		}
	}
}

func TestCancellationWithoutDesiredSnapshot(t *testing.T) {
	c := newTestClient(t, filepath.Join(socketDirectory(t), "absent.sock"))
	cancel, done := runClient(t, c)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle client did not honor cancellation")
	}
}
