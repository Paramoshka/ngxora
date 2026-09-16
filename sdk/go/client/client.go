// Package client synchronizes desired ngxora configuration over a local Unix socket.
package client

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	controlv1 "github.com/paramoshka/ngxora/sdk/go/ngxora/control/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Options controls reconciliation and connection retries. Zero values use defaults.
type Options struct {
	PollInterval time.Duration // default: 1s
	RPCTimeout   time.Duration // default: 3s, per RPC
	RetryMin     time.Duration // default: 200ms
	RetryMax     time.Duration // default: 5s, before +/-20% jitter
}

// Status describes the last observation, not a guarantee of current API availability.
type Status struct {
	DesiredVersion   string
	ConfirmedVersion string
	Synced           bool
	LastError        error
}

// ApplyError reports a snapshot rejected by ngxora without a transport failure.
type ApplyError struct {
	Message       string
	ActiveVersion string
}

func (e *ApplyError) Error() string { return "ngxora rejected snapshot: " + e.Message }

// RestartRequiredError reports bootstrap settings which cannot be applied live.
// The client does not restart ngxora; the caller must resolve this before retrying.
type RestartRequiredError struct {
	Message       string
	ActiveVersion string
}

func (e *RestartRequiredError) Error() string { return "ngxora requires restart: " + e.Message }

// Client retains only the latest desired snapshot. SetSnapshot and Status may be
// called concurrently with Run. Only one Run may execute at a time.
type Client struct {
	target  string
	options Options
	wake    chan struct{}
	mu      sync.Mutex
	desired *controlv1.ConfigSnapshot
	state   Status
	running bool
}

// NewUDS configures a client without dialing or touching the filesystem.
// The server owns socket permissions; a missing socket is retried by Run.
func NewUDS(path string, options Options) (*Client, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
		return nil, errors.New("UDS path must be an absolute filesystem path without NUL")
	}
	for _, item := range []struct {
		value    *time.Duration
		fallback time.Duration
	}{
		{&options.PollInterval, time.Second},
		{&options.RPCTimeout, 3 * time.Second},
		{&options.RetryMin, 200 * time.Millisecond},
		{&options.RetryMax, 5 * time.Second},
	} {
		if *item.value < 0 {
			return nil, errors.New("client durations must not be negative")
		}
		if *item.value == 0 {
			*item.value = item.fallback
		}
	}
	if options.RetryMin > options.RetryMax {
		return nil, errors.New("RetryMin must not exceed RetryMax")
	}
	// Leave headroom for jitter in both our timers and grpc-go's backoff.
	if options.RetryMax > time.Duration(1<<63-1)/2 {
		return nil, errors.New("RetryMax is too large to safely apply jitter")
	}
	target := (&url.URL{Scheme: "unix", Path: path}).String()
	return &Client{target: target, options: options, wake: make(chan struct{}, 1)}, nil
}

// SetSnapshot copies the desired configuration. Version must be nonempty and
// uniquely identify its contents, including across client/process restarts.
// Reusing the current version with different contents is rejected locally.
func (c *Client) SetSnapshot(snapshot *controlv1.ConfigSnapshot) error {
	if snapshot == nil || strings.TrimSpace(snapshot.Version) == "" {
		return errors.New("snapshot requires a nonempty version")
	}
	next := proto.Clone(snapshot).(*controlv1.ConfigSnapshot)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.desired != nil && c.desired.Version == next.Version {
		if !proto.Equal(c.desired, next) {
			return errors.New("snapshot version already identifies different contents")
		}
		return nil
	}
	c.desired = next
	c.state.DesiredVersion = next.Version
	c.state.Synced = false
	c.state.LastError = nil
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return nil
}

// Status returns a copy of the latest reconciliation status.
func (c *Client) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Run reconciles until ctx is canceled or a permanent error occurs. It closes
// its connection on exit, retains desired state, and may then be called again.
// Only Unavailable and DeadlineExceeded are retried. Other RPC errors and
// rejected snapshots are returned to the caller, never silently retried.
func (c *Client) Run(ctx context.Context) (runErr error) {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return errors.New("client Run is already active")
	}
	c.running = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.running = false
		c.state.Synced = false
		c.state.LastError = runErr
	}()
	conn, err := grpc.NewClient(c.target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDisableRetry(),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           backoff.Config{BaseDelay: c.options.RetryMin, Multiplier: 2, Jitter: 0.2, MaxDelay: c.options.RetryMax},
			MinConnectTimeout: c.options.RPCTimeout,
		}),
	)
	if err != nil {
		return fmt.Errorf("create UDS connection: %w", err)
	}
	defer func() { runErr = errors.Join(runErr, conn.Close()) }()
	return c.run(ctx, controlv1.NewControlPlaneClient(conn))
}

func (c *Client) run(ctx context.Context, rpc controlv1.ControlPlaneClient) error {
	retry := c.options.RetryMin
	var previous *controlv1.ConfigSnapshot
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.mu.Lock()
		desired := c.desired
		// Consume notifications before the attempt, so SetSnapshot during an RPC
		// still wakes the next iteration without causing duplicate idle polls.
		select {
		case <-c.wake:
		default:
		}
		c.mu.Unlock()
		if desired == nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-c.wake:
				continue
			}
		}
		if desired != previous {
			retry = c.options.RetryMin
			previous = desired
		}
		err := c.reconcile(ctx, rpc, desired)
		c.mu.Lock()
		current := c.desired == desired
		if current {
			c.state.LastError = err
			c.state.Synced = err == nil
			if err == nil {
				c.state.ConfirmedVersion = desired.Version
			}
		}
		c.mu.Unlock()
		if !current {
			continue // An old result must not acknowledge or reject a newer desired snapshot.
		}
		delay := c.options.PollInterval
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if status.Code(err) != codes.Unavailable && status.Code(err) != codes.DeadlineExceeded {
				return err
			}
			delay = time.Duration(float64(retry) * (0.8 + rand.Float64()*0.4))
			if retry >= c.options.RetryMax/2 {
				retry = c.options.RetryMax
			} else {
				retry *= 2
			}
		} else {
			retry = c.options.RetryMin
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-c.wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (c *Client) reconcile(ctx context.Context, rpc controlv1.ControlPlaneClient, desired *controlv1.ConfigSnapshot) error {
	callCtx, cancel := context.WithTimeout(ctx, c.options.RPCTimeout)
	active, err := rpc.GetSnapshot(callCtx, &controlv1.GetSnapshotRequest{})
	cancel()
	if err != nil {
		return fmt.Errorf("get snapshot: %w", err)
	}
	if active.Version == desired.Version {
		return nil
	}
	c.mu.Lock()
	current := c.desired == desired
	c.mu.Unlock()
	if !current {
		return nil // Run discards this result and immediately reconciles the new desired state.
	}
	callCtx, cancel = context.WithTimeout(ctx, c.options.RPCTimeout)
	result, err := rpc.ApplySnapshot(callCtx, desired)
	cancel()
	if err != nil {
		return fmt.Errorf("apply snapshot: %w", err)
	}
	if result.RestartRequired {
		return &RestartRequiredError{Message: result.Message, ActiveVersion: result.ActiveVersion}
	}
	if !result.Applied {
		return &ApplyError{Message: result.Message, ActiveVersion: result.ActiveVersion}
	}
	if result.ActiveVersion != desired.Version {
		return fmt.Errorf("apply snapshot acknowledged version %q, expected %q", result.ActiveVersion, desired.Version)
	}
	return nil
}
