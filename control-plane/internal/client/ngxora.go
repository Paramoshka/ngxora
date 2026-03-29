package client

import (
	"context"
	"fmt"
	"net"
	"time"

	controlv1 "github.com/paramoshka/ngxora/sdk/go/ngxora/control/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// NGXoraClient is a thin gRPC client for the local ngxora dataplane control
// socket.
type NGXoraClient struct {
	socketPath   string
	applyTimeout time.Duration
}

// New creates a client that talks to the co-located ngxora dataplane over UDS.
func New(socketPath string, applyTimeout time.Duration) *NGXoraClient {
	return &NGXoraClient{
		socketPath:   socketPath,
		applyTimeout: applyTimeout,
	}
}

// ApplySnapshot pushes the full desired runtime snapshot to the dataplane.
func (c *NGXoraClient) ApplySnapshot(ctx context.Context, snapshot *controlv1.ConfigSnapshot) (*controlv1.ApplyResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.applyTimeout)
	defer cancel()

	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := controlv1.NewControlPlaneClient(conn)
	return client.ApplySnapshot(ctx, snapshot)
}

// GetSnapshot returns the currently active snapshot from the dataplane.
func (c *NGXoraClient) GetSnapshot(ctx context.Context) (*controlv1.ConfigSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, c.applyTimeout)
	defer cancel()

	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := controlv1.NewControlPlaneClient(conn)
	return client.GetSnapshot(ctx, &controlv1.GetSnapshotRequest{})
}

// dial opens a UDS gRPC connection to the local dataplane instance.
func (c *NGXoraClient) dial(ctx context.Context) (*grpc.ClientConn, error) {
	target := fmt.Sprintf("unix://%s", c.socketPath)

	conn, err := grpc.DialContext(
		ctx,
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", c.socketPath)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("dial ngxora control socket: %w", err)
	}

	return conn, nil
}
