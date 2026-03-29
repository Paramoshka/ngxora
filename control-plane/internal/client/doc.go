// Package client contains the control-plane side gRPC client used to talk to a
// co-located ngxora dataplane over UDS.
//
// The client is intentionally narrow: fetch the active snapshot and push a new
// full snapshot. Higher-level reconciliation stays in the controller layer.
package client
