// Package snapshot converts normalized desired state into the gRPC
// ConfigSnapshot consumed by the ngxora dataplane.
//
// Responsibilities:
// - map translated routes onto Gateway listeners
// - build listeners, virtual hosts, and upstream groups
// - produce a deterministic snapshot version
//
// Non-responsibilities:
// - read raw Kubernetes objects
// - resolve Services, Secrets, or ReferenceGrants
// - execute runtime routing
package snapshot
