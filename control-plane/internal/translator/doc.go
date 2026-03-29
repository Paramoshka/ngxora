// Package translator converts Gateway API objects into normalized desired state.
//
// Responsibilities:
// - select HTTPRoutes that target the configured Gateway
// - translate hostnames, matches, filters, and backend refs into DesiredState
//
// Non-responsibilities:
// - resolve Kubernetes references such as Services or Secrets
// - write status conditions
// - build runtime snapshots
//
// This package is the API-shape to normalized-state boundary. Runtime code
// should consume the translated state, not raw Kubernetes objects.
package translator
