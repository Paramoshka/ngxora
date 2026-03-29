// Package controller wires controller-runtime reconciliation for the local
// ngxora control-plane.
//
// Responsibilities:
// - watch Gateway API and supporting Kubernetes objects
// - resolve cross-object references
// - build and apply full snapshots
// - write HTTPRoute and Gateway status
//
// Non-responsibilities:
// - request-time routing
// - Pingora listener binding
// - raw runtime config compilation from nginx text config
package controller
