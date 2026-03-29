// Package attachment contains shared Gateway listener attachment rules used by
// both status evaluation and snapshot build.
//
// Responsibilities:
// - match parentRefs to listeners
// - evaluate AllowedRoutes namespace and kind policy
// - compute effective hostnames after listener/route hostname intersection
//
// This package exists to keep attachment semantics in one place so controller
// status and snapshot generation do not drift apart.
package attachment
