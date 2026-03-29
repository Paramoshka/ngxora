# Snapshot Schema

This document records the intended data flow boundary for runtime configuration.

## Rule

The dataplane consumes only compiled snapshot state.

It does not read:

- raw Kubernetes objects
- text config AST
- unresolved references

## Current Flow

`HTTPRoute` / `Gateway` / `Service` / `Secret`
-> translator and reference resolution
-> normalized desired state
-> compiled `ConfigSnapshot`
-> gRPC `ApplySnapshot`
-> runtime `CompiledRouter`
-> Pingora request handling

## Snapshot Responsibilities

The snapshot is responsible for carrying:

- listeners
- virtual hosts
- route matchers
- upstream groups
- TLS bindings and listener TLS options
- plugin configuration already compiled for runtime use

## What Must Not Cross The Boundary

The snapshot builder must not depend on raw Kubernetes object shapes once translation is done.

Examples of bad flow:

- passing `gatewayv1.HTTPRoute` directly into runtime routing
- reading `corev1.Secret` from request-time code
- resolving `Service` ports inside the dataplane

## Why This Exists

This boundary is the main guardrail against architecture drift. If a future change bypasses it, treat that as a design regression, not a convenience shortcut.
