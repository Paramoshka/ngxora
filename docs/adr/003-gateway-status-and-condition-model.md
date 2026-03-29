# ADR-003: Gateway Status And Condition Model

## Context

Gateway API controllers become hard to reason about when status is written ad hoc in multiple places.

## Decision

Use a small internal condition model based on explicit status plans:

- route conditions are built from `routeConditionState`
- `HTTPRoute.status.parents` is patched from a per-route status plan
- `Gateway.status.listeners` and top-level `Gateway.status.conditions` are derived from listener evaluation plus apply result
- `Programmed` is driven by snapshot apply / active snapshot version, not by translation alone

## Consequences

- route and gateway status stay deterministic
- translation, reference resolution, and apply failures are separated cleanly
- new controllers should reuse the same pattern instead of hand-writing conditions inline
