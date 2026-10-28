# Design Notes

These notes document the package's security and lifecycle contracts that are easy to miss if you only read the
quick-start material or skim the test suite.

Each note is intentionally short and follows the same structure:

- `Purpose`
- `Invariants`
- `Success Path`
- `Failure / Edge Cases`
- `Implementation Anchors`
- `Authoritative Tests`
- `Change Triggers`

The current note set is:

- `guard-lifecycle-and-events.md`: standard Laravel auth events plus the package contextual events, and the exact
  successful event order for `attempt()`, direct `login()`, bearer auth, and refresh.
- `event-model.md`: the context every package event carries, what survives a queue, when an event that reports a write
  is dispatched, and the one failure event.
- `refresh-rotation-and-replay.md`: why refresh is stateful, how per-device rotation works, the grace window for the
  previous rotation id, and when a replayed refresh token revokes the device (`rotation_reuse`).
- `refresh-token-transport.md`: where a guard reads the refresh token from, why a request may carry it in only one
  place, the cookie's cross-site checks, and the cookie that carries a browser's refresh token.
- `fail-closed-pid-did.md`: why `pid` and `did` are treated as commitments rather than advisory hints.
- `access-only-mode.md`: the supported bearer-only, no-devices migration path.
- `guard-bound-tokens.md`: the `grd` claim that ties every token to its issuing guard, and the provider-scoped owner
  reload on refresh.
- `session-service.md`: how a guard's session service signs in, creates or continues a device, issues the first pair,
  and reports it.
- `device-lifecycle.md`: which devices are active, how an identity's devices are listed, how a session signs out and
  devices are revoked (one, every device of an identity or a principal, and on security changes, by method or optional
  listener), and when ended devices are pruned.
- `principal-choice-and-switch.md`: how a sign-in that names no principal waits for the identity to choose one, and how
  a session switches to another principal on its device, proven by its refresh token.
- `audience-policy.md`: what each guard decides about its sessions (methods, principal types, verified identifiers,
  lifetimes per principal type), where every path enforces it, and how the attempt limits and identifier normalisers
  meet it.
- `one-time-codes.md`: how one-time codes are bound, stored, issued, checked and delivered, why a request for one looks
  the same for an identifier no one has, and who a code is ever sent to.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
