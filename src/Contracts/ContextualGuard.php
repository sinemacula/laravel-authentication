<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Auth\Guard;

/**
 * Contextual guard contract.
 *
 * Extends Laravel's `Guard` with the package's contextual surface (identity,
 * principal, session, tenant, scopes, principal/session setters, contextual
 * `attempt` and `login`). Like `user()`, the accessors and setters resolve the
 * current request on first access, at most once per request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ContextualGuard extends Guard
{
    /**
     * Contextual attempt with optional principal and session pinning.
     *
     * Signature diverges from Laravel's `StatefulGuard::attempt()`: the second
     * and third parameters are contextual pins, not a remember-me flag. This
     * package is stateless-only. Pins are verified against the authenticated
     * identity before they are bound.
     *
     * @param  array<string, mixed>  $credentials
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return bool
     *
     * @imperative
     */
    public function attempt(#[\SensitiveParameter] array $credentials, ?Principal $principal = null, ?Session $session = null): bool;

    /**
     * Bind a fully resolved identity, principal, and optional session.
     *
     * The trusted entry point: the arguments are bound as given, so the caller
     * must already have proven that the principal and session belong to the
     * identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return void
     */
    public function login(Identity $identity, Principal $principal, ?Session $session = null): void;

    /**
     * Return the authenticated identity, if any, resolving the request on first
     * access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function identity(): ?Identity;

    /**
     * Return the active principal, if any, resolving the request on first
     * access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function principal(): ?Principal;

    /**
     * Return the pinned session, if any, resolving the request on first access.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function session(): ?Session;

    /**
     * Return the active tenant, the tenant the request acts in, if any,
     * resolving the request on first access: a session's is the one it records,
     * and a token without a session acts in the principal's own. A trusted bind
     * (`login()`, `setUser()`, `setPrincipal()`) binds the tenant the bound
     * session records, or the principal's own without a session, and none when
     * it cannot be loaded or no longer resolves.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function tenant(): ?Tenant;

    /**
     * Return the scopes the request's credential grants, resolving the request
     * on first access: `null` for a human identity's session, which no
     * credential limits, otherwise the granted list (`[]` for none). The scopes
     * are opaque strings and a ceiling, never a permission.
     *
     * @return ?list<string>
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function scopes(): ?array;

    /**
     * Bind the active principal for the current request, resolving the request
     * first so it replaces the principal the request's credential binds rather
     * than being replaced by it.
     *
     * A trusted bind, like `login()`: the principal is bound as given, with no
     * check that it belongs to the identity, is active, or acts within an
     * active tenant. A principal taken from request input must be proven to
     * belong to the identity first, as `attempt()` does for the principal
     * pinned on it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return static
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function setPrincipal(Principal $principal): static;

    /**
     * Bind the active session for the current request, resolving the request
     * first so it replaces the session the request's credential binds rather
     * than being replaced by it.
     *
     * A trusted bind, like `login()`: the session is bound as given, with no
     * check that it belongs to the identity, is not revoked, or has not ended.
     * A session taken from request input must be proven to be one of the
     * identity's live sessions first, as `attempt()` does for the session
     * pinned on it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return static
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function setSession(Session $session): static;
}
