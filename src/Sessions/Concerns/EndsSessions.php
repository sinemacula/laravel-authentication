<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Pagination\LengthAwarePaginator;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionSignOut;
use SineMacula\Laravel\Authentication\Sessions\SignOutResult;
use SineMacula\Laravel\Authentication\Sessions\TenantPolicyChanges;

/**
 * The session service's session list, and its sign-out, revocation and
 * security-change methods, which `SessionRevocations` carries out: signing out
 * and signing out everywhere for the binding the service is given, the rest for
 * whatever identity, principal or tenant they are given; signing out by refresh
 * credential, which `SessionSignOut` carries out; and the application of a
 * tenant's changed authentication policy, which `TenantPolicyChanges` carries
 * out.
 *
 * They are delegations with no state of their own but those three; they sit in
 * a trait only so the service stays within the number of methods one class may
 * declare.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait EndsSessions
{
    /** @var \SineMacula\Laravel\Authentication\Sessions\SessionRevocations Signs sessions out and ends them, on the guard's context. */
    private readonly SessionRevocations $revocations;

    /** @var \SineMacula\Laravel\Authentication\Sessions\TenantPolicyChanges Applies a tenant's changed authentication policy to its sessions. */
    private readonly TenantPolicyChanges $policyChanges;

    /** @var \SineMacula\Laravel\Authentication\Sessions\SessionSignOut Signs sessions out by their refresh credential. */
    private readonly SessionSignOut $signOuts;

    /**
     * One page of the identity's active sessions, of every guard, for a session
     * list: most recently used first (never used last), then newest first, each
     * summarised without its digests, revocation or principal, and marked when
     * it is the session this guard is authenticated with for the request. Read
     * on the write connection through the identity's `sessions()` relation.
     * `$perPage` is 1 to 100; the page is the request's `page` parameter unless
     * given.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  int  $perPage
     * @param  ?int  $page
     * @return \Illuminate\Pagination\LengthAwarePaginator<int, \SineMacula\Laravel\Authentication\Sessions\SessionSummary>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function sessions(Identity $identity, int $perPage = 15, ?int $page = null): LengthAwarePaginator
    {
        return ActiveSessions::page($identity, $this->binding->session(), $perPage, $page);
    }

    /**
     * Sign the request's session out: revoke the session the guard is bound to
     * (`signed_out`), dispatch Laravel's `Logout` when an identity was bound,
     * and forget the guard's state for the rest of the request. Returns whether
     * this call revoked a session.
     *
     * An access-only token, which names no stored session, has nothing to
     * revoke and is only forgotten; a guest request does nothing. To sign out a
     * client whose access token has expired, and to clear a cookie
     * application's refresh cookie, use `signOutFromRequest()`.
     *
     * @return bool
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     *
     * @imperative
     */
    public function signOut(): bool
    {
        return $this->revocations->signOut($this->binding);
    }

    /**
     * Sign the request out by whichever credential it carries, so a client
     * whose access token has expired can still sign out.
     *
     * A request whose access token is bound to a stored session is signed out
     * as `signOut()` signs it out, and its refresh credential is not read.
     * Otherwise any binding is forgotten first (an access-only token's, with
     * Laravel's `Logout`, the guard staying signed out for the rest of the
     * request), and the refresh credential is read through the application's
     * transport (the cookie of a cookie application, with its cross-site
     * checks; the body field or header of a body application): none signs
     * nothing out; one the transport refuses fails with its reason
     * (`refresh_token_conflict`, `refresh_transport_mismatch`,
     * `cross_site_request`, `token_invalid`); one the session it names refuses
     * (as a refresh would refuse it, short of rotating it, a replay revoking
     * the session as `rotation_reuse`) fails with that reason; and the session
     * it proves is revoked (`signed_out`, reported by `SessionRevoked` once
     * committed), Laravel's `Logout` firing for its owner when the guard's
     * provider still returns it and none fired already. A refusal is reported
     * by `AuthenticationFailed` with the flow `sign_out`, and by no `Failed`. A
     * cookie application's result carries the expired cookie that clears the
     * browser's (`SignOutResult::attachTo()`) when the access token signed its
     * session out, or when the request passes the cookie's same-site checks and
     * was not refused as `refresh_token_conflict`, so a cross-site page cannot
     * clear it.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignOutResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     *
     * @imperative
     */
    public function signOutFromRequest(): SignOutResult
    {
        return $this->signOuts->fromRequest();
    }

    /**
     * Sign out the session a body application's refresh token, read by your own
     * code, proves, as `signOutFromRequest()` signs out a session its refresh
     * credential proves; a binding of the guard to that session is forgotten. A
     * cookie application's token is read only from its cookie, with the
     * cookie's cross-site checks, so on a cookie application this throws a
     * `LogicException`: use `signOutFromRequest()`.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Sessions\SignOutResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     *
     * @imperative
     */
    public function signOutWith(#[\SensitiveParameter] Secret|string $refreshToken): SignOutResult
    {
        return $this->signOuts->with($refreshToken);
    }

    /**
     * End every session of the request's identity, of every guard, with reason
     * `signed_out_everywhere`, keeping the request's own session when asked.
     * Returns how many sessions this call revoked; `0` for a guest request.
     *
     * The request's session is kept by leaving it unrevoked. An access-only
     * token, which names no session, is kept by leaving the identity's "tokens
     * valid after" cutoff where it is, since a session-less token can only be
     * ended through it: its sessions are still revoked, but the identity's
     * other session-less tokens then also keep working until they expire. The
     * identity's pending identifier changes are cancelled either way, since
     * none records the session it was requested from.
     *
     * The guard stays bound for the rest of the request either way; call
     * `signOut()` as well to end the request's own session.
     *
     * @param  bool  $keepCurrentSession
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Throwable
     */
    public function signOutEverywhere(bool $keepCurrentSession = false): int
    {
        return $this->revocations->signOutEverywhere($this->binding, $keepCurrentSession);
    }

    /**
     * Revoke one session of the owner, found through the owner's `sessions()`
     * relation on the write connection, so another identity's session is not
     * found: `false`, without saying whether it exists. Returns whether this
     * call revoked it (`false` too for a session already revoked).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @param  mixed  $sessionId
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @return bool
     *
     * @throws \LogicException
     *
     * @imperative
     */
    public function revokeSession(Identity $owner, mixed $sessionId, RevocationReason $reason): bool
    {
        return $this->revocations->revokeSession($owner, $sessionId, $reason);
    }

    /**
     * Revoke every session of the identity, of every guard, except the given
     * one (its pending sessions among them), and cancel its pending identifier
     * changes (a change link needs no session); when the identity records a
     * "tokens valid after" cutoff, move it to now first, so its access tokens
     * issued without a session stop as well. Returns how many sessions this
     * call revoked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function revokeSessions(Identity $identity, RevocationReason $reason, ?Session $except = null): int
    {
        return $this->revocations->revokeSessions($identity, $reason, $except);
    }

    /**
     * Revoke every session that acts as the principal, except the given one,
     * pending sessions that record it among them; when the principal records a
     * "tokens valid after" cutoff, move it to now first. Returns how many
     * sessions this call revoked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @return int
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function revokePrincipalSessions(Principal $principal, RevocationReason $reason, ?Session $except = null): int
    {
        return $this->revocations->revokePrincipalSessions($principal, $reason, $except);
    }

    /**
     * The identity's password was changed: end its sessions
     * (`password_changed`), except the given session, the one the change was
     * made from when the application keeps it signed in. Never call it for an
     * automatic rehash.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function passwordChanged(Identity $identity, ?Session $except = null): int
    {
        return $this->revocations->passwordChanged($identity, $except);
    }

    /**
     * The identity's password was reset: end every session it has
     * (`password_reset`).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function passwordReset(Identity $identity): int
    {
        return $this->revocations->passwordReset($identity);
    }

    /**
     * A factor the identity signs in with was removed: end its sessions
     * (`factor_removed`), except the given session. The seam a further-factor
     * package calls when a factor is removed.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function factorRemoved(Identity $identity, ?Session $except = null): int
    {
        return $this->revocations->factorRemoved($identity, $except);
    }

    /**
     * The identity was deactivated: end every session it has
     * (`identity_deactivated`).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function identityDeactivated(Identity $identity): int
    {
        return $this->revocations->identityDeactivated($identity);
    }

    /**
     * The principal was deactivated: end every session acting as it
     * (`principal_deactivated`).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return int
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function principalDeactivated(Principal $principal): int
    {
        return $this->revocations->principalDeactivated($principal);
    }

    /**
     * The tenant was deactivated: end every session acting as one of the
     * principals the application lists for it, and every session whose active
     * tenant it is, whatever principal it acts as (`tenant_deactivated`). Every
     * principal must belong to the tenant (the same class and identifier, read
     * on the write connection), or nothing is written and an
     * `InvalidArgumentException` is thrown; a principal listed twice counts
     * once, and so does a session both find. A tenant that opts into activation
     * (`CanBeActive`) and is already deleted or soft-deleted works too: a
     * principal whose `getTenant()` throws the `TenantUnavailableException`
     * naming it (its class, key name and key, as `ActsAsPrincipal` does) acts
     * within it. A tenant that does not opt in reads as no tenant once it
     * cannot be loaded, so call this before deleting it. All sessions, pending
     * ones among them, are ended in one transaction, after each principal's
     * cutoff moved, with one `SignedOutEverywhere` per principal.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  iterable<\SineMacula\Laravel\Authentication\Contracts\Principal>  $principals
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function tenantDeactivated(Tenant $tenant, iterable $principals): int
    {
        return $this->revocations->tenantDeactivated($tenant, $principals);
    }

    /**
     * Apply a change of the tenant's authentication policy to the live sessions
     * acting in it, on every guard, at once: an active session that no longer
     * meets the policy is revoked (`tenant_policy_changed`) and one that meets
     * it records the version answered; a pending one is revoked only when it
     * would need another connection; a session recorded at the very version
     * answered (neither `null`) is skipped, and one that has already ended is
     * left for pruning. Returns how many sessions were revoked.
     *
     * Call it in the transaction that publishes the change, on the storage
     * connection, so both commit or roll back together (it runs as a savepoint
     * there and never commits on its own), and for a strict cut-off once more
     * after that commits: a session that entered the tenant while the first
     * call ran is then judged too, and every session the first call recorded is
     * skipped. `SessionRevoked` reports each revocation once committed.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return int
     *
     * @throws \Throwable
     */
    public function tenantPolicyChanged(Tenant $tenant): int
    {
        return $this->policyChanges->apply($tenant, CarbonImmutable::now()->startOfSecond());
    }
}
