<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Pagination\LengthAwarePaginator;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessions;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeResult;
use SineMacula\Laravel\Authentication\Sessions\FactorRemoval;
use SineMacula\Laravel\Authentication\Sessions\FactorRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionSignOut;
use SineMacula\Laravel\Authentication\Sessions\SignOutResult;
use SineMacula\Laravel\Authentication\Sessions\TenantPolicyChanges;

/**
 * The session service's session list, and its sign-out, revocation and
 * security-change methods, which `SessionRevocations` carries out: signing out
 * and signing out everywhere for the binding the service is given, the rest for
 * whatever identity, principal or tenant they are given; signing out by refresh
 * credential, by what the request carries or from plain values, which
 * `SessionSignOut` carries out; the removal and reset of the factor package's
 * factors, and the judgement of the current session again after an addition to
 * them, which `FactorRevocations` carries out; and the application of a
 * tenant's changed authentication policy, which `TenantPolicyChanges` carries
 * out.
 *
 * They are delegations with no state of their own but those four; they sit in a
 * trait only so the service stays within the number of methods one class may
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

    /** @var \SineMacula\Laravel\Authentication\Sessions\FactorRevocations Ends sessions when the factor package removes or resets factors, and judges the current session again after its changes. */
    private readonly FactorRevocations $factorRevocations;

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
     * application's refresh cookie, use `signOutFromRequest()`, or
     * `signOutPresented()` with the refresh credential and the client as plain
     * values.
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
     * credential proves; only a binding of the guard to that session is
     * forgotten, so a guard bound to another session stays bound to it. A
     * cookie application's token comes only from its cookie, with the cookie's
     * cross-site checks, so on a cookie application this throws a
     * `LogicException`: use `signOutFromRequest()` or `signOutPresented()`.
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
     * Sign out by the refresh credential a controller extracted from its
     * request and handed on as plain values, for a service layer that keeps
     * HTTP out: what `RefreshTokenTransport::extract()` answered, or a
     * `PresentedRefreshToken` the application built as its trusted description
     * of the request, and the request's `ClientContext`. Valid on a cookie and
     * a body application alike; nothing is read from the guard's request.
     *
     * It signs out by the refresh credential alone, as `signOutWith()` does:
     * the guard's binding is not consulted, and only a binding to the session
     * it revokes is forgotten. The package judges the token again, as
     * `refreshPresented()` does (`refresh_token_conflict`,
     * `refresh_transport_mismatch`, `cross_site_request` for a cookie whose
     * client fails the same-site check); a reason the transport answers is
     * reported as `signOutFromRequest()` reports it, and any other is a
     * caller's error (`InvalidArgumentException`), nothing dispatched. `null`
     * signs nothing out; a refusal, or a session the token does not prove (a
     * replay revoking it as `rotation_reuse`), is reported by
     * `AuthenticationFailed` with the flow `sign_out` and by no `Failed`; and
     * the session it proves, inside the grace window too, is revoked
     * (`signed_out`, reported by `SessionRevoked` once committed), Laravel's
     * `Logout` firing for its owner when the guard's provider still returns it.
     * Every package event this call dispatches carries the client. A cookie
     * application's result carries the expired cookie that clears the browser's
     * (`SignOutResult::attachTo()`) when the client passes the cookie's
     * same-site checks and the token was not refused as
     * `refresh_token_conflict`, so a cross-site page cannot clear it.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\SignOutResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     *
     * @imperative
     */
    public function signOutPresented(#[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented, ClientContext $client): SignOutResult
    {
        return $this->signOuts->presented($presented, $client);
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
     * call revoked. Called inside a transaction on the storage connection, it
     * runs as a savepoint there and reports once that commits, so a change of
     * the application's rolled back with it revokes nothing; the identity must
     * live on that connection too for its cutoff to roll back as well.
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
     * A first-factor credential of the identity (a passkey, or a phone number
     * or email address it signs in with) was removed: end its sessions
     * (`factor_removed`), except the given session.
     * `RevokeSessionsOnPasskeyRemoval` calls it for a removed passkey.
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
    public function credentialRemoved(Identity $identity, ?Session $except = null): int
    {
        return $this->revocations->credentialRemoved($identity, $except);
    }

    /**
     * The factor package removed the identity's factor `$factor` (its reference
     * to it, 1 to 255 characters): end every session of the identity but
     * `$current`, pending ones included (`factor_removed`), and judge
     * `$current` again without the factor. Its proofs made with the factor stop
     * counting; it stays active while it still meets the identity's factor
     * policy and its tenant's policy, returns to pending (flow `factor_change`)
     * while it falls short of a further factor only, its tokens stopping at
     * once, and is revoked (`factor_removed`) when it is no longer admitted as
     * a refresh admits it or its tenant now requires a connection. A current
     * session that is pending has its proofs made with the factor voided too
     * and stays pending, its next action judged without them; one that was
     * meanwhile revoked or ended is left as it is. When this guard is bound to
     * it and it is returned to pending or revoked, the binding is forgotten
     * once the removal commits; with no `$current`, every session of the
     * identity ends, and a binding to the identity is forgotten then.
     *
     * Mandatory: the factor package calls it inside the transaction that
     * removes the factor, after taking its own locks, so both commit or roll
     * back together; it runs as a savepoint there and its events follow the
     * commit. `$current`, when given, must be a session of this guard the
     * identity owns, and the identity must live on the storage connection, or
     * nothing is written and an exception is thrown.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $factor
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $current
     * @return \SineMacula\Laravel\Authentication\Sessions\FactorRemoval
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function factorRemoved(Identity $identity, string $factor, ?Session $current = null): FactorRemoval
    {
        return $this->factorRevocations->remove($identity, $factor, $current, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * The factor package made a change to the identity's factors from
     * `$current` that removes none of them (a factor confirmed, a passkey
     * associated as a factor): judge `$current` again exactly as
     * `factorRemoved()` judges it, without voiding any proof or touching any
     * other session. It stays active while it still meets the identity's factor
     * policy and its tenant's policy (`active`); returns to pending (flow
     * `factor_change`) while it falls short of a further factor only, its
     * tokens stopping from the commit and the result carrying the pending
     * session and the new pending credential for the client (`pending`); and is
     * revoked when it is no longer admitted as a refresh admits it or its
     * tenant now requires a connection (`revoked`, `factor_changed`, or
     * `factor_removed` for `FACTOR_REMOVED`). A session that is no longer the
     * one given, or no longer live and active (a pending one is judged at its
     * next action), is left as it is (`skipped`), which says nothing of whether
     * it is usable. When this guard is bound to it and it is returned to
     * pending or revoked, the binding is forgotten once the change commits.
     *
     * The factor package calls it inside the transaction that makes the change,
     * on the storage connection, after taking its own locks, so both commit or
     * roll back together: it runs as a savepoint there, locks the session's
     * row, writes its issuance guard before anything reads its proofs, and its
     * events follow the commit. Called with no transaction on the storage
     * connection, it commits on its own. `$current` must be a session of this
     * guard the identity owns, or nothing is written and an exception is
     * thrown. Never call it in place of `factorRemoved()` or `factorReset()`: a
     * replacement removes the factor it replaces, so it calls `factorRemoved()`
     * for that factor, and a removal needs nothing more. `FACTOR_REMOVED`,
     * after it, judges a session the removal kept again at this call's own
     * time, so it can still return it to pending: the client's credential is
     * then this result's, not the removal's.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade  $change
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $current
     * @return \SineMacula\Laravel\Authentication\Sessions\FactorChangeResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function factorChanged(Identity $identity, FactorChangeMade $change, Session $current): FactorChangeResult
    {
        return $this->factorRevocations->change($identity, $change, $current, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * The factor package reset the identity's further factors: end every
     * session it has, the current one included (`factor_reset`), and, when this
     * guard is bound to the identity, forget the binding once the reset
     * commits. Mandatory, as `factorRemoved()` is, and called the same way; the
     * identity must live on the storage connection.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function factorReset(Identity $identity): int
    {
        return $this->factorRevocations->reset($identity);
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
