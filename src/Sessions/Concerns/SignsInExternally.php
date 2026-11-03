<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\ExternalReauthentication;
use SineMacula\Laravel\Authentication\Sessions\ExternalSignIn;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;

/**
 * The session service's external sign-in, which `ExternalSignIn` takes from the
 * result to the linked identity before the service starts its session as it
 * starts any other, and its external reauthentication and standing, which
 * `ExternalReauthentication` carries out.
 *
 * It sits in a trait only so the service stays within the number of methods one
 * class may declare.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait SignsInExternally
{
    /** @var \SineMacula\Laravel\Authentication\Sessions\ExternalSignIn Maps external results to their linked identities, on the guard's context. */
    private readonly ExternalSignIn $externalSignIns;

    /** @var \SineMacula\Laravel\Authentication\Sessions\ExternalReauthentication Reauthenticates sessions through the links that established them, on the guard's context. */
    private readonly ExternalReauthentication $externalReauthentications;

    /**
     * Sign in with a result an external identity provider verified, which a
     * trusted server-side adapter hands over (from a handoff it redeemed, say)
     * and never a client: the session starts for the identity the link contract
     * links the result's connection, issuer and subject to, under the method
     * `external_provider`.
     *
     * In order: the provider's session deadline joins the context's
     * (`SignInContext::withNotAfter()`), so the earlier of the two caps the
     * session; the application policy must allow `external_provider`
     * (`method_not_allowed`, the link contract never asked); the link contract
     * must link the result to an identity (`ExternalResultUnlinked`, then
     * `external_result_unlinked`); then, from the linked identity on, the
     * sign-in follows the order `start()` does: the identity reloaded through
     * the guard's provider (`identity_unknown`), admitted, a deadline already
     * passed refused as `session_expired`, the principal the context names or
     * the only one selected, or a choice left outstanding, the identity-level
     * factor policy, the selected principal's tenant, and that tenant's
     * authentication policy, judged against the provider's proof: one requiring
     * a connection other than the result's refuses it as `sso_required`, and a
     * further factor it requires is outstanding as the identity's own is. No
     * attempt limit or timebox applies, and no `Attempting` is dispatched:
     * nothing is guessed here.
     *
     * The session's first proof is the provider's: the connection as its
     * channel, the private `urn:sinemacula:amr:external_provider` `amr` value,
     * and the provider's authentication time (now, when it gave none or one
     * after now). Its provenance (the connection and tenant, the provider's
     * time and deadline, the policy version and the id of the link) is written
     * with it once, pending or active, and never rewritten. Call it inside the
     * transaction the adapter takes its own locks in, on the storage
     * connection: the session's writes are a savepoint there, the link contract
     * is asked before them, and the reports and the guard's bind wait for the
     * commit. A database error, a serialization failure included, and an
     * exception from the link contract propagate, so the whole transaction can
     * be retried. Failures are results: Laravel's `Failed` and then
     * `AuthenticationFailed` (flow `sign_in`) report them.
     *
     * @param  \SineMacula\Laravel\Authentication\External\ExternalResult  $result
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function signInExternally(ExternalResult $result, ?SignInContext $context = null): SignInResult
    {
        $method    = SignInMethodManager::EXTERNAL_METHOD;
        $transport = $this->transport();
        $context   = ($context ?? SignInContext::fromRequest($this->context->request()))->withNotAfter($result->sessionNotAfter);
        $resolved  = $this->externalSignIns->resolve($result, $context);
        $outcome   = $resolved instanceof Refused ? $resolved : $this->startFor($resolved[0], $context->principal, $method, $context, $resolved[1]);

        return $outcome instanceof Refused ? $this->fail($outcome, $method, $context, null, []) : $this->bound($outcome, $transport);
    }

    /**
     * Reauthenticate the session with a result an external identity provider
     * verified, which a trusted server-side adapter hands over (from a
     * reauthentication handoff it redeemed, say), and issue the session a new
     * access token only: the session, its refresh token, its deadlines and its
     * provenance are kept.
     *
     * Only on an application that allows `external_provider`
     * (`method_not_allowed`), only for this guard's live, active session of a
     * person (`session_unknown`, `session_guard_mismatch`, `session_revoked`,
     * `session_pending`, `session_expired`, `machine_identity`), only with the
     * time the provider authenticated the identity (`proof_invalid`, also when
     * that is before the session began), and only through the very link that
     * established the session: the link contract must link the result to an
     * identity (`ExternalResultUnlinked`, then `external_result_unlinked`),
     * that identity must own the session, and the session's provenance must
     * record exactly the result's connection and the link's id
     * (`link_mismatch`, as for a session established through another link or
     * through none). With the proof recorded, the session must still meet its
     * tenant's authentication policy, as every redemption must: a connection
     * the tenant no longer admits is `sso_required` and a further factor it now
     * requires and the session does not meet `additional_factor_required`, the
     * proof rolled back and the session left for its next refresh.
     *
     * The proof (`external_reauthentication`) is timed when the provider
     * authenticated the identity (now, when that is after now), so the new
     * token's `auth_time` is the later of the session's and the provider's. Its
     * `amr` gains the provider's private value, and `mfa`, only when the
     * evidence contract accepts the result's evidence (as multifactor, for
     * `mfa`); otherwise only `auth_time` moves. Call it inside the transaction
     * the adapter takes its own locks in, on the storage connection: the
     * session's row is locked last, after them, and a database error, a
     * serialization failure included, propagates. Once committed,
     * `Reauthenticated` (method `external_provider`) reports it; a refusal
     * reports `AuthenticationFailed` (flow `reauthentication`) and is answered,
     * never thrown.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\External\ExternalResult  $result
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \Throwable
     */
    public function reauthenticateExternally(Session $session, ExternalResult $result): AccessTokenResult
    {
        return $this->externalReauthentications->reauthenticate($session, $result);
    }

    /**
     * Say whether the session stands for an external reauthentication by the
     * identity through the connection and the link: `null` when it is this
     * guard's live, active session of a person, owned by the identity and
     * established through exactly that connection and that link, on an
     * application that allows `external_provider`; otherwise why not
     * (`method_not_allowed`, `session_unknown`, `session_guard_mismatch`,
     * `session_revoked`, `session_pending`, `session_expired`,
     * `machine_identity`, `link_mismatch`).
     *
     * With no link given, a session established through that connection and any
     * link stands (one recorded with no link never does): for an adapter asked,
     * when a reauthentication flow starts, whether the identity is signed in
     * through the connection at all, before the exact link is known. Asked
     * outside a transaction, the session is read on the write connection and
     * nothing is locked. Asked inside one on the session model's connection,
     * after the adapter's own locks, the row stays locked until the transaction
     * ends, so nothing revokes the session before the adapter renews it. It
     * writes and reports nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $connectionId
     * @param  ?string  $linkId
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public function externalStanding(Session $session, Identity $identity, string $connectionId, ?string $linkId = null): ?FailureReason
    {
        return $this->externalReauthentications->standing($session, $identity, $connectionId, $linkId);
    }
}
