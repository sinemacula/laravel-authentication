<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Sessions\ExternalSignIn;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;

/**
 * The session service's external sign-in, which `ExternalSignIn` takes from the
 * result to the linked identity before the service starts its session as it
 * starts any other.
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
}
