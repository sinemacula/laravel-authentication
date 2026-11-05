<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
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
     * `external_result_unlinked`); then the sign-in goes on from the linked
     * identity as `start()` does, judged against the provider's proof, a tenant
     * that requires another connection refusing it as `sso_required`. No
     * attempt limit or timebox applies, and no `Attempting` is dispatched:
     * nothing is guessed here. Unlike `start()`, it is not held to a cookie
     * application's same-site check: the provider's callback is a cross-site
     * navigation by design, and its defence against signing a browser into
     * another account is the provider flow's browser-bound state (the adapter's
     * `state` and nonce, bound to the browser that began the flow, and the
     * single-use handoff).
     *
     * The session's first proof is the provider's: the connection as its
     * channel, the private `urn:sinemacula:amr:external_provider` `amr` value,
     * and the provider's authentication time (now, when it gave none or one
     * after now). Its provenance (the connection and tenant, the provider's
     * time and deadline, the policy version, the id of the link and the
     * result's provider context) is written with it once, pending or active,
     * and never rewritten, after the link's connection guard, which a
     * revocation of the link or the connection writes too, so the two never
     * miss each other. Call it inside the transaction the adapter takes its own
     * locks in, on the storage connection: the link contract is asked and the
     * session written in a savepoint there, and the reports and the guard's
     * bind wait for the commit. Called outside one, it opens its own around
     * both, so a contract that locks the link it reads holds it until the
     * session commits; the connection guards order a sign-in against a
     * revocation but never ask the contract again, so they add to the adapter's
     * locks and never replace them. A database error, a serialisation failure
     * included, and an exception from the link contract propagate, so the whole
     * transaction can be retried. Once the session commits,
     * `ExternalResultRedeemed` (flow `sign_in`) follows the session's own
     * events, with the result's connection and request reference. Failures are
     * results: Laravel's `Failed` and then `AuthenticationFailed` (flow
     * `sign_in`) report them, with the connection and request reference too.
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
        $outcome   = SessionLookup::model()->getConnection()->transaction(function () use ($result, $context, $method): mixed {

            $resolved = $this->externalSignIns->resolve($result, $context);

            return $resolved instanceof Refused ? $resolved : $this->startFor($resolved[0], $context->principal, $method, $context, $resolved[1]);
        });

        return $outcome instanceof Refused ? $this->fail($outcome, $method, $context, null, [], null, $result) : $this->bound($outcome, $transport);
    }

    /**
     * Reauthenticate a session, by its identifier, with a result an external
     * identity provider verified, which a trusted server-side adapter hands
     * over (from a reauthentication handoff it redeemed, say), and issue the
     * session a new access token only: the session, its refresh token, its
     * deadlines and its provenance, provider context included, are kept (the
     * result's own provider context is not recorded). The identifier is the
     * session the handoff names, never the one the request happens to be
     * authenticated with; one that cannot be a key of the session model, or
     * names no session, is `session_unknown`.
     *
     * Only through the very link that established the session
     * (`external_result_unlinked`, `link_mismatch`), for this guard's live,
     * active session of a person (`session_guard_mismatch`, `session_revoked`,
     * `session_pending`, `session_expired`, `machine_identity`), on an
     * application that allows `external_provider` (`method_not_allowed`), with
     * the time the provider authenticated the identity, not before the session
     * began (`proof_invalid`), and only while the session, with the proof
     * recorded, still meets its tenant's authentication policy (`sso_required`,
     * `additional_factor_required`, the proof rolled back). The tenant's policy
     * and the evidence contract's `meets()` are asked under the session's row
     * lock, so neither may take a lock the adapter takes after the session's.
     * The new token's `auth_time` is the later of the session's and the
     * provider's; its `amr` changes only when the evidence contract accepts the
     * result's evidence.
     *
     * Call it inside the transaction the adapter takes its own locks in, on the
     * storage connection: the session's row is locked last, and a database
     * error, a serialization failure included, propagates. Once committed,
     * `Reauthenticated` (method `external_provider`) reports it, then
     * `ExternalResultRedeemed` (flow `reauthentication`) with the result's
     * connection and request reference; a refusal reports
     * `AuthenticationFailed` (flow `reauthentication`, with the connection and
     * request reference) and is answered, never thrown.
     *
     * @param  mixed  $sessionId
     * @param  \SineMacula\Laravel\Authentication\External\ExternalResult  $result
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \Throwable
     */
    public function reauthenticateExternally(mixed $sessionId, ExternalResult $result): AccessTokenResult
    {
        return $this->externalReauthentications->reauthenticate($sessionId, $result);
    }

    /**
     * Say whether a session, by its identifier (the one the adapter's flow
     * names), stands for an external reauthentication by the identity through
     * the connection and the link: `null` when it is this guard's live, active
     * session of a person, owned by the identity and established through
     * exactly that connection and that link, on an application that allows
     * `external_provider`; otherwise why not (`method_not_allowed`,
     * `session_unknown`, `session_guard_mismatch`, `session_revoked`,
     * `session_pending`, `session_expired`, `machine_identity`,
     * `link_mismatch`).
     *
     * With no link given, a session established through that connection and any
     * link stands (one recorded with no link never does): for an adapter asked,
     * when a reauthentication flow starts, whether the identity is signed in
     * through the connection at all, before the exact link is known. Asked
     * outside a transaction, the session is read on the write connection and
     * nothing is locked. Asked inside one on the session model's connection,
     * after the adapter's own locks, the row stays locked until the transaction
     * ends, so nothing revokes the session before the adapter renews it, and
     * its provenance is read current, so a key another sign-in reused after the
     * transaction's first read is judged on its own. It writes and reports
     * nothing.
     *
     * @param  mixed  $sessionId
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
    public function externalStanding(mixed $sessionId, Identity $identity, string $connectionId, ?string $linkId = null): ?FailureReason
    {
        return $this->externalReauthentications->standing($sessionId, $identity, $connectionId, $linkId);
    }
}
