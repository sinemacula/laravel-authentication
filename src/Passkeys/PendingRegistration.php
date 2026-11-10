<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Failed;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\IdentityLock;
use SineMacula\Laravel\Authentication\Database\SharedConnection;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Sessions\PendingLookup;
use SineMacula\Laravel\Authentication\Sessions\SessionPreconditions;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * The part of a passkey registration that enrols a factor on a pending sign-in
 * (see `PasskeyService::register()`): reading the pending credential handed in,
 * holding the pending session it names, and reporting the registration refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PendingRegistration
{
    /** @var string What a registration on a pending sign-in is called in the shared-connection refusal. */
    private const string FLOW = 'A passkey registration on a pending sign-in';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard the passkey is registered on. */
        private GuardContext $context,

        /** Container the configuration is resolved from. */
        private Container $container,
    ) {}

    /**
     * The pending credential handed in, as `SessionPreconditions` reads it, or
     * `null` for an ordinary registration. Given one, the identity must live on
     * the storage connection. Raised before anything is read or consumed.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Secrets\Secret|string|null  $pending
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Secrets\Secret|string|null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function credential(#[\SensitiveParameter] FailureReason|Secret|string|null $pending, Identity&Model $owner): Refused|Secret|string|null
    {
        if ($pending === null) {
            return null;
        }

        $presented = SessionPreconditions::pendingCredential($pending);

        SharedConnection::assert($owner, self::FLOW, $this->container->make(Repository::class));

        return $presented;
    }

    /**
     * The pending credential handed in as the secret the gate is given, or the
     * registration's refusal: `cross_site_request` for a cookie application's
     * client that did not come from a page of its own site, `pending_invalid`
     * for `pending_invalid` handed in or a credential that is empty; `null`
     * for an ordinary registration. Read before the pending session, and so
     * before any query.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Secrets\Secret|string|null  $presented
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeyRegistration|\SineMacula\Laravel\Authentication\Secrets\Secret|null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function presented(
        #[\SensitiveParameter] Refused|Secret|string|null $presented,
        Identity&Model $owner,
        RelyingParty $rp,
        ClientContext $client,
    ): PasskeyRegistration|Secret|null {
        if ($presented === null) {
            return null;
        }

        $transport = RefreshTokenTransport::forGuard($rp->guard, $this->container->make(Repository::class));

        if (SessionPreconditions::crossSite($transport, $client) !== null) {
            return $this->refused($owner, $rp, $client, FailureReason::CROSS_SITE_REQUEST);
        }

        if ($presented instanceof Refused || $presented === '') {
            return $this->refused($owner, $rp, $client, FailureReason::PENDING_INVALID);
        }

        return $presented instanceof Secret ? $presented : new Secret($presented);
    }

    /**
     * Prove, under the locks held until the transaction ends, that the pending
     * credential names a live pending session of this guard whose owner is the
     * identity and, when the challenge was bound, the session it names. The
     * identity's row is locked first, then the session's, before the gate's own
     * locks and the passkey's row, as the package's lock order puts them. The
     * session is found as the pending-session actions find it
     * (`PendingLookup`), so a credential that names none of the guard's live
     * pending sessions fails here exactly as it does there.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $pending
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Passkeys\UnheldPendingSession
     */
    public function hold(Identity&Model $owner, ?ProofBinding $binding, #[\SensitiveParameter] Secret $pending): void
    {
        $found = IdentityLock::acquire($owner) === null ? null : (new PendingLookup($this->context))->find($pending, CarbonImmutable::now()->startOfSecond(), true);

        $session = $found[0] ?? null;
        $named   = $binding === null ? null : IdentifierCoercion::stringify($binding->sessionId);
        $held    = $session !== null
            && SessionOwnership::isOwner($session, $owner)
            && ($binding === null || IdentifierCoercion::stringify($session->getSessionIdentifier()) === $named);

        if (!$held) {
            throw new UnheldPendingSession;
        }
    }

    /**
     * Report a registration on a pending sign-in refused, as a pending action
     * refused is reported (Laravel's `Failed` and `AuthenticationFailed` for
     * the sign-in flow, carrying the client and the identity and never the
     * credential), and answer it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeyRegistration
     */
    public function refused(Identity&Model $owner, RelyingParty $rp, ClientContext $client, FailureReason $reason): PasskeyRegistration
    {
        $this->context->dispatch(new Failed($rp->guard, $owner, []));
        $this->context->dispatch(new AuthenticationFailed(new EventContext($rp->guard, $client, $owner), AuthenticationFlow::SIGN_IN, $reason));

        return $reason === FailureReason::CROSS_SITE_REQUEST ? PasskeyRegistration::crossSiteRequest() : PasskeyRegistration::pendingInvalid();
    }
}
