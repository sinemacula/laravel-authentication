<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Admission\SignInAdmission;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\AdditionalFactorRequired;
use SineMacula\Laravel\Authentication\Events\DeviceCreated;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;

/**
 * Takes an admitted sign-in to its session, or to a pending sign-in when the
 * additional-factor policy asks for a further factor, and schedules what
 * reports it: `AdditionalFactorRequired` once a pending sign-in is committed,
 * `DeviceCreated` (for a new device) and `SignedIn` once a session is committed
 * on the device's connection, and the slot give-back of the pending sign-in a
 * session completes once that sign-in's delete is committed.
 *
 * It never binds the guard. The session service binds after it returns, so
 * everything a session's commit reports is already scheduled when the bind
 * starts, and a bind listener that throws cannot withhold it.
 *
 * It runs on the guard's context: its events carry the client of the sign-in
 * they report, and go to the context's dispatcher as it is when they are
 * dispatched.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionEstablishment
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionWriter  $writer
     * @param  \SineMacula\Laravel\Authentication\Sessions\DeviceProof  $proof
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingSignIns  $pendings
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard whose sessions are established. */
        private GuardContext $context,

        /** Writes the device and issues the pair. */
        private SessionWriter $writer,

        /** Decides which device a client proved it holds. */
        private DeviceProof $proof,

        /** Issues and completes the sign-ins waiting for a further factor. */
        private PendingSignIns $pendings,

        /** Defers the lifecycle events, and a completion's released slots, until the writes commit. */
        private AfterCommit $afterCommit,

        /** Container the sign-in policies and the attempt limiter are resolved from. */
        private Container $container,
    ) {}

    /**
     * Take an admitted sign-in to its session: check the client's proof of an
     * existing device, then establish the session on it or on a new device.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  string  $method
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  ?list<array<string, string>>  $attemptWindows
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function proceed(Admitted $admitted, string $method, ?string $identifierType, SignInContext $context, ?array $attemptWindows = null): SignInResult
    {
        $proven = $context->refreshToken === null
            ? null
            : $this->proof->provenDevice($this->context->name(), $admitted, $context->refreshToken);

        return $this->establish($admitted, $proven, $method, $identifierType, $context, CarbonImmutable::now()->startOfSecond(), $attemptWindows);
    }

    /**
     * Ask the additional-factor policy about the sign-in on the proven device
     * (or none): when it requires a further factor, hand out a pending sign-in
     * that remembers the device and the attempt-limit slots the sign-in took,
     * and dispatch `AdditionalFactorRequired` once it is committed; otherwise
     * start the session, continuing the proven device or creating one. When the
     * proven device changed before it could be continued, the sign-in is
     * reconsidered without it, factor policy included; it never retries the
     * device. A session that completes a spent pending sign-in (a choice of
     * principal) gives back the slots that sign-in took once committed, and a
     * device it creates records the client the sign-in began from.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice)|null  $proven
     * @param  string  $method
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?list<array<string, string>>  $attemptWindows
     * @param  ?\SineMacula\Laravel\Authentication\Models\PendingSignIn  $spent
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function establish(
        Admitted $admitted,
        (EloquentDevice&Model)|null $proven,
        string $method,
        ?string $identifierType,
        SignInContext $context,
        CarbonImmutable $now,
        ?array $attemptWindows,
        ?PendingSignIn $spent = null,
    ): SignInResult {
        $admitted = $admitted->on($proven);

        if ($this->requiresAdditionalFactor($admitted, $method, $context)) {

            $pending = $this->pendings->issue($this->context->name(), $admitted, $method, $identifierType, $context, $now, $attemptWindows);
            $event   = new AdditionalFactorRequired(
                new EventContext($pending->guard, $context->client, $pending->identity, $pending->principal, $pending->tenant, $pending->provenDevice, $method),
                $pending->expiresAt,
            );

            $this->afterCommit->run(new PendingSignIn, fn () => $this->context->dispatch($event));

            return SignInResult::pendingFactor($pending);
        }

        $session = $this->write($admitted, $proven, $method, $identifierType, $context, $now, $spent === null ? null : PendingSignIns::origin($spent));

        return $session === null
            ? $this->establish($admitted, null, $method, $identifierType, $context, $now, $attemptWindows, $spent)
            : $this->signedIn($session, $admitted, $context, $spent);
    }

    /**
     * Use the pending sign-in up, check it again and write its session, in one
     * transaction on the pending sign-in's connection, then schedule what
     * reports the session and the give-back of the slots its sign-in took.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\FoundPendingSignIn  $found
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function complete(FoundPendingSignIn $found, SignInContext $context, CarbonImmutable $now): Refused|SignInResult
    {
        $outcome = $found->pending->getConnection()->transaction(fn (): array|Refused => $this->completeWith($found, $context, $now));

        if ($outcome instanceof Refused) {
            return $outcome;
        }

        [$admitted, $session] = $outcome;

        return $this->signedIn($session, $admitted, $context, $found->pending);
    }

    /**
     * Use the pending sign-in up, check it again, and write its session, all in
     * the caller's transaction.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\FoundPendingSignIn  $found
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \Carbon\CarbonImmutable  $now
     * @return array{0: \SineMacula\Laravel\Authentication\Admission\Admitted, 1: \SineMacula\Laravel\Authentication\Sessions\SignedInSession}|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function completeWith(FoundPendingSignIn $found, SignInContext $context, CarbonImmutable $now): array|Refused
    {
        $factor = $found->factor;

        SessionPreconditions::assertHoldsDevices($factor->identity);

        $audience = $this->container->make(AudiencePolicy::class);
        $admitted = match (true) {
            !$this->pendings->consume($found, $now)                           => new Refused(FailureReason::PENDING_INVALID),
            !$audience->allowsMethod($this->context->name(), $factor->method) => new Refused(FailureReason::METHOD_NOT_ALLOWED, $factor->identity, $factor->principal),
            default                                                           => (new SignInAdmission($audience))->admit(
                $this->context->name(),
                $factor->identity,
                static fn (): Principal => $factor->principal,
                FailureReason::PRINCIPAL_UNRESOLVED,
                $found->pending->identifier_type,
            ),
        };

        if ($admitted instanceof Refused) {
            return $admitted;
        }

        $origin  = PendingSignIns::origin($found->pending);
        $type    = $found->pending->identifier_type;
        $session = $this->write($admitted->on($found->device), $found->device, $factor->method, $type, $context, $now, $origin)
            ?? $this->write($admitted, null, $factor->method, $type, $context, $now, $origin);

        return [$admitted->on($session->device), $session];
    }

    /**
     * Write the session of an admitted sign-in, with the guard's lifetimes for
     * its principal: continue the proven device, or create one, recorded as
     * created from the origin's client when that differs from the context's (a
     * completion records where its sign-in began). The device records the
     * method and the type of identifier the sign-in used, which a later switch
     * of principal admits its target with. `null` when the proven device
     * changed before it could be continued.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice)|null  $proven
     * @param  string  $method
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $origin
     * @return ($proven is null ? \SineMacula\Laravel\Authentication\Sessions\SignedInSession : ?\SineMacula\Laravel\Authentication\Sessions\SignedInSession)
     *
     * @throws \Throwable
     */
    private function write(
        Admitted $admitted,
        (EloquentDevice&Model)|null $proven,
        string $method,
        ?string $identifierType,
        SignInContext $context,
        CarbonImmutable $now,
        ?ClientContext $origin = null,
    ): ?SignedInSession {
        $lifetimes = $this->container->make(AudiencePolicy::class)->lifetimes($this->context->name(), $admitted->principal);

        return $proven === null
            ? $this->writer->create($admitted, $method, $identifierType, $context, $lifetimes, $now, $origin ?? $context->client)
            : $this->writer->continueOn($proven, $admitted, $method, $identifierType, $context, $lifetimes, $now);
    }

    /**
     * Whether the additional-factor policy asks the sign-in for a further
     * factor.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function requiresAdditionalFactor(Admitted $admitted, string $method, SignInContext $context): bool
    {
        return $this->container->make(AdditionalFactorPolicy::class)->requiresAdditionalFactor(new AdditionalFactorContext(
            $this->context->name(),
            $admitted->identity,
            $admitted->principal,
            $admitted->tenant,
            $method,
            $context->client,
            $context->clientName,
            $context->platform,
            $admitted->device,
        ));
    }

    /**
     * Schedule the reports of a written session, and answer it:
     * `DeviceCreated`, for a new device, and `SignedIn` once the session is
     * committed on the device's own connection, and the give-back of the slots
     * of the pending sign-in it completes, if any, once that sign-in's delete
     * is committed on its own.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  ?\SineMacula\Laravel\Authentication\Models\PendingSignIn  $spent
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     */
    private function signedIn(SignedInSession $session, Admitted $admitted, SignInContext $context, ?PendingSignIn $spent): SignInResult
    {
        $event    = new EventContext($this->context->name(), $context->client, $session->identity, $session->principal, $admitted->tenant, $session->device, $session->method);
        $created  = $session->deviceCreated ? new DeviceCreated($event) : null;
        $signedIn = new SignedIn($event, $session->deviceCreated, false);

        $this->afterCommit->run($session->device, function () use ($created, $signedIn): void {

            if ($created !== null) {
                $this->context->dispatch($created);
            }

            $this->context->dispatch($signedIn);
        });

        // A rolled-back completion restores the pending sign-in, whose token
        // can then be completed again: giving its slots back before the commit,
        // on a counter connection of its own, would give them back twice.
        if ($spent !== null) {
            $this->afterCommit->run($spent, fn () => $this->giveBack($spent));
        }

        return SignInResult::signedIn($session);
    }

    /**
     * Give back the attempt-limit slots a committed completion's sign-in took.
     *
     * A failure is reported, not thrown: the session already stands, and
     * Laravel runs a commit's callbacks in order without catching, so a throw
     * here would stop the callbacks queued after this one (another session's
     * events, the caller's own) from running. The slots not given back stay
     * counted.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\PendingSignIn  $pending
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function giveBack(PendingSignIn $pending): void
    {
        try {
            foreach (PendingSignIns::reservations($pending) as $reservation) {
                $this->container->make(AttemptLimiter::class)->release($reservation);
            }
        } catch (\Throwable $exception) {
            $this->container->make(ExceptionHandler::class)->report($exception);
        }
    }
}
