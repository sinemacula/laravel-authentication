<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Routing\UrlGenerator;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\IdentityLock;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Delivery\QueuedDelivery;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\IdentifierChangeRequested;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Sessions\RecentAuthentication;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * Requests changes of identifier for the identifier change service, once it has
 * checked the configuration.
 *
 * First, in order, on the identity's row as stored (read again by key on the
 * write connection): the proof of a recent authentication, the new identifier
 * (one the type's normaliser accepts, and not the current one), and a slot of
 * the `identifier_change` limits, counted on the new identifier, on the
 * identity and on the IP address. Each refusal is answered and reported by
 * `AuthenticationFailed` (flow `identifier_change`, with the identifier as
 * given), and writes nothing. Whether another identity holds the new identifier
 * is not looked at, so the answer says nothing about it. The limiter counts
 * before the transaction below opens, never inside it (see
 * `RecentAuthentication`).
 *
 * Then, in one transaction on the identity's connection that first locks the
 * identity's row (see `IdentityLock`), the proof must still stand and the new
 * identifier still differ from the current one, both as the locked row reads: a
 * password write, which cancels the pending changes, and a bulk revocation,
 * which waits on the lock of the device that proves the request, fall before
 * that check or after the change is written, never in between. A refusal there
 * gives the `identifier_change` slots back. The current identifier, and whether
 * it is verified, are read from the row as locked (the instance given, once it
 * is no longer stored).
 *
 * Then a code is issued, for a change proven by code; the pending change is
 * written in place of any the identity had for the type, through any guard, and
 * the code of the one it replaced is invalidated, so the newest request wins;
 * and the code's delivery is queued, or the link signed. Once committed,
 * `IdentifierChangeRequested` is dispatched. A change proven by code waits no
 * longer than its code works.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ChangeRequests
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The guard the change is requested through. */
        private JwtGuard $guard,

        /** Container the settings, limiter, engine, URL generator and delivery are resolved from. */
        private Container $container,
    ) {}

    /**
     * Request the change, proven by code, or by a link to the route and
     * parameters `$link` holds.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  string  $identifier
     * @param  \SineMacula\Laravel\Authentication\Sessions\Reauthentication  $proof
     * @param  ?array{0: string, 1: array<string, mixed>}  $link
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Throwable
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function request(
        HasChangeableIdentifiers&Identity&Model $identity,
        string $type,
        #[\SensitiveParameter] string $identifier,
        Reauthentication $proof,
        ?array $link,
        EventContext $context,
    ): IdentifierChangeRequest {
        $now      = CarbonImmutable::now()->startOfSecond();
        $settings = new IdentifierChangeSettings($this->container->make(Repository::class));
        $recent   = new RecentAuthentication($this->guard, $this->container, $settings->recentAuthenticationSeconds(), $now);
        $before   = self::stored($identity);
        $checked  = $this->checked($identity, $before, $type, $identifier, $proof, $recent, $context);

        if ($checked instanceof IdentifierChangeRequest) {
            return $checked;
        }

        // `#[\SensitiveParameter]` does not cover what a closure captures,
        // which a dump of the trace shows.
        $given   = new \SensitiveParameterValue($identifier);
        $stands  = static fn (Identity $stored): bool => $recent->stands($before, $stored, $proof);
        $expires = $now->addSeconds($settings->ttlSeconds());

        $requested = $identity->getConnection()->transaction(function () use ($identity, $type, $given, $stands, $link, $context, $now, $expires): IdentifierChangeRequest|int {

            $stored     = IdentityLock::acquire($identity) ?? $identity;
            $identifier = $given->getValue();
            $previous   = WriteConnection::during($stored, static fn (): ?string => $stored->getIdentifierForVerification($type));
            $verified   = WriteConnection::during($stored, static fn (): bool => $stored->hasVerifiedIdentifier($type));

            $normalised = $stands($stored)
                ? $this->accepted($type, $previous, $context, $identifier)
                : $this->refuse(IdentifierChangeRequest::reauthenticationRequired(), FailureReason::REAUTHENTICATION_REQUIRED, $context, $identifier);

            if (!is_string($normalised)) {
                return $normalised;
            }

            $change = new RequestedChange($type, $previous, $verified, $normalised, Str::uuid()->toString(), $now, $expires);

            return $this->write($identity, $change, $link, $context);
        });

        if ($requested instanceof IdentifierChangeRequest && !$requested->isSent()) {
            $this->container->make(AttemptLimiter::class)->release($checked);
        }

        return is_int($requested) ? $this->refuse(IdentifierChangeRequest::rateLimited($requested), FailureReason::RATE_LIMITED, $context, $identifier, $requested) : $requested;
    }

    /**
     * Check the request before its transaction, as the class describes, on the
     * identity's row as read before the proof: the refusal, or the slots of the
     * `identifier_change` limits it took.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity  $before
     * @param  string  $type
     * @param  string  $identifier
     * @param  \SineMacula\Laravel\Authentication\Sessions\Reauthentication  $proof
     * @param  \SineMacula\Laravel\Authentication\Sessions\RecentAuthentication  $recent
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest|\SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Throwable
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function checked(
        Identity&Model $identity,
        HasChangeableIdentifiers&Identity $before,
        string $type,
        #[\SensitiveParameter] string $identifier,
        Reauthentication $proof,
        RecentAuthentication $recent,
        EventContext $context,
    ): AttemptReservation|IdentifierChangeRequest {
        $refused = $this->unauthenticated($recent, $identity, $proof, $context, $identifier);

        if ($refused !== null) {
            return $refused;
        }

        $current    = WriteConnection::during($before, static fn (): ?string => $before->getIdentifierForVerification($type));
        $normalised = $this->accepted($type, $current, $context, $identifier);

        return is_string($normalised) ? $this->limited($identity, $type, $normalised, $context, $identifier) : $normalised;
    }

    /**
     * The identity's row as stored, read by key on the write connection without
     * scopes or eager loads, or the instance given once it is no longer stored.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  TModel  $identity
     * @return TModel
     */
    private static function stored(Model $identity): Model
    {
        return $identity->newModelQuery()->useWritePdo()->whereKey($identity->getKey())->first() ?? $identity;
    }

    /**
     * The refusal of a request whose proof does not show a recent enough
     * authentication, or `null`.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\RecentAuthentication  $recent
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Sessions\Reauthentication  $proof
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  string  $identifier
     * @return ?\SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Throwable
     */
    private function unauthenticated(
        RecentAuthentication $recent,
        Identity&Model $identity,
        Reauthentication $proof,
        EventContext $context,
        #[\SensitiveParameter] string $identifier,
    ): ?IdentifierChangeRequest {
        $refusal = $recent->refusal($identity, $proof, $context->client->ip);

        return match (true) {
            $refusal === null => null,
            is_int($refusal)  => $this->refuse(IdentifierChangeRequest::rateLimited($refusal), FailureReason::RATE_LIMITED, $context, $identifier, $refusal),
            default           => $this->refuse(IdentifierChangeRequest::reauthenticationRequired(), $refusal, $context, $identifier),
        };
    }

    /**
     * The new identifier in its normal form, or the refusal of one the type's
     * normaliser rejects, or that, in its normal form, is the identity's
     * current one in its canonical form.
     *
     * @param  string  $type
     * @param  ?string  $current
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  string  $identifier
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest|string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function accepted(
        string $type,
        #[\SensitiveParameter] ?string $current,
        EventContext $context,
        #[\SensitiveParameter] string $identifier,
    ): IdentifierChangeRequest|string {
        $normalised = $this->container->make(IdentifierNormalisers::class)->get($type)->normalise($identifier);

        if ($normalised === null) {
            return $this->refuse(IdentifierChangeRequest::identifierInvalid(), FailureReason::INVALID_CREDENTIALS, $context, $identifier);
        }

        $canonical = $current === null ? null : $this->container->make(IdentifierVerifier::class)->canonical($type, $current);

        return $canonical !== null && hash_equals($canonical, $normalised)
            ? $this->refuse(IdentifierChangeRequest::identifierUnchanged(), FailureReason::INVALID_CREDENTIALS, $context, $identifier)
            : $normalised;
    }

    /**
     * Take a slot of the `identifier_change` limits for the new identifier, the
     * identity and the IP address: the slots taken, or the refusal when one has
     * none left.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  string  $normalised
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  string  $identifier
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest|\SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function limited(
        Identity $identity,
        string $type,
        #[\SensitiveParameter] string $normalised,
        EventContext $context,
        #[\SensitiveParameter] string $identifier,
    ): AttemptReservation|IdentifierChangeRequest {
        $reservation = $this->container->make(AttemptLimiter::class)->acquire(
            new AttemptSubject($this->guard->getName(), AttemptFlow::IDENTIFIER_CHANGE, $normalised, $type, $context->client->ip, AccountAttempts::account($identity)),
        );

        $retryAfter = $reservation->retryAfter;

        if ($retryAfter === null) {
            return $reservation;
        }

        return $this->refuse(IdentifierChangeRequest::rateLimited($retryAfter), FailureReason::RATE_LIMITED, $context, $identifier, $retryAfter);
    }

    /**
     * Write the change as the class describes; when the engine refuses to issue
     * the code, nothing is written and the seconds until it would are returned.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\IdentifierChanges\RequestedChange  $change
     * @param  ?array{0: string, 1: array<string, mixed>}  $link
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return int|\SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    private function write(Identity&Model $identity, RequestedChange $change, ?array $link, EventContext $context): IdentifierChangeRequest|int
    {
        $guard   = $this->guard->getName();
        $codes   = $this->container->make(OneTimeCodes::class);
        $binding = CodeBinding::identifierChange($guard, $change->type, $change->identifier, $identity, $change->requestId);
        $issued  = $link === null ? $codes->issueFirst($binding, $change->requestedAt) : null;

        if (is_int($issued)) {
            return $issued;
        }

        $change   = $issued === null ? $change : $change->expiringBy($issued->expiresAt);
        $replaced = PendingChanges::write($identity, $guard, $change);

        if ($replaced !== null) {
            $codes->invalidate([PendingChanges::binding($replaced, $identity)]);
        }

        $this->deliver($identity, $binding, $issued, $change, $context);

        return IdentifierChangeRequest::sent($change->expiresAt, $link === null ? null : (new ChangeLinks($this->container->make(UrlGenerator::class)))->sign(
            $link[0],
            $link[1],
            $guard,
            (string) IdentifierCoercion::stringify($identity->getAuthIdentifier()),
            $change,
        ));
    }

    /**
     * Once the request commits, queue the code's delivery, when one was issued,
     * and dispatch `IdentifierChangeRequested`.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  ?\SineMacula\Laravel\Authentication\Codes\IssuedCode  $issued
     * @param  \SineMacula\Laravel\Authentication\IdentifierChanges\RequestedChange  $change
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function deliver(Identity&Model $identity, CodeBinding $binding, ?IssuedCode $issued, RequestedChange $change, EventContext $context): void
    {
        $container = $this->container;
        $events    = $this->guard->getDispatcher();
        $event     = new IdentifierChangeRequested($context, $change->type, $change->identifier, $change->expiresAt);

        if ($issued !== null) {
            $container->make(QueuedDelivery::class)->dispatch(new SendIdentifierChangeCode($binding, $issued, $identity, $change->requestId), $identity);
        }

        (new AfterCommit(static fn (): mixed => $container->bound('db.transactions') ? $container->make('db.transactions') : null))
            ->run($identity, static function () use ($events, $event): void {
                $events->dispatch($event);
            });
    }

    /**
     * Report a refused request with `AuthenticationFailed` and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest  $request
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  string  $identifier
     * @param  ?int  $retryAfter
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest
     */
    private function refuse(
        IdentifierChangeRequest $request,
        FailureReason $reason,
        EventContext $context,
        #[\SensitiveParameter] string $identifier,
        ?int $retryAfter = null,
    ): IdentifierChangeRequest {
        $this->guard->getDispatcher()->dispatch(new AuthenticationFailed($context, AuthenticationFlow::IDENTIFIER_CHANGE, $reason, $identifier, $retryAfter));

        return $request;
    }
}
