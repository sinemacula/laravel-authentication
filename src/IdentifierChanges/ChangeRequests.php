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
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Delivery\QueuedDelivery;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\IdentifierChangeRequested;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\AccountAttempts;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Sessions\RecentAuthentication;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * Requests changes of identifier for the identifier change service, once it has
 * checked the configuration: in order, the proof of a recent authentication,
 * the new identifier (one the type's normaliser accepts, and not the current
 * one), and a slot of the `identifier_change` limits, counted on the new
 * identifier, on the identity and on the IP address. Each refusal is answered
 * and reported by `AuthenticationFailed` (flow `identifier_change`, with the
 * identifier as given). Whether another identity holds the new identifier is
 * not looked at, so the answer says nothing about it.
 *
 * Then, in one transaction on the identity's connection: a code is issued, for
 * a change proven by code; the pending change is written in place of any the
 * identity had for the type, through any guard, and the code of the one it
 * replaced is invalidated, so the newest request wins; and the code's delivery
 * is queued, or the link signed. Once committed, `IdentifierChangeRequested` is
 * dispatched. A change proven by code waits no longer than its code works.
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
        $now        = CarbonImmutable::now()->startOfSecond();
        $settings   = new IdentifierChangeSettings($this->container->make(Repository::class));
        $normalised = $this->container->make(IdentifierNormalisers::class)->get($type)->normalise($identifier);
        $previous   = WriteConnection::during($identity, static fn (): ?string => $identity->getIdentifierForVerification($type));

        $refused = $this->unauthenticated($identity, $proof, $settings, $context, $identifier, $now)
            ?? $this->unacceptable($type, $previous, $normalised, $context, $identifier)
            ?? $this->limited($identity, $type, (string) $normalised, $context, $identifier);

        if ($refused !== null) {
            return $refused;
        }

        $change    = new RequestedChange($type, $previous, (string) $normalised, Str::uuid()->toString(), $now, $now->addSeconds($settings->ttlSeconds()));
        $requested = $identity->getConnection()->transaction(fn (): IdentifierChangeRequest|int => $this->write($identity, $change, $link, $context));

        return is_int($requested) ? $this->refuse(IdentifierChangeRequest::rateLimited($requested), FailureReason::RATE_LIMITED, $context, $identifier, $requested) : $requested;
    }

    /**
     * The refusal of a request whose proof does not show a recent enough
     * authentication, or `null`.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Sessions\Reauthentication  $proof
     * @param  \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeSettings  $settings
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  string  $identifier
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Throwable
     */
    private function unauthenticated(
        Identity&Model $identity,
        Reauthentication $proof,
        IdentifierChangeSettings $settings,
        EventContext $context,
        #[\SensitiveParameter] string $identifier,
        CarbonImmutable $now,
    ): ?IdentifierChangeRequest {
        $refusal = (new RecentAuthentication($this->guard, $this->container, $settings->recentAuthenticationSeconds(), $now))->refusal($identity, $proof, $context->client->ip);

        return match (true) {
            $refusal === null => null,
            is_int($refusal)  => $this->refuse(IdentifierChangeRequest::rateLimited($refusal), FailureReason::RATE_LIMITED, $context, $identifier, $refusal),
            default           => $this->refuse(IdentifierChangeRequest::reauthenticationRequired(), $refusal, $context, $identifier),
        };
    }

    /**
     * The refusal of a new identifier the type's normaliser rejects, or that,
     * in its normal form, is the identity's current one in its canonical form;
     * otherwise `null`.
     *
     * @param  string  $type
     * @param  ?string  $current
     * @param  ?string  $normalised
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  string  $identifier
     * @return ?\SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function unacceptable(
        string $type,
        #[\SensitiveParameter] ?string $current,
        #[\SensitiveParameter] ?string $normalised,
        EventContext $context,
        #[\SensitiveParameter] string $identifier,
    ): ?IdentifierChangeRequest {
        if ($normalised === null) {
            return $this->refuse(IdentifierChangeRequest::identifierInvalid(), FailureReason::INVALID_CREDENTIALS, $context, $identifier);
        }

        $canonical = $current === null ? null : $this->container->make(IdentifierVerifier::class)->canonical($type, $current);

        return $canonical !== null && hash_equals($canonical, $normalised)
            ? $this->refuse(IdentifierChangeRequest::identifierUnchanged(), FailureReason::INVALID_CREDENTIALS, $context, $identifier)
            : null;
    }

    /**
     * Take a slot of the `identifier_change` limits for the new identifier, the
     * identity and the IP address: the refusal when one has none left,
     * otherwise `null`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  string  $normalised
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  string  $identifier
     * @return ?\SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest
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
    ): ?IdentifierChangeRequest {
        $retryAfter = $this->container->make(AttemptLimiter::class)->acquire(
            new AttemptSubject($this->guard->getName(), AttemptFlow::IDENTIFIER_CHANGE, $normalised, $type, $context->client->ip, AccountAttempts::account($identity)),
        )->retryAfter;

        return $retryAfter === null ? null : $this->refuse(IdentifierChangeRequest::rateLimited($retryAfter), FailureReason::RATE_LIMITED, $context, $identifier, $retryAfter);
    }

    /**
     * Inside the request's transaction: issue the code (for a change proven by
     * code), write the pending change, invalidate the code of the one it
     * replaced, queue the code's delivery or sign the link, and dispatch
     * `IdentifierChangeRequested` once committed. When the engine refuses to
     * issue the code, nothing is written and the seconds until it would are
     * returned.
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
        $issued  = $link === null ? $codes->issue($binding, $change->requestedAt) : null;

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
