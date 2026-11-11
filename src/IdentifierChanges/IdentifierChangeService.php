<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Routing\UrlGenerator;
use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;
use SineMacula\Laravel\Authentication\Codes\CodeKeys;
use SineMacula\Laravel\Authentication\Codes\CodeSettings;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\IdentifierChangeNotifier;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Database\IdentityLock;
use SineMacula\Laravel\Authentication\Database\SharedConnection;
use SineMacula\Laravel\Authentication\Delivery\QueuedDelivery;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Freshness\Operations;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\SignedLink;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;
use SineMacula\Laravel\Authentication\Models\IdentifierChange;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\RateLimiting\LimitedOutcome;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;

/**
 * The identifier change service of a JWT guard: changes an identity's email
 * address or phone number once the new one is proven.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentifierChangeService
{
    /** @var string What the flow is called in a connection refusal. */
    private const string FLOW = 'An identifier change';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard whose identities' identifiers the service changes. */
        private GuardContext $context,

        /** Container the settings, limiter, engine, URL generator and delivery are resolved from. */
        private Container $container,
    ) {}

    /**
     * Start a change of the identity's identifier of the type to the one given,
     * proven by a one-time code sent to it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  string  $identifier
     * @param  \SineMacula\Laravel\Authentication\Sessions\Reauthentication  $proof
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     *
     * @phpstan-impure
     */
    public function requestByCode(
        Identity $identity,
        string $type,
        #[\SensitiveParameter] string $identifier,
        Reauthentication $proof,
        ClientContext $client,
    ): IdentifierChangeRequest {
        $changeable = $this->changeable($identity, $type);

        (new CodeSettings($this->collaborator(Repository::class)))->validate();
        $this->assertCodeSender();

        return (new ChangeRequests($this->context, $this->container))->request($changeable, $type, $identifier, $proof, null, $this->eventContext($changeable, $client));
    }

    /**
     * Start a change of the identity's identifier of the type to the one given,
     * proven by a signed link to the named route.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  string  $identifier
     * @param  \SineMacula\Laravel\Authentication\Sessions\Reauthentication  $proof
     * @param  string  $route
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  array<string, mixed>  $parameters
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     *
     * @phpstan-impure
     */
    public function requestByLink(
        Identity $identity,
        string $type,
        #[\SensitiveParameter] string $identifier,
        Reauthentication $proof,
        string $route,
        ClientContext $client,
        array $parameters = [],
    ): IdentifierChangeRequest {
        $changeable = $this->changeable($identity, $type);

        $this->links()->assertRoute($route, $parameters);

        $context = $this->eventContext($changeable, $client);

        return (new ChangeRequests($this->context, $this->container))->request($changeable, $type, $identifier, $proof, [$route, $parameters], $context);
    }

    /**
     * Confirm the identity's pending change of the type with the code sent to
     * the new identifier, and make it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  string  $challengeId
     * @param  string  $code
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\RateLimiting\LimitedOutcome<\SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     *
     * @phpstan-impure
     */
    public function confirmByCode(Identity $identity, string $type, string $challengeId, #[\SensitiveParameter] string $code, ClientContext $client): LimitedOutcome
    {
        $changeable = $this->changeable($identity, $type);
        $context    = $this->eventContext($changeable, $client);
        $codes      = $this->collaborator(OneTimeCodes::class);
        $challenge  = $codes->isWellFormedChallenge($challengeId) ? $challengeId : null;

        $limiter     = $this->collaborator(AttemptLimiter::class);
        $reservation = $limiter->acquire(
            new AttemptSubject($this->context->name(), AttemptFlow::IDENTIFIER_CHANGE, null, null, $context->client->ip, AccountAttempts::account($changeable)),
        );

        if ($reservation->retryAfter !== null) {
            $retryAfter = $reservation->retryAfter;
            $failure    = new AuthenticationFailed($context, AuthenticationFlow::IDENTIFIER_CHANGE, FailureReason::RATE_LIMITED, retryAfter: $retryAfter, challengeId: $challenge);

            $this->context->dispatch($failure);

            return new LimitedOutcome(IdentifierChangeOutcome::RATE_LIMITED, $retryAfter);
        }

        if ($challenge === null || !$codes->isWellFormed($code)) {
            return new LimitedOutcome($this->refuseConfirmation(IdentifierChangeOutcome::INVALID, FailureReason::INVALID_CREDENTIALS, $context, $challenge));
        }

        // `#[\SensitiveParameter]` does not cover what a closure captures.
        $secret = new \SensitiveParameterValue($code);

        $prove = static function (IdentifierChange $change, CarbonImmutable $now) use ($changeable, $challengeId, $secret, $codes): ?ChangeRefused {
            $check = $codes->check(PendingChanges::binding($change, $changeable), $challengeId, $secret->getValue(), $now);

            return match ($check) {
                CodeCheck::ACCEPTED  => null,
                CodeCheck::EXPIRED   => new ChangeRefused(IdentifierChangeOutcome::EXPIRED, FailureReason::CODE_EXPIRED),
                CodeCheck::EXHAUSTED => new ChangeRefused(IdentifierChangeOutcome::EXHAUSTED, FailureReason::CODE_EXHAUSTED),
                CodeCheck::INVALID,
                CodeCheck::NOT_FOUND,
                CodeCheck::USED,
                CodeCheck::WRONG => new ChangeRefused(IdentifierChangeOutcome::INVALID, FailureReason::INVALID_CREDENTIALS),
            };
        };

        $outcome = $this->confirm($changeable, $type, $context, $prove, FailureReason::CODE_EXPIRED, $challenge);

        if ($outcome === IdentifierChangeOutcome::CHANGED) {
            $limiter->release($reservation);
        }

        return new LimitedOutcome($outcome);
    }

    /**
     * Confirm the pending change a change link names, as
     * `SignedLink::fromRequest()` captured it, and make it.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\SignedLink  $signed
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\RateLimiting\LimitedOutcome<\SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     *
     * @phpstan-impure
     */
    public function confirmByLink(#[\SensitiveParameter] SignedLink $signed, ClientContext $client): LimitedOutcome
    {
        $context = new EventContext($this->context->name(), $client);
        $link    = $this->links()->read($signed->toRequest());

        if ($link instanceof FailureReason) {
            $outcome = $link === FailureReason::LINK_EXPIRED ? IdentifierChangeOutcome::EXPIRED : IdentifierChangeOutcome::INVALID;

            return new LimitedOutcome($this->refuseConfirmation($outcome, $link, $context));
        }

        $identity = $link->guard === $this->context->name() ? $this->context->provider()->retrieveById($link->identity) : null;

        if (!$identity instanceof Identity) {
            return new LimitedOutcome($this->refuseConfirmation(IdentifierChangeOutcome::INVALID, FailureReason::INVALID_CREDENTIALS, $context));
        }

        $changeable = $this->changeable($identity, $link->type);
        $refusal    = new ChangeRefused(IdentifierChangeOutcome::INVALID, FailureReason::INVALID_CREDENTIALS);
        $prove      = static fn (IdentifierChange $change): ?ChangeRefused => $link->names($change) ? null : $refusal;

        return new LimitedOutcome($this->confirm($changeable, $link->type, $this->eventContext($changeable, $client), $prove, FailureReason::LINK_EXPIRED));
    }

    /**
     * The identity's unexpired change of the identifier of the type pending
     * through this guard, or `null`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @return ?\SineMacula\Laravel\Authentication\IdentifierChanges\PendingIdentifierChange
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @phpstan-impure
     */
    public function pending(Identity $identity, string $type): ?PendingIdentifierChange
    {
        $change = PendingChanges::live(self::changeableIdentity($identity), IdentifierType::assertValid($type), $this->context->name(), CarbonImmutable::now()->startOfSecond());

        return $change === null ? null : new PendingIdentifierChange(
            $change->type,
            $change->identifier,
            CarbonImmutable::instance($change->requested_at),
            CarbonImmutable::instance($change->expires_at),
        );
    }

    /**
     * Cancel the identity's change of the identifier of the type pending
     * through this guard, returning whether there was one.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     *
     * @phpstan-impure
     *
     * @imperative
     */
    public function cancel(Identity $identity, string $type): bool
    {
        $changeable = self::changeableIdentity($identity);

        IdentifierType::assertValid($type);
        (new CodeKeys($this->collaborator(Repository::class)))->validate();

        return (new IdentifierChange)->getConnection()->transaction(function () use ($changeable, $type): bool {

            IdentityLock::acquire($changeable);

            $change = PendingChanges::find($changeable, $type);

            if ($change === null || $change->guard !== $this->context->name() || !PendingChanges::delete($change)) {
                return false;
            }

            $this->collaborator(OneTimeCodes::class)->invalidate([PendingChanges::binding($change, $changeable)]);

            return true;
        });
    }

    /**
     * Prove and make the pending change in one transaction on the identity's
     * connection.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \Closure(\SineMacula\Laravel\Authentication\Models\IdentifierChange, \Carbon\CarbonImmutable): ?\SineMacula\Laravel\Authentication\IdentifierChanges\ChangeRefused  $prove
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $expired
     * @param  ?string  $challengeId
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function confirm(
        HasChangeableIdentifiers&Identity&Model $identity,
        string $type,
        EventContext $context,
        \Closure $prove,
        FailureReason $expired,
        ?string $challengeId = null,
    ): IdentifierChangeOutcome {
        $now     = CarbonImmutable::now()->startOfSecond();
        $attempt = fn (): ?ChangeRefused => self::lockedRefusal($identity) ?? $this->make($identity, $type, $context, $prove, $expired, $now);

        try {
            $refused = $identity->getConnection()->transaction($attempt);
        } catch (ChangeRefused $refusal) {
            $refused = $refusal;
        }

        return $refused === null ? IdentifierChangeOutcome::CHANGED : $this->refuseConfirmation($refused->outcome, $refused->reason, $context, $challengeId);
    }

    /**
     * Check the proof against the pending change and make it: the refusal, or
     * `null` once made.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \Closure(\SineMacula\Laravel\Authentication\Models\IdentifierChange, \Carbon\CarbonImmutable): ?\SineMacula\Laravel\Authentication\IdentifierChanges\ChangeRefused  $prove
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $expired
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\IdentifierChanges\ChangeRefused
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\IdentifierChanges\ChangeRefused
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function make(
        HasChangeableIdentifiers&Identity&Model $identity,
        string $type,
        EventContext $context,
        \Closure $prove,
        FailureReason $expired,
        CarbonImmutable $now,
    ): ?ChangeRefused {
        $change = PendingChanges::find($identity, $type);

        if ($change === null || $change->guard !== $this->context->name()) {
            return new ChangeRefused(IdentifierChangeOutcome::INVALID, FailureReason::INVALID_CREDENTIALS);
        }

        if (PendingChanges::hasExpired($change, $now)) {
            return new ChangeRefused(IdentifierChangeOutcome::EXPIRED, $expired);
        }

        $refused = $prove($change, $now);

        if ($refused === null) {
            (new ChangeConfirmation($this->context, $this->container))->complete($identity, $change, $context, $now);
        }

        return $refused;
    }

    /**
     * Lock the identity's row and refuse a confirmation when it is gone or not
     * active.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $identity
     * @return ?\SineMacula\Laravel\Authentication\IdentifierChanges\ChangeRefused
     */
    private static function lockedRefusal(Model $identity): ?ChangeRefused
    {
        $stored = IdentityLock::acquire($identity);

        return match (true) {
            $stored === null                     => new ChangeRefused(IdentifierChangeOutcome::INVALID, FailureReason::INVALID_CREDENTIALS),
            !ActivationPolicy::isActive($stored) => new ChangeRefused(IdentifierChangeOutcome::INVALID, FailureReason::IDENTITY_INACTIVE),
            default                              => null,
        };
    }

    /**
     * The identity as one whose identifier of the type can be changed through
     * this guard, once every setting a change reads is checked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function changeable(Identity $identity, string $type): HasChangeableIdentifiers&Identity&Model
    {
        $changeable = self::changeableIdentity($identity);
        $config     = $this->collaborator(Repository::class);

        if (!$this->collaborator(IdentifierNormalizers::class)->has(IdentifierType::assertValid($type))) {
            $message = "No identifier normaliser is registered for [{$type}], so its identifiers cannot be changed:"
                . ' add one to `authentication.identifiers.normalizers`.';

            throw new \InvalidArgumentException($message);
        }

        (new IdentifierChangeSettings($config))->validate();
        $this->collaborator(FreshnessPolicy::class)->requirement($this->context->name(), Operations::IDENTIFIER_CHANGE);
        (new CodeKeys($config))->validate();
        $this->collaborator(QueuedDelivery::class)->settings();

        if (!$this->container->bound(IdentifierChangeNotifier::class)) {
            throw new \LogicException(sprintf('No %s is bound to tell an old identifier of its change: bind one before changing identifiers.', IdentifierChangeNotifier::class));
        }

        SharedConnection::assert($changeable, self::FLOW, $this->collaborator(ConfigRepository::class));

        return $changeable;
    }

    /**
     * Refuse a change by code while no `OneTimeCodeSender` is bound to deliver
     * the code to the new identifier.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function assertCodeSender(): void
    {
        if ($this->container->bound(OneTimeCodeSender::class)) {
            return;
        }

        $message = sprintf('No %s is bound to deliver the code that proves a new identifier: bind one before changing identifiers by code.', OneTimeCodeSender::class);

        throw new \LogicException($message);
    }

    /**
     * The identity as an Eloquent model whose identifiers can be changed.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function changeableIdentity(Identity $identity): HasChangeableIdentifiers&Identity&Model
    {
        if ($identity instanceof MachineIdentity) {
            throw new \InvalidArgumentException(sprintf('%s is a machine identity: it has no identifiers to change.', $identity::class));
        }

        if (!$identity instanceof HasChangeableIdentifiers || !$identity instanceof Model) {
            throw new \LogicException(sprintf('%s cannot change identifiers: it must be an Eloquent model that implements %s.', $identity::class, HasChangeableIdentifiers::class));
        }

        return $identity;
    }

    /**
     * Report a refused confirmation with `AuthenticationFailed` and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome  $outcome
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  ?string  $challengeId
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome
     */
    private function refuseConfirmation(IdentifierChangeOutcome $outcome, FailureReason $reason, EventContext $context, ?string $challengeId = null): IdentifierChangeOutcome
    {
        $this->context->dispatch(new AuthenticationFailed($context, AuthenticationFlow::IDENTIFIER_CHANGE, $reason, challengeId: $challengeId));

        return $outcome;
    }

    /**
     * The change links, signed and checked by the application's URL generator.
     *
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\ChangeLinks
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function links(): ChangeLinks
    {
        return new ChangeLinks($this->collaborator(UrlGenerator::class));
    }

    /**
     * The event context of the identity's change through this guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private function eventContext(Identity $identity, ClientContext $client): EventContext
    {
        return new EventContext($this->context->name(), $client, $identity);
    }

    /**
     * Resolve a collaborator from the container at the time it is needed.
     *
     * @template TCollaborator of object
     *
     * @param  class-string<TCollaborator>  $abstract
     * @return TCollaborator
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function collaborator(string $abstract): object
    {
        return $this->container->make($abstract);
    }
}
