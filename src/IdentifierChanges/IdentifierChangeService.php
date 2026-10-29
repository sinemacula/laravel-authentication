<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Routing\UrlGenerator;
use SineMacula\Laravel\Authentication\Codes\CodeKeys;
use SineMacula\Laravel\Authentication\Codes\CodeSettings;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\IdentifierChangeNotifier;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Database\SharedConnection;
use SineMacula\Laravel\Authentication\Delivery\QueuedDelivery;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;
use SineMacula\Laravel\Authentication\Models\IdentifierChange;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;

/**
 * The identifier change service of a JWT guard
 * (`Auth::identifierChanges($guard)`): changes an identity's email address or
 * phone number once the new one is proven, keeping the current one until then.
 *
 * A request (`requestByCode()`, `requestByLink()`) must prove that the identity
 * authenticated recently (see `Reauthentication`), names the new identifier,
 * which must be one the type's normaliser accepts and not the current one, and
 * is limited by the `identifier_change` rate limits, counted on the new
 * identifier, on the identity and on the IP address. It replaces any change the
 * identity had pending for the type, through any guard, so the code and link of
 * an earlier request stop working at once. The proof goes to the new
 * identifier: a one-time code, delivered by a queued job through the
 * application's `OneTimeCodeSender`, or a signed link to a route of the
 * application's, returned for the application to send. Whether another identity
 * holds the new identifier is not checked here, so the answer says nothing
 * about it.
 *
 * A confirmation (`confirmByCode()`, `confirmByLink()`) proves the pending
 * change of this guard and makes it, in one transaction on the identity's
 * connection (see `ChangeConfirmation`): a refused code's attempt is counted
 * and kept, but a change refused once its proof is accepted (another identity
 * holds the identifier, the identifier changed by another path) rolls back
 * whole, proof included. The identity's sessions are not revoked: the change
 * was proven and recently authenticated, and its old identifier is notified,
 * through the application's `IdentifierChangeNotifier`, once it commits. The
 * change stands if that notice fails.
 *
 * A confirmation writes the proof, the pending change and the identity in one
 * transaction, so the identity must be an Eloquent model on the device model's
 * connection (see `SharedConnection`), where the codes and the pending changes
 * are kept; a machine identity has no identifiers to change. Misconfiguration
 * throws before anything is counted or written; every refusal is a result,
 * reported by `AuthenticationFailed` (flow `identifier_change`), and is not
 * concealed, since the caller holds the identity. The service keeps no state
 * between calls: it reads the guard's request and dispatcher, and resolves the
 * settings, limiter, engine and delivery from the container, each time.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentifierChangeService
{
    /** @var string What the flow is called in a connection refusal. */
    public const string FLOW = 'An identifier change';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The guard whose identities' identifiers the service changes. */
        private JwtGuard $guard,

        /** Container the settings, limiter, engine, URL generator and delivery are resolved from. */
        private Container $container,
    ) {}

    /**
     * Start a change of the identity's identifier of the type to the one given,
     * proven by a one-time code sent to it: the code's delivery is queued once
     * the request commits, through the application's `OneTimeCodeSender` with
     * the purpose `change_identifier`. The answer says until when the code
     * confirms the change.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  string  $identifier
     * @param  \SineMacula\Laravel\Authentication\Sessions\Reauthentication  $proof
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     *
     * @phpstan-impure
     */
    public function requestByCode(
        Identity $identity,
        string $type,
        #[\SensitiveParameter] string $identifier,
        Reauthentication $proof,
        ?ClientContext $client = null,
    ): IdentifierChangeRequest {
        $changeable = $this->changeable($identity, $type);

        (new CodeSettings($this->collaborator(Repository::class)))->validate();

        return (new ChangeRequests($this->guard, $this->container))->request($changeable, $type, $identifier, $proof, null, $this->context($changeable, $client));
    }

    /**
     * Start a change of the identity's identifier of the type to the one given,
     * proven by a signed link to the named route of the application's (its own
     * parameters are kept), which the answer carries in `link()` for the
     * application to send to the new identifier, and only there. The route's
     * parameters may not use, nor its path take as placeholders, the names the
     * link sets (`InvalidArgumentException`).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  string  $identifier
     * @param  \SineMacula\Laravel\Authentication\Sessions\Reauthentication  $proof
     * @param  string  $route
     * @param  array<string, mixed>  $parameters
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     *
     * @phpstan-impure
     */
    public function requestByLink(
        Identity $identity,
        string $type,
        #[\SensitiveParameter] string $identifier,
        Reauthentication $proof,
        string $route,
        array $parameters = [],
        ?ClientContext $client = null,
    ): IdentifierChangeRequest {
        $changeable = $this->changeable($identity, $type);

        $this->links()->assertRoute($route, $parameters);

        return (new ChangeRequests($this->guard, $this->container))->request($changeable, $type, $identifier, $proof, [$route, $parameters], $this->context($changeable, $client));
    }

    /**
     * Confirm the identity's pending change of the type, requested through this
     * guard, with the code sent to the new identifier, and make it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  string  $code
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Throwable
     *
     * @phpstan-impure
     */
    public function confirmByCode(Identity $identity, string $type, #[\SensitiveParameter] string $code, ?ClientContext $client = null): IdentifierChangeOutcome
    {
        $changeable = $this->changeable($identity, $type);
        $context    = $this->context($changeable, $client);
        $codes      = $this->collaborator(OneTimeCodes::class);

        if (!$codes->isWellFormed($code)) {
            return $this->refuseConfirmation(IdentifierChangeOutcome::INVALID, FailureReason::INVALID_CREDENTIALS, $context);
        }

        return $this->confirm($changeable, $type, $context, function (IdentifierChange $change, CarbonImmutable $now) use ($changeable, $code, $codes): ?ChangeRefused {
            $check = $codes->check(PendingChanges::binding($change, $changeable), $code, $now);

            return match ($check) {
                CodeCheck::ACCEPTED  => null,
                CodeCheck::EXPIRED   => new ChangeRefused(IdentifierChangeOutcome::EXPIRED, FailureReason::CODE_EXPIRED),
                CodeCheck::EXHAUSTED => new ChangeRefused(IdentifierChangeOutcome::EXHAUSTED, FailureReason::CODE_EXHAUSTED),
                CodeCheck::INVALID   => new ChangeRefused(IdentifierChangeOutcome::INVALID, FailureReason::INVALID_CREDENTIALS),
            };
        }, FailureReason::CODE_EXPIRED);
    }

    /**
     * Confirm the pending change a request to a change link names, and make it.
     * The link must be validly signed, unexpired, for this guard, and name the
     * identity's pending change of its type as it stands: the same request and
     * the same new identifier.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Throwable
     *
     * @phpstan-impure
     */
    public function confirmByLink(Request $request): IdentifierChangeOutcome
    {
        $client  = ClientContext::fromRequest($request);
        $context = new EventContext($this->guard->getName(), $client);
        $link    = $this->links()->read($request);

        if ($link instanceof FailureReason) {
            return $this->refuseConfirmation($link === FailureReason::LINK_EXPIRED ? IdentifierChangeOutcome::EXPIRED : IdentifierChangeOutcome::INVALID, $link, $context);
        }

        $identity = $link->guard === $this->guard->getName() ? $this->guard->getProvider()->retrieveById($link->identity) : null;

        if (!$identity instanceof Identity) {
            return $this->refuseConfirmation(IdentifierChangeOutcome::INVALID, FailureReason::INVALID_CREDENTIALS, $context);
        }

        $changeable = $this->changeable($identity, $link->type);
        $refusal    = new ChangeRefused(IdentifierChangeOutcome::INVALID, FailureReason::INVALID_CREDENTIALS);
        $prove      = static fn (IdentifierChange $change): ?ChangeRefused => $link->names($change) ? null : $refusal;

        return $this->confirm($changeable, $link->type, $this->context($changeable, $client), $prove, FailureReason::LINK_EXPIRED);
    }

    /**
     * The identity's change of the identifier of the type pending through this
     * guard, read on the write connection, or `null` when it has none, or one
     * that expired or was requested through another guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @return ?\SineMacula\Laravel\Authentication\IdentifierChanges\PendingIdentifierChange
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     *
     * @phpstan-impure
     */
    public function pending(Identity $identity, string $type): ?PendingIdentifierChange
    {
        $change = PendingChanges::live(self::changeableIdentity($identity), IdentifierType::assertValid($type), $this->guard->getName(), CarbonImmutable::now()->startOfSecond());

        return $change === null ? null : new PendingIdentifierChange(
            $change->type,
            $change->identifier,
            CarbonImmutable::instance($change->requested_at),
            CarbonImmutable::instance($change->expires_at),
        );
    }

    /**
     * Cancel the identity's change of the identifier of the type pending
     * through this guard, so its code and link stop working; returns whether
     * there was one to cancel (an expired one is cancelled too). A change
     * requested through another guard is left alone.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
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
            $change = PendingChanges::find($changeable, $type);

            if ($change === null || $change->guard !== $this->guard->getName() || !PendingChanges::delete($change)) {
                return false;
            }

            $this->collaborator(OneTimeCodes::class)->invalidate([PendingChanges::binding($change, $changeable)]);

            return true;
        });
    }

    /**
     * In one transaction on the identity's connection: read the identity's
     * pending change of the type (of this guard, unexpired), check the proof
     * against it, and make it. A refused proof commits, so a code's attempt is
     * counted; a change refused after the proof was accepted rolls back whole.
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
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome
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
    private function confirm(
        HasChangeableIdentifiers&Identity&Model $identity,
        string $type,
        EventContext $context,
        \Closure $prove,
        FailureReason $expired,
    ): IdentifierChangeOutcome {
        $now = CarbonImmutable::now()->startOfSecond();

        try {
            $refused = $identity->getConnection()->transaction(function () use ($identity, $context, $prove, $expired, $type, $now): ?ChangeRefused {
                $change = PendingChanges::find($identity, $type);

                if ($change === null || $change->guard !== $this->guard->getName()) {
                    return new ChangeRefused(IdentifierChangeOutcome::INVALID, FailureReason::INVALID_CREDENTIALS);
                }

                if (PendingChanges::hasExpired($change, $now)) {
                    return new ChangeRefused(IdentifierChangeOutcome::EXPIRED, $expired);
                }

                $refused = $prove($change, $now);

                if ($refused === null) {
                    (new ChangeConfirmation($this->guard, $this->container))->complete($identity, $change, $context, $now);
                }

                return $refused;
            });
        } catch (ChangeRefused $refusal) {
            $refused = $refusal;
        }

        return $refused === null ? IdentifierChangeOutcome::CHANGED : $this->refuseConfirmation($refused->outcome, $refused->reason, $context);
    }

    /**
     * The identity as one whose identifier of the type can be changed through
     * this guard, once every setting a change reads is checked:
     * misconfiguration fails here, before anything is counted or written.
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

        if (!$this->collaborator(IdentifierNormalisers::class)->has(IdentifierType::assertValid($type))) {
            $message = "No identifier normaliser is registered for [{$type}], so its identifiers cannot be changed:"
                . ' add one to `authentication.identifiers.normalisers`.';

            throw new \InvalidArgumentException($message);
        }

        (new IdentifierChangeSettings($config))->validate();
        (new CodeKeys($config))->validate();
        $this->collaborator(QueuedDelivery::class)->settings();

        if (!$this->container->bound(IdentifierChangeNotifier::class)) {
            throw new \LogicException(sprintf('No %s is bound to tell an old identifier of its change: bind one before changing identifiers.', IdentifierChangeNotifier::class));
        }

        SharedConnection::assert($changeable, self::FLOW, $this->collaborator(ConfigRepository::class));

        return $changeable;
    }

    /**
     * The identity as an Eloquent model whose identifiers can be changed; a
     * machine identity, which has none, and any other identity are a
     * misconfiguration.
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
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome
     */
    private function refuseConfirmation(IdentifierChangeOutcome $outcome, FailureReason $reason, EventContext $context): IdentifierChangeOutcome
    {
        $this->guard->getDispatcher()->dispatch(new AuthenticationFailed($context, AuthenticationFlow::IDENTIFIER_CHANGE, $reason));

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
     * The context of the identity's change through this guard, from the client
     * given, or the client of the request the guard is serving.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private function context(Identity $identity, ?ClientContext $client): EventContext
    {
        return new EventContext($this->guard->getName(), $client ?? ClientContext::fromRequest($this->guard->getRequest()), $identity);
    }

    /**
     * Resolve a collaborator from the container, so the binding in effect when
     * it is needed is the one used.
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
