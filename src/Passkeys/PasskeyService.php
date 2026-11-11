<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PasskeyAdded;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\ClientText;
use SineMacula\Laravel\Authentication\Http\ConsumerMessages;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose;
use SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengeRefusal;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * The passkeys of a JWT guard, scoped to the guard's relying party.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasskeyService
{
    /** @var int Bytes of randomness in a challenge and in a new user handle. */
    private const int RANDOM_BYTES = 32;

    /** @var int Longest name a passkey is stored with, in characters. */
    private const int NAME_MAX_LENGTH = 255;

    /** @var int Longest session key a ceremony's binding may name, in characters. */
    private const int SESSION_MAX_LENGTH = 255;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard whose passkeys the service manages. */
        private GuardContext $context,

        /** Container the configuration, limiter, translator and library wrapper are resolved from. */
        private Container $container,
    ) {}

    /**
     * Hand out the options of a registration ceremony for the identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $userName
     * @param  ?string  $displayName
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Passkeys\CeremonyOptions
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function registrationOptions(Identity $identity, string $userName, ?string $displayName = null, ?ProofBinding $binding = null): CeremonyOptions
    {
        $owner = PasskeyOwner::of($identity);

        self::assertNames($userName, $displayName);

        $rp = $this->relyingParty();

        if ($binding !== null) {
            self::assertBinding($binding, $owner, $rp);
        }

        $passkeys = PasskeyCredentials::of($rp, $owner);
        $handle   = $passkeys === [] ? random_bytes(self::RANDOM_BYTES) : PasskeyCredentials::userHandle($passkeys[0]);

        $challenges = $this->assertions()->challenges();
        $options    = $this->webauthn()->creationOptions(
            $rp,
            random_bytes(self::RANDOM_BYTES),
            $handle,
            $userName,
            $displayName ?? $userName,
            array_map(PasskeyCredentials::descriptor(...), $passkeys),
            $challenges->ttlSeconds() * 1000,
        );

        return $challenges->issue(ChallengePurpose::REGISTER, $rp, $owner, $options, CarbonImmutable::now()->startOfSecond(), $binding);
    }

    /**
     * Register the passkey the browser created in answer to the identity's
     * registration challenge.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $challenge
     * @param  array<array-key, mixed>|string  $credential
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?string  $name
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Secrets\Secret|string|null  $pending
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeyRegistration
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Throwable
     */
    public function register(
        Identity $identity,
        string $challenge,
        #[\SensitiveParameter] array|string $credential,
        ClientContext $client,
        ?string $name = null,
        #[\SensitiveParameter] FailureReason|Secret|string|null $pending = null,
    ): PasskeyRegistration {
        $owner     = PasskeyOwner::of($identity);
        $onPending = new PendingRegistration($this->context, $this->container);
        $presented = $onPending->credential($pending, $owner);
        $rp        = $this->relyingParty();
        $now       = CarbonImmutable::now()->startOfSecond();
        $consumed  = $this->assertions()->challenges()->consume($challenge, ChallengePurpose::REGISTER, $rp, $owner, $now);

        if ($consumed instanceof ChallengeRefusal) {
            return $consumed->registration();
        }

        $held = $presented === null ? null : $onPending->presented($presented, $owner, $rp, $client);

        if ($held instanceof PasskeyRegistration) {
            return $held;
        }

        $webauthn = $this->webauthn();
        $parsed   = $webauthn->credential($credential);
        $verified = $parsed === null ? null : $webauthn->register($rp, $consumed->options, $parsed);

        if ($verified === null) {
            return PasskeyRegistration::responseInvalid();
        }

        [$record, $observed] = $verified;

        if (PasskeyCredentials::isRegistered($record->publicKeyCredentialId)) {
            return PasskeyRegistration::alreadyRegistered();
        }

        $cleaned = ClientText::clean($name, self::NAME_MAX_LENGTH);
        $passkey = PasskeyCredentials::draft($rp, $owner, $record, $cleaned, $now);
        $seen    = new RegisteredPasskey($passkey->id, $passkey->credential_id, $rp->id, $observed, $now);
        $binding = PasskeyChallenges::bindingOf($consumed, $owner);

        try {
            $stored      = [$seen, $binding, $cleaned, $client, $held];
            $association = $passkey->getConnection()->transaction(fn (): ?PasskeyFactorAssociation => $this->store($owner, $rp, $passkey, $stored, $onPending));
        } catch (ConcurrentPasskeyChange) {
            return PasskeyRegistration::alreadyRegistered();
        } catch (UnheldPendingSession) {
            return $onPending->refused($owner, $rp, $client, FailureReason::PENDING_INVALID);
        }

        $this->dispatchOnceCommitted($passkey, new PasskeyAdded(PasskeyAssertions::context($rp, $client, $owner, $passkey->id)));

        return PasskeyRegistration::registered(PasskeySummary::of($passkey), $association);
    }

    /**
     * Hand out the options of a usernameless sign-in, counted against the
     * client's IP address.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Passkeys\CeremonyOptions
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function signInOptions(ClientContext $client): CeremonyOptions
    {
        $rp      = $this->relyingParty();
        $subject = new AttemptSubject($rp->guard, AttemptFlow::PASSKEY_OPTIONS, null, null, $client->ip);

        $this->refuseWhenThrottled($this->container->make(AttemptLimiter::class)->acquire($subject));

        return $this->assertionOptions(ChallengePurpose::SIGN_IN, $rp, null, []);
    }

    /**
     * Hand out the options of a factor ceremony for the identity's passkeys
     * with the given credential ids, or `null` when it has none.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @param  array<array-key, mixed>  $credentialIds
     * @param  bool  $requireUserVerification
     * @return ?\SineMacula\Laravel\Authentication\Passkeys\CeremonyOptions
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function factorOptions(Identity $identity, ProofBinding $binding, #[\SensitiveParameter] array $credentialIds, bool $requireUserVerification = true): ?CeremonyOptions
    {
        $owner = PasskeyOwner::of($identity);
        $rp    = $this->relyingParty();

        self::assertBinding($binding, $owner, $rp);
        self::assertCredentialIds($credentialIds);

        $allowed = array_values(array_filter(PasskeyCredentials::of($rp, $owner), static fn (Passkey $passkey): bool => in_array($passkey->credential_id, $credentialIds, true)));

        if ($allowed === []) {
            return null;
        }

        $challenges = $this->assertions()->challenges();
        $options    = $this->webauthn()->requestOptions(
            $rp,
            random_bytes(self::RANDOM_BYTES),
            array_map(PasskeyCredentials::descriptor(...), $allowed),
            $challenges->ttlSeconds() * 1000,
            $requireUserVerification,
        );

        return $challenges->issue(ChallengePurpose::FACTOR, $rp, $owner, $options, CarbonImmutable::now()->startOfSecond(), $binding);
    }

    /**
     * Verify one of the identity's passkeys as a further factor, in answer to
     * its factor challenge for the binding.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @param  string  $challenge
     * @param  array<array-key, mixed>|string  $credential
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function verifyFactor(
        Identity $identity,
        ProofBinding $binding,
        string $challenge,
        #[\SensitiveParameter] array|string $credential,
        ClientContext $client,
    ): PasskeyFactorResult {
        $owner      = PasskeyOwner::of($identity);
        $rp         = $this->relyingParty();
        $assertions = $this->assertions();
        $now        = CarbonImmutable::now()->startOfSecond();

        self::assertBinding($binding, $owner, $rp);

        $verified = $assertions->verify(
            $rp,
            ChallengePurpose::FACTOR,
            $owner,
            $challenge,
            $credential,
            static fn (Passkey $passkey): FailureReason|Identity => PasskeyOwner::owns($owner, $passkey) ? $owner : FailureReason::INVALID_CREDENTIALS,
            $now,
            $binding,
        );

        if ($verified instanceof FailureReason) {
            return PasskeyFactorResult::failed($verified);
        }

        [, $passkey, $observed] = $verified;

        $assertions->used($rp, $client, $owner, $passkey, $this->context->dispatch(...));

        return PasskeyFactorResult::verified(new PasskeyFactorAssertion($passkey->id, $passkey->credential_id, $observed, $now, PasskeySummary::of($passkey)));
    }

    /**
     * The identity's passkeys for the guard's relying party, oldest first.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return list<\SineMacula\Laravel\Authentication\Passkeys\PasskeySummary>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function passkeys(Identity $identity): array
    {
        return array_map(PasskeySummary::of(...), PasskeyCredentials::of($this->relyingParty(), PasskeyOwner::of($identity)));
    }

    /**
     * The credential ids of the identity's passkeys for the guard's relying
     * party, oldest first; hand them only to a caller authorised for it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function credentialIds(Identity $identity): array
    {
        return array_map(static fn (Passkey $passkey): string => $passkey->credential_id, PasskeyCredentials::of($this->relyingParty(), PasskeyOwner::of($identity)));
    }

    /**
     * Remove the identity's passkey with the id, asking the factor gate in the
     * same transaction.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $passkeyId
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeyRemoval
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function remove(Identity $identity, string $passkeyId, ClientContext $client): PasskeyRemoval
    {
        $owner   = PasskeyOwner::of($identity);
        $rp      = $this->relyingParty();
        $passkey = PasskeyCredentials::owned($rp, $owner, $passkeyId);

        if ($passkey === null) {
            return PasskeyRemoval::notRemoved();
        }

        $gate = $this->gate();

        try {
            $completion = $passkey->getConnection()->transaction(static function () use ($gate, $owner, $rp, $passkey, $client): ?object {

                $completion = $gate->removing($owner, $rp->guard, $passkey->id, $passkey->credential_id, $client);

                PasskeyCredentials::delete($passkey) || throw new ConcurrentPasskeyChange;

                return $completion;
            });
        } catch (ConcurrentPasskeyChange) {
            return PasskeyRemoval::notRemoved();
        }

        $this->dispatchOnceCommitted($passkey, new PasskeyRemoved(PasskeyAssertions::context($rp, $client, $owner, $passkey->id)));

        return PasskeyRemoval::removed($completion);
    }

    /**
     * Hand out the options of an assertion ceremony allowing the credentials,
     * with a challenge for the purpose bound to the owner (none for a sign-in).
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose  $purpose
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)|null  $owner
     * @param  list<array{0: string, 1: list<string>}>  $allow
     * @return \SineMacula\Laravel\Authentication\Passkeys\CeremonyOptions
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    private function assertionOptions(ChallengePurpose $purpose, RelyingParty $rp, (Identity&Model)|null $owner, array $allow): CeremonyOptions
    {
        $challenges = $this->assertions()->challenges();
        $options    = $this->webauthn()->requestOptions($rp, random_bytes(self::RANDOM_BYTES), $allow, $challenges->ttlSeconds() * 1000);

        return $challenges->issue($purpose, $rp, $owner, $options, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * Hold the pending session, if any, ask the factor gate about the passkey
     * and store it, inside the registration's transaction.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @param  array{0: \SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey, 1: ?\SineMacula\Laravel\Authentication\Proofs\ProofBinding, 2: ?string, 3: \SineMacula\Laravel\Authentication\Http\ClientContext, 4: ?\SineMacula\Laravel\Authentication\Secrets\Secret}  $registration
     * @param  \SineMacula\Laravel\Authentication\Passkeys\PendingRegistration  $onPending
     * @return ?\SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Authentication\Passkeys\ConcurrentPasskeyChange
     * @throws \SineMacula\Laravel\Authentication\Passkeys\UnheldPendingSession
     */
    private function store(Identity&Model $owner, RelyingParty $rp, Passkey $passkey, array $registration, PendingRegistration $onPending): ?PasskeyFactorAssociation
    {
        [$seen, $binding, $name, $client, $pending] = $registration;

        if ($pending !== null) {
            $onPending->hold($owner, $binding, $pending);
        }

        $association = $this->gate()->registering($owner, $rp->guard, $seen, $binding, $name, $client, $pending);

        PasskeyCredentials::insert($passkey) || throw new ConcurrentPasskeyChange;

        return $association;
    }

    /**
     * Refuse a binding that names another identity, another application or no
     * session.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertBinding(ProofBinding $binding, Identity&Model $owner, RelyingParty $rp): void
    {
        $bound   = $binding->identity instanceof Model && $binding->identity->is($owner);
        $session = IdentifierCoercion::stringify($binding->sessionId) ?? '';

        if (!$bound || $binding->application !== $rp->guard || $session === '' || mb_strlen($session) > self::SESSION_MAX_LENGTH) {
            throw new \InvalidArgumentException(sprintf('A passkey ceremony\'s binding must name the identity it is for, the guard [%s] and a session.', $rp->guard));
        }
    }

    /**
     * Refuse credential ids that are not each a canonical unpadded base64url
     * string.
     *
     * @param  array<array-key, mixed>  $credentialIds
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertCredentialIds(#[\SensitiveParameter] array $credentialIds): void
    {
        foreach ($credentialIds as $credentialId) {
            if (!is_string($credentialId) || !PasskeyCredentials::isCanonical($credentialId)) {
                throw new \InvalidArgumentException('A passkey factor ceremony allows credential ids given as canonical unpadded base64url.');
            }
        }
    }

    /**
     * Refuse a blank user name or a given but blank display name.
     *
     * @param  string  $userName
     * @param  ?string  $displayName
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertNames(string $userName, ?string $displayName): void
    {
        if (trim($userName) === '' || ($displayName !== null && trim($displayName) === '')) {
            throw new \InvalidArgumentException('A passkey registration needs a non-empty user name, and a display name that is null or non-empty.');
        }
    }

    /**
     * Answer a reservation the limiter refused with a 429.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation  $reservation
     * @return void
     *
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     */
    private function refuseWhenThrottled(AttemptReservation $reservation): void
    {
        if (!$reservation->granted()) {
            $message = ConsumerMessages::translate($this->container->make(Translator::class), ConsumerMessages::TOO_MANY_ATTEMPTS);

            throw new ThrottleRequestsException($message, null, ['Retry-After' => $reservation->retryAfter]);
        }
    }

    /**
     * Dispatch the event once the writes on the passkey's connection are
     * committed.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @param  object  $event
     * @return void
     */
    private function dispatchOnceCommitted(Passkey $passkey, object $event): void
    {
        $this->assertions()->afterCommit()->run($passkey, fn () => $this->context->dispatch($event));
    }

    /**
     * The guard's relying party, read and validated now.
     *
     * @return \SineMacula\Laravel\Authentication\Passkeys\RelyingParty
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function relyingParty(): RelyingParty
    {
        return RelyingParty::forGuard($this->context->name(), $this->container->make(Repository::class));
    }

    /**
     * The factor gate bound now.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function gate(): PasskeyFactorGate
    {
        return $this->container->make(PasskeyFactorGate::class);
    }

    /**
     * The assertion verifier.
     *
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeyAssertions
     */
    private function assertions(): PasskeyAssertions
    {
        return new PasskeyAssertions($this->container);
    }

    /**
     * The library wrapper.
     *
     * @return \SineMacula\Laravel\Authentication\Passkeys\WebAuthn
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function webauthn(): WebAuthn
    {
        return $this->container->make(WebAuthn::class);
    }
}
