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
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * The passkeys of a JWT guard, scoped to the guard's relying party: the
 * registration ceremony, the options of a usernameless sign-in (which the
 * `passkey` sign-in method completes through `Auth::sessions()->signIn()`), the
 * factor ceremony through which a further-factor package verifies one of the
 * passkeys it associated as an identity's factors, and the listing and removal
 * of an identity's passkeys. A registration and a removal ask the factor gate
 * (`Contracts\PasskeyFactorGate`) inside the transaction that makes them.
 *
 * Every ceremony hands out options with a single-use challenge stored in the
 * database, which the response must answer within its lifetime, through the
 * same guard, for the same relying party, and, for a registration or a factor,
 * for the same identity. Passkeys belong to Eloquent identities that are not
 * machine identities. The guard's relying party is read and validated on every
 * call, so a malformed one fails closed with an `InvalidArgumentException`.
 * Failures are results, not exceptions, except the `429` of `signInOptions()`.
 * The service keeps no state between calls.
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

        /** Container the configuration, the limiter, the translator and the library wrapper are resolved from on every call. */
        private Container $container,
    ) {}

    /**
     * Hand out the options of a registration ceremony for the identity: a
     * discoverable credential with user verification and no attestation,
     * excluding the passkeys it already has for the guard's relying party,
     * under the user handle its passkeys there were registered with (a random
     * one for its first). The user name and display name are what the browser
     * shows (the display name defaults to the user name); choose them from the
     * identity's own record, never from the request. A factor package that asks
     * for the registration on a session (a pending session enrolling its
     * factor, say) gives its binding, which must name this identity and this
     * guard (an `InvalidArgumentException` otherwise); its session and purpose
     * are kept on the challenge and handed to the factor gate when the
     * registration completes.
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
     * registration challenge, under the name given (cleaned of NUL bytes and
     * invalid UTF-8, and cut to 255 characters). The challenge is used up
     * whatever the outcome (unless a transaction of the caller's around the
     * call rolls back). Refused as `challenge_invalid` when the challenge is
     * not a live registration challenge of this guard for the identity,
     * `response_invalid` when the response is malformed or does not verify
     * (origin, relying party, user presence and verification, challenge,
     * algorithm, attestation statement), and `already_registered` when the
     * credential is registered already, before the factor gate is asked.
     *
     * Then, in one transaction on the passkey model's connection (the storage
     * connection; a savepoint in the caller's), the factor gate is asked first
     * (`PasskeyFactorGate::registering()`), with the passkey as the
     * registration showed it and the challenge's binding, and the passkey's row
     * is written only after it: a gate that throws refuses the registration,
     * rolling back everything it did, and its exception reaches the caller. A
     * credential registered concurrently, found only by the insert, rolls the
     * whole change back, the gate's work (its association, a pending session it
     * satisfied) with it, and is answered as `already_registered`. A passkey
     * registered is `registered`, with its summary and the factor association
     * the gate answered, if any, and dispatches `PasskeyAdded` once its row is
     * committed.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $challenge
     * @param  array<array-key, mixed>|string  $credential
     * @param  ?string  $name
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
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
        ?string $name = null,
        ?ClientContext $client = null,
    ): PasskeyRegistration {
        $owner = PasskeyOwner::of($identity);
        $rp    = $this->relyingParty();
        $now   = CarbonImmutable::now()->startOfSecond();

        $consumed = $this->assertions()->challenges()->consume($challenge, ChallengePurpose::REGISTER, $rp, $owner, $now);

        if ($consumed === null) {
            return PasskeyRegistration::challengeInvalid();
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
            $association = $passkey->getConnection()->transaction(fn (): ?PasskeyFactorAssociation => $this->store($owner, $rp, $passkey, [$seen, $binding, $cleaned]));
        } catch (ConcurrentPasskeyChange) {
            return PasskeyRegistration::alreadyRegistered();
        }

        $this->dispatchOnceCommitted($passkey, new PasskeyAdded(PasskeyAssertions::context($rp, $this->client($client), $owner, $passkey->id)));

        return PasskeyRegistration::registered(PasskeySummary::of($passkey), $association);
    }

    /**
     * Hand out the options of a usernameless sign-in: user verification
     * required and no credentials named, so the browser offers every passkey it
     * holds for the relying party. The sign-in completes through
     * `Auth::sessions()->signIn('passkey', ...)`. Anyone may ask, and each
     * request writes a challenge, so each is counted against the client's IP
     * address under the guard's `passkey_options` limit; once that is used up a
     * `ThrottleRequestsException` (429 with `Retry-After`) is thrown.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Passkeys\CeremonyOptions
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function signInOptions(?ClientContext $client = null): CeremonyOptions
    {
        $rp      = $this->relyingParty();
        $subject = new AttemptSubject($rp->guard, AttemptFlow::PASSKEY_OPTIONS, null, null, $this->client($client)->ip);

        $this->refuseWhenThrottled($this->container->make(AttemptLimiter::class)->acquire($subject));

        return $this->assertionOptions(ChallengePurpose::SIGN_IN, $rp, null, []);
    }

    /**
     * Hand out the options of a factor ceremony for the identity, bound to the
     * factor package's binding (which must name this identity and this guard,
     * and a session), allowing only those of the identity's passkeys for the
     * guard's relying party whose credential id is one given: the ones the
     * factor package associated as its factors, each as canonical unpadded
     * base64url (an `InvalidArgumentException` otherwise). User verification is
     * required unless the factor package asks only to prefer it. `null`, with
     * no challenge written, when none of the identity's passkeys is among them:
     * an empty list would let the browser offer any credential it holds. The
     * seam a further-factor package verifies a passkey through, with
     * `verifyFactor()`.
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
     * its factor challenge for the binding: verified, with what the assertion
     * showed, or failed with why. The challenge must be a live factor
     * challenge of this guard and relying party for the identity and the
     * binding's session and purpose (`passkey_challenge_invalid`); the passkey
     * asserted must be one the challenge allowed, compared exactly, and the
     * identity's (`invalid_credentials`, as for a malformed or unverified
     * response); then the origin, the relying party id hash, user presence,
     * user verification where the challenge required it, the signature and the
     * challenge are verified, and the sign counter rule applies, with its
     * tolerance of a counter that stays at zero (`passkey_counter_regressed`).
     * The assertion reports what its authenticator data showed, never what the
     * ceremony asked for. A verified passkey records its use and dispatches
     * `PasskeyUsed`; nothing else is dispatched and nothing counted, since the
     * factor's outcome is the further-factor package's to report and limit.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @param  string  $challenge
     * @param  array<array-key, mixed>|string  $credential
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
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
        ?ClientContext $client = null,
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

        $assertions->used($rp, $this->client($client), $owner, $passkey, $this->context->dispatch(...));

        return PasskeyFactorResult::verified(new PasskeyFactorAssertion($passkey->id, $passkey->credential_id, $observed, $now, PasskeySummary::of($passkey)));
    }

    /**
     * The identity's passkeys for the guard's relying party, oldest first, read
     * from the write connection.
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
     * Remove the identity's passkey with the id, for the guard's relying party,
     * found on the write connection. In one transaction on the passkey model's
     * connection (the storage connection; a savepoint in the caller's), the
     * factor gate is asked first (`PasskeyFactorGate::removing()`), then the
     * row is deleted: a gate that throws refuses the removal, keeping the
     * passkey, and its exception reaches the caller; a passkey removed
     * concurrently rolls the gate's work back. Returns whether this call
     * removed it, and only then dispatches `PasskeyRemoved`, once the removal
     * is committed. Ending the identity's sessions when it loses a first-factor
     * credential is the optional `RevokeSessionsOnPasskeyRemoval` listener's;
     * a factor package calls its own mandatory helper when the passkey was one
     * of its factors.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $passkeyId
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function remove(Identity $identity, string $passkeyId, ?ClientContext $client = null): bool
    {
        $owner   = PasskeyOwner::of($identity);
        $rp      = $this->relyingParty();
        $passkey = PasskeyCredentials::owned($rp, $owner, $passkeyId);

        if ($passkey === null) {
            return false;
        }

        $gate = $this->gate();

        try {
            $passkey->getConnection()->transaction(static function () use ($gate, $owner, $rp, $passkey): void {

                $gate->removing($owner, $rp->guard, $passkey->id, $passkey->credential_id);

                PasskeyCredentials::delete($passkey) || throw new ConcurrentPasskeyChange;
            });
        } catch (ConcurrentPasskeyChange) {
            return false;
        }

        $this->dispatchOnceCommitted($passkey, new PasskeyRemoved(PasskeyAssertions::context($rp, $this->client($client), $owner, $passkey->id)));

        return true;
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
     * Ask the factor gate about the passkey, then store it, inside the
     * registration's transaction; a credential the insert finds registered
     * already throws, so the transaction rolls back whatever the gate did.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @param  array{0: \SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey, 1: ?\SineMacula\Laravel\Authentication\Proofs\ProofBinding, 2: ?string}  $registration
     * @return ?\SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Authentication\Passkeys\ConcurrentPasskeyChange
     */
    private function store(Identity&Model $owner, RelyingParty $rp, Passkey $passkey, array $registration): ?PasskeyFactorAssociation
    {
        [$seen, $binding, $name] = $registration;

        $association = $this->gate()->registering($owner, $rp->guard, $seen, $binding, $name);

        PasskeyCredentials::insert($passkey) || throw new ConcurrentPasskeyChange;

        return $association;
    }

    /**
     * Refuse a binding that names another identity, another application, or no
     * session (a key of 1 to 255 characters).
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
     * Refuse names a browser cannot show: a blank user name, or a display name
     * that is given but blank.
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
     * Answer a reservation the limiter refused with a 429 that says how long to
     * wait, its message translated.
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
     * Dispatch the event, once the writes on the passkey model's connection are
     * committed, to the dispatcher the guard has then.
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
     * The client the call is for: the one given, else the guard's request's.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    private function client(?ClientContext $client): ClientContext
    {
        return $client ?? $this->context->client();
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
