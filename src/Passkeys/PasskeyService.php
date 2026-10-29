<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PasskeyAdded;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\ClientText;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose;
use SineMacula\Laravel\Authentication\Passkeys\Enums\PasskeyRegistrationFailure;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;

/**
 * The passkeys of a JWT guard, scoped to the guard's relying party: the
 * registration ceremony, the options of a usernameless sign-in (which the
 * `passkey` sign-in method completes through `Auth::sessions()->signIn()`), the
 * factor ceremony through which a further-factor package verifies one of an
 * identity's passkeys, and the listing and removal of an identity's passkeys.
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

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The guard whose passkeys the service manages. */
        private JwtGuard $guard,

        /** Container the configuration, the limiter and the library wrapper are resolved from on every call. */
        private Container $container,
    ) {}

    /**
     * Hand out the options of a registration ceremony for the identity: a
     * discoverable credential with user verification and no attestation,
     * excluding the passkeys it already has for the guard's relying party,
     * under the user handle its passkeys there were registered with (a random
     * one for its first). The user name and display name are what the browser
     * shows (the display name defaults to the user name); choose them from the
     * identity's own record, never from the request.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $userName
     * @param  ?string  $displayName
     * @return \SineMacula\Laravel\Authentication\Passkeys\CeremonyOptions
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function registrationOptions(Identity $identity, string $userName, ?string $displayName = null): CeremonyOptions
    {
        $owner = PasskeyOwner::of($identity);

        self::assertNames($userName, $displayName);

        $rp       = $this->relyingParty();
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

        return $challenges->issue(ChallengePurpose::REGISTER, $rp, $owner, $options, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * Register the passkey the browser created in answer to the identity's
     * registration challenge, under the name given (cleaned of NUL bytes and
     * invalid UTF-8, and cut to 255 characters). The challenge is used up
     * whatever the outcome. Refused as `challenge_invalid` when the challenge
     * is not a live registration challenge of this guard for the identity,
     * `response_invalid` when the response is malformed or does not verify
     * (origin, relying party, user presence and verification, challenge,
     * algorithm, attestation statement), and `already_registered` when the
     * credential is registered already. A passkey registered dispatches
     * `PasskeyAdded` once its row is committed.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $challenge
     * @param  array<array-key, mixed>|string  $credential
     * @param  ?string  $name
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Passkeys\Enums\PasskeyRegistrationFailure|\SineMacula\Laravel\Authentication\Passkeys\PasskeySummary
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function register(
        Identity $identity,
        string $challenge,
        #[\SensitiveParameter] array|string $credential,
        ?string $name = null,
        ?ClientContext $client = null,
    ): PasskeyRegistrationFailure|PasskeySummary {
        $owner = PasskeyOwner::of($identity);
        $rp    = $this->relyingParty();
        $now   = CarbonImmutable::now()->startOfSecond();

        $options = $this->assertions()->challenges()->consume($challenge, ChallengePurpose::REGISTER, $rp, $owner, $now);

        if ($options === null) {
            return PasskeyRegistrationFailure::CHALLENGE_INVALID;
        }

        $webauthn = $this->webauthn();
        $parsed   = $webauthn->credential($credential);
        $record   = $parsed === null ? null : $webauthn->register($rp, $options, $parsed);

        if ($record === null) {
            return PasskeyRegistrationFailure::RESPONSE_INVALID;
        }

        $passkey = PasskeyCredentials::register($rp, $owner, $record, ClientText::clean($name, self::NAME_MAX_LENGTH), $now);

        if ($passkey === null) {
            return PasskeyRegistrationFailure::ALREADY_REGISTERED;
        }

        $this->dispatchOnceCommitted($passkey, new PasskeyAdded(PasskeyAssertions::context($rp, $this->client($client), $owner, $passkey->id)));

        return PasskeySummary::of($passkey);
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
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function signInOptions(?ClientContext $client = null): CeremonyOptions
    {
        $rp      = $this->relyingParty();
        $subject = new AttemptSubject($rp->guard, AttemptFlow::PASSKEY_OPTIONS, null, null, $this->client($client)->ip);

        self::refuseWhenThrottled($this->container->make(AttemptLimiter::class)->acquire($subject));

        return $this->assertionOptions(ChallengePurpose::SIGN_IN, $rp, null, []);
    }

    /**
     * Hand out the options of a factor ceremony for the identity: user
     * verification required, allowing only its passkeys for the guard's relying
     * party. The seam a further-factor package verifies a passkey through, with
     * `verifyFactor()`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Passkeys\CeremonyOptions
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function factorOptions(Identity $identity): CeremonyOptions
    {
        $owner = PasskeyOwner::of($identity);
        $rp    = $this->relyingParty();

        return $this->assertionOptions(ChallengePurpose::FACTOR, $rp, $owner, array_map(PasskeyCredentials::descriptor(...), PasskeyCredentials::of($rp, $owner)));
    }

    /**
     * Verify the identity's passkey as a further factor, in answer to its
     * factor challenge: `null` when it verified, else why not
     * (`passkey_challenge_invalid`; `invalid_credentials` for a malformed or
     * unverified response or a passkey that is not the identity's;
     * `passkey_counter_regressed`). The same checks and sign counter rule as a
     * sign-in apply. A verified passkey records its use and dispatches
     * `PasskeyUsed`; nothing else is dispatched and nothing counted, since the
     * factor's outcome is the further-factor package's to report and limit.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $challenge
     * @param  array<array-key, mixed>|string  $credential
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function verifyFactor(Identity $identity, string $challenge, #[\SensitiveParameter] array|string $credential, ?ClientContext $client = null): ?FailureReason
    {
        $owner      = PasskeyOwner::of($identity);
        $rp         = $this->relyingParty();
        $assertions = $this->assertions();

        $verified = $assertions->verify(
            $rp,
            ChallengePurpose::FACTOR,
            $owner,
            $challenge,
            $credential,
            static fn (Passkey $passkey): FailureReason|Identity => PasskeyOwner::owns($owner, $passkey) ? $owner : FailureReason::INVALID_CREDENTIALS,
            CarbonImmutable::now()->startOfSecond(),
        );

        if ($verified instanceof FailureReason) {
            return $verified;
        }

        $assertions->used($rp, $this->client($client), $owner, $verified[1], $this->guard->getDispatcher());

        return null;
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
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public function passkeys(Identity $identity): array
    {
        return array_map(PasskeySummary::of(...), PasskeyCredentials::of($this->relyingParty(), PasskeyOwner::of($identity)));
    }

    /**
     * Remove the identity's passkey with the id, for the guard's relying party.
     * Returns whether this call removed it, and only then dispatches
     * `PasskeyRemoved`, once the removal is committed. Ending the identity's
     * sessions when it loses a factor is the optional
     * `RevokeDevicesOnPasskeyRemoval` listener's.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $passkeyId
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public function remove(Identity $identity, string $passkeyId, ?ClientContext $client = null): bool
    {
        $owner = PasskeyOwner::of($identity);
        $rp    = $this->relyingParty();

        if (!PasskeyCredentials::remove($rp, $owner, $passkeyId)) {
            return false;
        }

        $this->dispatchOnceCommitted(new Passkey, new PasskeyRemoved(PasskeyAssertions::context($rp, $this->client($client), $owner, $passkeyId)));

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
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    private function assertionOptions(ChallengePurpose $purpose, RelyingParty $rp, (Identity&Model)|null $owner, array $allow): CeremonyOptions
    {
        $challenges = $this->assertions()->challenges();
        $options    = $this->webauthn()->requestOptions($rp, random_bytes(self::RANDOM_BYTES), $allow, $challenges->ttlSeconds() * 1000);

        return $challenges->issue($purpose, $rp, $owner, $options, CarbonImmutable::now()->startOfSecond());
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
     * wait.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation  $reservation
     * @return void
     *
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     */
    private static function refuseWhenThrottled(AttemptReservation $reservation): void
    {
        if (!$reservation->granted()) {
            throw new ThrottleRequestsException('Too Many Attempts.', null, ['Retry-After' => $reservation->retryAfter]);
        }
    }

    /**
     * Dispatch the event on the guard's dispatcher once the writes on the
     * passkey model's connection are committed.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @param  object  $event
     * @return void
     */
    private function dispatchOnceCommitted(Passkey $passkey, object $event): void
    {
        $events = $this->guard->getDispatcher();

        $this->assertions()->afterCommit()->run($passkey, static function () use ($events, $event): void {
            $events->dispatch($event);
        });
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
        return RelyingParty::forGuard($this->guard->getName(), $this->container->make(Repository::class));
    }

    /**
     * The client the call is for: the one given, else the guard's request's.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    private function client(?ClientContext $client): ClientContext
    {
        return $client ?? ClientContext::fromRequest($this->guard->getRequest());
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
