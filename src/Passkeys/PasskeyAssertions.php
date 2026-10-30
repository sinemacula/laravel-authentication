<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PasskeyUsed;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose;
use Webauthn\PublicKeyCredential;

/**
 * Verifies a passkey assertion, for a sign-in or as a further factor, in the
 * order that spends nothing on a response that cannot succeed and never changes
 * a passkey for one that fails:
 *
 * 1. the challenge is used up (unknown, expired, already answered, or another
 *    guard's, relying party's, ceremony's or identity's:
 *    `passkey_challenge_invalid`);
 * 2. the response must parse, and name a passkey of the relying party
 *    (`invalid_credentials`);
 * 3. the caller admits the passkey's owner, or answers why not (a sign-in loads
 *    it through the guard's provider and counts the check against the
 *    account; a factor requires it to be the identity verifying);
 * 4. the assertion must verify: origin, relying party id hash, user presence
 *    and verification, signature, challenge and user handle
 *    (`invalid_credentials`);
 * 5. the sign counter rule (`SignCounter`) must accept the count, and the
 *    passkey's row is moved from the count it was verified against, by a
 *    compare-and-set (`passkey_counter_regressed`).
 *
 * A verified use dispatches `PasskeyUsed` once its row is committed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PasskeyAssertions
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Container the library wrapper, the configuration and the transactions manager are resolved from when needed. */
        private Container $container,
    ) {}

    /**
     * Verify the response to the challenge and return the passkey's owner, as
     * the owner callback admitted it, with the passkey; or why it was refused.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  \SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose  $purpose
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)|null  $bound
     * @param  mixed  $challenge
     * @param  mixed  $credential
     * @param  \Closure(\SineMacula\Laravel\Authentication\Models\Passkey): (\SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason)  $owner
     * @param  \Carbon\CarbonImmutable  $now
     * @return array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Models\Passkey}|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    public function verify(
        RelyingParty $rp,
        ChallengePurpose $purpose,
        (Identity&Model)|null $bound,
        mixed $challenge,
        #[\SensitiveParameter] mixed $credential,
        \Closure $owner,
        CarbonImmutable $now,
    ): array|FailureReason {
        $options = is_string($challenge) ? $this->challenges()->consume($challenge, $purpose, $rp, $bound, $now) : null;

        if ($options === null) {
            return FailureReason::PASSKEY_CHALLENGE_INVALID;
        }

        $found = $this->find($rp, $credential);

        if ($found === null) {
            return FailureReason::INVALID_CREDENTIALS;
        }

        [$parsed, $passkey] = $found;

        $identity = $owner($passkey);

        if ($identity instanceof FailureReason) {
            return $identity;
        }

        return $this->assert($rp, $options, $parsed, $passkey, $bound, $now) ?? [$identity, $passkey];
    }

    /**
     * Dispatch `PasskeyUsed` for the passkey once its use is committed on its
     * connection.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return void
     */
    public function used(RelyingParty $rp, ClientContext $client, Identity $identity, Passkey $passkey, Dispatcher $events): void
    {
        $event = new PasskeyUsed(self::context($rp, $client, $identity, $passkey->id));

        $this->afterCommit()->run($passkey, static function () use ($events, $event): void {
            $events->dispatch($event);
        });
    }

    /**
     * The context of a passkey's event.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $passkeyId
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    public static function context(RelyingParty $rp, ClientContext $client, Identity $identity, string $passkeyId): EventContext
    {
        return new EventContext($rp->guard, $client, $identity, method: PasskeySignIn::NAME, credentialId: $passkeyId);
    }

    /**
     * Defers work until the writes on a passkey's connection are committed,
     * with the transactions manager resolved when it runs.
     *
     * @return \SineMacula\Laravel\Authentication\Database\AfterCommit
     */
    public function afterCommit(): AfterCommit
    {
        $container = $this->container;

        return new AfterCommit(static fn (): mixed => $container->bound('db.transactions') ? $container->make('db.transactions') : null);
    }

    /**
     * The challenge store, reading the current configuration.
     *
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeyChallenges
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function challenges(): PasskeyChallenges
    {
        return new PasskeyChallenges($this->container->make(Repository::class));
    }

    /**
     * The response parsed, with the passkey of the relying party it names, or
     * `null` when it is malformed or names none.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  mixed  $credential
     * @return ?array{0: \Webauthn\PublicKeyCredential, 1: \SineMacula\Laravel\Authentication\Models\Passkey}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function find(RelyingParty $rp, #[\SensitiveParameter] mixed $credential): ?array
    {
        $parsed  = is_array($credential) || is_string($credential) ? $this->webauthn()->credential($credential) : null;
        $passkey = $parsed === null ? null : PasskeyCredentials::find($rp, $parsed->rawId);

        return $parsed === null || $passkey === null ? null : [$parsed, $passkey];
    }

    /**
     * Verify the assertion against the passkey (with the handle it was
     * registered under, for a ceremony bound to an identity) and move its
     * count: `null` when both succeed, else why not.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  array<array-key, mixed>  $options
     * @param  \Webauthn\PublicKeyCredential  $parsed
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)|null  $bound
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    private function assert(RelyingParty $rp, array $options, PublicKeyCredential $parsed, Passkey $passkey, (Identity&Model)|null $bound, CarbonImmutable $now): ?FailureReason
    {
        $handle   = $bound === null ? null : PasskeyCredentials::userHandle($passkey);
        $verified = $this->webauthn()->assert($rp, $options, $parsed, PasskeyCredentials::record($passkey), $handle);

        if ($verified === null) {
            return FailureReason::INVALID_CREDENTIALS;
        }

        return SignCounter::accepts($passkey->sign_count, $verified->counter) && PasskeyCredentials::use($passkey, $verified, $now)
            ? null
            : FailureReason::PASSKEY_COUNTER_REGRESSED;
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
