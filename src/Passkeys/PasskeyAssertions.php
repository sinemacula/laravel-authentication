<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PasskeyUsed;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose;
use SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengeRefusal;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use Webauthn\PublicKeyCredential;

/**
 * Verifies a passkey assertion, for a sign-in or as a further factor.
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

        /** Container the library wrapper, configuration and transactions manager are resolved from. */
        private Container $container,
    ) {}

    /**
     * Verify the response to the challenge and return the passkey's owner, the
     * passkey and what the assertion showed, or why it was refused.
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
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @return array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Models\Passkey, 2: \SineMacula\Laravel\Authentication\Proofs\ObservedProperties}|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
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
        ?ProofBinding $binding = null,
    ): array|FailureReason {
        $consumed = is_string($challenge) ? $this->challenges()->consume($challenge, $purpose, $rp, $bound, $now, $binding) : ChallengeRefusal::NOT_FOUND;

        if ($consumed instanceof ChallengeRefusal) {
            return $consumed->reason();
        }

        $options = $consumed->options;
        $found   = $this->find($rp, $credential);

        if ($found === null || !self::isAllowed($options, $found[1])) {
            return FailureReason::INVALID_CREDENTIALS;
        }

        [$parsed, $passkey] = $found;

        $identity = $owner($passkey);

        if ($identity instanceof FailureReason) {
            return $identity;
        }

        $asserted = $this->assert($rp, $options, $parsed, $passkey, $bound, $now);

        return $asserted instanceof FailureReason ? $asserted : [$identity, $passkey, $asserted];
    }

    /**
     * Dispatch `PasskeyUsed` for the passkey once its use is committed.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @param  \Closure(object): void  $dispatch
     * @return void
     */
    public function used(RelyingParty $rp, ClientContext $client, Identity $identity, Passkey $passkey, \Closure $dispatch): void
    {
        $event = new PasskeyUsed(self::context($rp, $client, $identity, $passkey->id));

        $this->afterCommit()->run($passkey, static fn () => $dispatch($event));
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
     * Defers work until the writes on a passkey's connection are committed.
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
     * The parsed response with the passkey it names, or `null` when it is
     * malformed or names none.
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
     * Whether the challenge allowed the passkey; one that names none allows
     * any.
     *
     * @param  array<array-key, mixed>  $options
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @return bool
     */
    private static function isAllowed(array $options, Passkey $passkey): bool
    {
        $allowed = is_array($options['allowCredentials'] ?? null) ? $options['allowCredentials'] : [];

        return $allowed === [] || in_array($passkey->credential_id, array_column($allowed, 'id'), true);
    }

    /**
     * Verify the assertion against the passkey and move its count.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RelyingParty  $rp
     * @param  array<array-key, mixed>  $options
     * @param  \Webauthn\PublicKeyCredential  $parsed
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)|null  $bound
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Proofs\ObservedProperties
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    private function assert(
        RelyingParty $rp,
        array $options,
        PublicKeyCredential $parsed,
        Passkey $passkey,
        (Identity&Model)|null $bound,
        CarbonImmutable $now,
    ): FailureReason|ObservedProperties {
        $handle   = $bound === null ? null : PasskeyCredentials::userHandle($passkey);
        $verified = $this->webauthn()->assert($rp, $options, $parsed, PasskeyCredentials::record($passkey), $handle);

        if ($verified === null) {
            return FailureReason::INVALID_CREDENTIALS;
        }

        [$record, $observed] = $verified;

        return SignCounter::accepts($passkey->sign_count, $record->counter) && PasskeyCredentials::use($passkey, $record, $now)
            ? $observed
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
