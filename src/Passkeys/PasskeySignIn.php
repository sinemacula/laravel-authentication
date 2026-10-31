<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;

/**
 * The passkey sign-in method: usernameless, with a discoverable credential and
 * user verification, answering a challenge `Auth::passkeys()->signInOptions()`
 * handed out.
 *
 * The input is `['challenge' => <the options' challenge id>, 'credential' =>
 * <the browser's PublicKeyCredential, as JSON or decoded>]`. The method names
 * no identifier, so the attempt limits count the sign-in per IP address, and
 * the passkey's owner, once found, per account. In order: the guard's sign-in
 * challenge is used up (`passkey_challenge_invalid`, which says nothing about
 * any account, so the result carries it and the client starts again); the
 * response must parse and name a passkey of the guard's relying party; its
 * owner must load through the guard's provider as the very model the passkey
 * records; a slot of the owner's account limit is taken before the assertion is
 * checked; the assertion must verify, its user handle included; and the sign
 * counter must advance (`passkey_counter_regressed`, a possible clone, which
 * the result conceals as `invalid_credentials`). Every other refusal is
 * `invalid_credentials`. A verified passkey records its new count and last use
 * and dispatches `PasskeyUsed`, whether or not the session service then admits
 * the sign-in; the session service decides the rest (a machine identity,
 * activity, the principal, the audience, a further factor, the device).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasskeySignIn implements SignInMethod
{
    /** @var string Name of the method, under which it is registered and recorded. */
    public const string NAME = 'passkey';

    /** @var string Input key holding the challenge id. */
    public const string CHALLENGE_KEY = 'challenge';

    /** @var string Input key holding the browser's response. */
    public const string CREDENTIAL_KEY = 'credential';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Container the configuration, the library wrapper, the dispatcher and the transactions manager are resolved from on every call. */
        private Container $container,
    ) {}

    /**
     * The method uses no identifier: the sign-in is usernameless.
     *
     * @param  string  $guard
     * @return null
     */
    #[\Override]
    public function identifierType(string $guard): null
    {
        return null;
    }

    /**
     * No identifier: the sign-in is usernameless.
     *
     * @param  string  $guard
     * @param  array<array-key, mixed>  $input
     * @return null
     */
    #[\Override]
    public function identifier(string $guard, #[\SensitiveParameter] array $input): null
    {
        return null;
    }

    /**
     * Verify the passkey assertion the input carries and return its owner.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    #[\Override]
    public function authenticate(SignInRequest $request): FailureReason|Identity
    {
        $rp         = RelyingParty::forGuard($request->guard, $this->container->make(Repository::class));
        $assertions = new PasskeyAssertions($this->container);

        $verified = $assertions->verify(
            $rp,
            ChallengePurpose::SIGN_IN,
            null,
            $request->input[self::CHALLENGE_KEY]  ?? null,
            $request->input[self::CREDENTIAL_KEY] ?? null,
            static function (Passkey $passkey) use ($request): FailureReason|Identity {
                $owner = PasskeyOwner::load($passkey, $request->provider);

                return $owner !== null && $request->reserveAccountAttempt($owner) ? $owner : FailureReason::INVALID_CREDENTIALS;
            },
            CarbonImmutable::now()->startOfSecond(),
        );

        if ($verified instanceof FailureReason) {
            return $verified;
        }

        [$identity, $passkey] = $verified;

        $assertions->used($rp, $request->client, $identity, $passkey, function (object $event): void {
            $this->container->make(Dispatcher::class)->dispatch($event);
        });

        return $identity;
    }
}
