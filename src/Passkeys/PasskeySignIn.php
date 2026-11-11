<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;

/**
 * The usernameless passkey sign-in method, answering a challenge
 * `Auth::passkeys()->signInOptions()` handed out.
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

    /** @var string The `amr` value of a passkey: proof of possession of a key (RFC 8176). */
    private const string AMR = 'pop';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Container the configuration, library wrapper, dispatcher and transactions manager are resolved from. */
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
     * The challenge id the input answers, when it is a UUID.
     *
     * @param  array<array-key, mixed>  $input
     * @return ?string
     */
    #[\Override]
    public function challenge(#[\SensitiveParameter] array $input): ?string
    {
        $challenge = $input[self::CHALLENGE_KEY] ?? null;

        return is_string($challenge) && Str::isUuid($challenge) ? $challenge : null;
    }

    /**
     * Verify the passkey assertion the input carries and return its owner's
     * first factor.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Proofs\FirstFactor
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     */
    #[\Override]
    public function authenticate(SignInRequest $request): FailureReason|FirstFactor
    {
        $rp         = RelyingParty::forGuard($request->guard, $this->container->make(Repository::class));
        $assertions = new PasskeyAssertions($this->container);

        $verified = $assertions->verify(
            $rp,
            ChallengePurpose::SIGN_IN,
            null,
            $request->input()[self::CHALLENGE_KEY]  ?? null,
            $request->input()[self::CREDENTIAL_KEY] ?? null,
            static function (Passkey $passkey) use ($request): FailureReason|Identity {
                $owner = PasskeyOwner::load($passkey, $request->provider);

                return $owner !== null && $request->reserveAccountAttempt($owner) ? $owner : FailureReason::INVALID_CREDENTIALS;
            },
            CarbonImmutable::now()->startOfSecond(),
        );

        if ($verified instanceof FailureReason) {
            return $verified;
        }

        [$identity, $passkey, $observed] = $verified;

        $assertions->used($rp, $request->client, $identity, $passkey, function (object $event): void {
            $this->container->make(Dispatcher::class)->dispatch($event);
        });

        return new FirstFactor($identity, new Channel(ChannelKind::PASSKEY, $passkey->id), $observed, [self::AMR]);
    }
}
