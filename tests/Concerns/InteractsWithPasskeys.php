<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passkeys\CeremonyOptions;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySummary;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Fixtures\Passkeys\VirtualAuthenticator;

/**
 * Shared set-up for the passkey tests, on top of the session tests' guards: a
 * relying party for every guard, every guard allowing the `passkey` method, and
 * a virtual authenticator that registers and signs with real keys.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithPasskeys
{
    /** @var string The relying party id of every guard. */
    protected const string RP_ID = 'example.test';

    /** @var string The origin the ceremonies run on. */
    protected const string ORIGIN = 'https://app.example.test';

    /** @var string The user name a registration shows. */
    protected const string USER_NAME = 'ada@example.test';

    /** @var ?\Tests\Fixtures\Passkeys\VirtualAuthenticator The authenticator the tests use. */
    private ?VirtualAuthenticator $virtualAuthenticator = null;

    /**
     * Give every session test guard the relying party and allow the `passkey`
     * method on each.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    protected static function configurePasskeys(ConfigRepository $config): void
    {
        $config->set('authentication.passkeys.relying_party', ['id' => self::RP_ID, 'name' => 'Example', 'origins' => [self::ORIGIN]]);

        foreach (['api', 'admin', 'members'] as $guard) {
            $config->set("auth.guards.{$guard}.audience.methods", ['password', 'sso', 'trusted', 'passkey']);
        }
    }

    /**
     * The authenticator, created on first use.
     *
     * @return \Tests\Fixtures\Passkeys\VirtualAuthenticator
     */
    protected function authenticator(): VirtualAuthenticator
    {
        return $this->virtualAuthenticator ??= new VirtualAuthenticator(self::ORIGIN);
    }

    /**
     * Register a passkey for the identity through the guard, with the
     * authenticator given or the test's own.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $guard
     * @param  ?\Tests\Fixtures\Passkeys\VirtualAuthenticator  $authenticator
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeySummary
     *
     * @throws \Throwable
     */
    protected function registerPasskey(Identity $identity, string $guard = 'api', ?VirtualAuthenticator $authenticator = null): PasskeySummary
    {
        $passkeys = Auth::passkeys($guard);
        $options  = $passkeys->registrationOptions($identity, self::USER_NAME);
        $summary  = $passkeys->register($identity, $options->challengeId, ($authenticator ?? $this->authenticator())->create($options->options), 'Laptop');

        self::assertInstanceOf(PasskeySummary::class, $summary);

        return $summary;
    }

    /**
     * Hand out sign-in options through the guard.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Passkeys\CeremonyOptions
     *
     * @throws \Throwable
     */
    protected function signInOptions(string $guard = 'api'): CeremonyOptions
    {
        return Auth::passkeys($guard)->signInOptions();
    }

    /**
     * Sign in through the guard's session service with the authenticator's
     * answer to fresh sign-in options, after letting the test change it.
     *
     * @param  string  $guard
     * @param  ?\Closure(array<string, mixed>): array<string, mixed>  $tamper
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    protected function signInWithPasskey(string $guard = 'api', ?\Closure $tamper = null): SignInResult
    {
        $options    = $this->signInOptions($guard);
        $credential = $this->authenticator()->get($options->options);

        return $this->sessions($guard)->signIn('passkey', ['challenge' => $options->challengeId, 'credential' => $tamper === null ? $credential : $tamper($credential)]);
    }
}
