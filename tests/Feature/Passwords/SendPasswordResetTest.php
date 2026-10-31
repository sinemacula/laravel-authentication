<?php

declare(strict_types = 1);

namespace Tests\Feature\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Auth\RequestGuard;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\ApiKeyGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Passwords\SendPasswordReset;
use Tests\Concerns\InteractsWithPasswordResets;
use Tests\TestCase;

/**
 * Feature tests of the password reset delivery job: it delivers only reset
 * purposes, for a jwt guard, and only the live issuance, through the provider
 * of the guard the jwt driver builds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SendPasswordReset::class)]
final class SendPasswordResetTest extends TestCase
{
    use InteractsWithPasswordResets;

    /**
     * The delivery job delivers only reset purposes, for a jwt guard, and only
     * while its token or code is live.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDeliveryJobRefusesWhatItCannotDeliver(): void
    {
        self::seedResettable();

        $codes  = app(OneTimeCodes::class);
        $issued = $codes->issue(CodeBinding::signIn('web', 'email', self::EMAIL), CarbonImmutable::now());

        self::assertInstanceOf(IssuedCode::class, $issued);

        try {
            (new SendPasswordReset(CodeBinding::signIn('web', 'email', self::EMAIL), $issued))->handle(app());
            self::fail('A sign-in code was delivered as a reset.');
        } catch (\LogicException $exception) {
            self::assertSame(SendPasswordReset::class . ' delivers only password reset links and codes, not [sign_in] codes.', $exception->getMessage());
        }

        config()->set('auth.guards.session', ['driver' => 'session', 'provider' => 'password_identities']);

        try {
            (new SendPasswordReset(CodeBinding::passwordReset('session', 'email', self::EMAIL), $issued))->handle(app());
            self::fail('A reset was delivered for a session guard.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Auth guard [session] is not a jwt guard, so it sends no password resets.', $exception->getMessage());
        }

        $binding = CodeBinding::passwordResetLink('web', 'email', self::EMAIL);
        $first   = $codes->issueToken($binding, CarbonImmutable::now(), 3600);
        $second  = $codes->issueToken($binding, CarbonImmutable::now()->addMinute(), 3600);

        self::assertInstanceOf(IssuedCode::class, $first);
        self::assertInstanceOf(IssuedCode::class, $second);

        (new SendPasswordReset($binding, $first))->handle(app());

        self::assertSame(0, $this->links->count());

        (new SendPasswordReset($binding, $second))->handle(app());

        self::assertSame($second->code, $this->links->lastTokenFor(self::EMAIL));
    }

    /**
     * A job naming a guard of another driver is refused even when the guard
     * resolves to the package's jwt guard: the jwt guards are the ones
     * `auth.guards` configures with the `jwt` driver, the only ones whose reset
     * proofs an identifier change outdates.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAJobNamingAnotherDriversJwtGuardThrows(): void
    {
        self::seedResettable();

        config()->set('auth.guards.copied', ['driver' => 'copied_jwt', 'provider' => 'password_identities']);

        Auth::extend('copied_jwt', static fn (Application $app): JwtGuard => AuthenticationServiceProvider::createJwtGuard($app, 'web', config()->array('auth.guards.web')));

        self::assertInstanceOf(JwtGuard::class, Auth::manager()->guard('copied'));

        try {
            $this->job('copied')->handle(app());
            self::fail('A reset was delivered through a guard without the jwt driver.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Auth guard [copied] is not a jwt guard, so it sends no password resets.', $exception->getMessage());
        }

        self::assertSame(0, $this->links->count());
    }

    /**
     * A job for a jwt guard whose driver the application replaced with a guard
     * that is not the package's has no provider to find the recipient through,
     * and sends nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAJobForAJwtDriverReplacedByAnotherGuardThrows(): void
    {
        self::seedResettable();

        $job      = $this->job('web');
        $expected = sprintf('Auth guard [web] has the jwt driver but resolves to %s, not a package guard, so it sends no password resets.', RequestGuard::class);

        Auth::extend('jwt', static fn (): RequestGuard => new RequestGuard(static fn (): null => null, request()));
        Auth::forgetGuards();

        try {
            $job->handle(app());
            self::fail('A reset was delivered through a guard that is not the package\'s.');
        } catch (\LogicException $exception) {
            self::assertSame($expected, $exception->getMessage());
        }

        self::assertSame(0, $this->links->count());
    }

    /**
     * A job for a jwt guard whose driver the application replaced with another
     * of the package's guards finds the recipient through that guard's
     * provider.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAJobForAJwtDriverReplacedByAnotherPackageGuardSendsThroughItsProvider(): void
    {
        $identity = self::seedResettable();
        $job      = $this->job('web');

        Auth::extend('jwt', static fn (Application $app, string $name, array $config): ApiKeyGuard => AuthenticationServiceProvider::createApiKeyGuard($app, $name, $config));
        Auth::forgetGuards();

        self::assertInstanceOf(ApiKeyGuard::class, Auth::manager()->guard('web'));

        $job->handle(app());

        $link = $this->links->sent()[0] ?? null;

        self::assertNotNull($link);
        self::assertSame(1, $this->links->count());
        self::assertSame(['web', $job->issued->code], [$link->guard, $link->token()]);
        self::assertTrue($identity->is($link->identity));
    }

    /**
     * The delivery job of a live reset link for the seeded email, bound to the
     * guard.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Passwords\SendPasswordReset
     *
     * @throws \Throwable
     */
    private function job(string $guard): SendPasswordReset
    {
        $binding = CodeBinding::passwordResetLink($guard, 'email', self::EMAIL);
        $issued  = app(OneTimeCodes::class)->issueToken($binding, CarbonImmutable::now(), 3600);

        self::assertInstanceOf(IssuedCode::class, $issued);

        return new SendPasswordReset($binding, $issued);
    }
}
