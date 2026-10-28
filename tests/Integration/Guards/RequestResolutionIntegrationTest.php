<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Auth\Events\Failed;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Request resolution through the `Auth` facade: a rejected bearer token is
 * attempted once per request, and `Auth::logout()` keeps the request signed out
 * although its bearer token is still valid.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
final class RequestResolutionIntegrationTest extends TestCase
{
    /**
     * Create the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_principals');

        parent::tearDown();
    }

    /**
     * Repeated `Auth` calls on a request with a rejected token report one
     * failure.
     *
     * @return void
     */
    public function testRejectedBearerTokenIsAttemptedOncePerRequest(): void
    {
        $failures = 0;

        Event::listen(Failed::class, static function () use (&$failures): void {
            $failures++;
        });

        Route::get('/repeat', static fn (): array => [
            'check' => Auth::check(),
            'id'    => Auth::id(),
            'user'  => Auth::user(),
            'guest' => Auth::guest(),
        ]);

        $this->withHeaders(['Authorization' => 'Bearer not-a-jwt'])->getJson('/repeat')
            ->assertOk()
            ->assertExactJson(['check' => false, 'id' => null, 'user' => null, 'guest' => true]);

        self::assertSame(1, $failures);
    }

    /**
     * After `Auth::logout()` the request stays signed out for the rest of the
     * request although its bearer token is still valid.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testLogoutKeepsTheRequestSignedOut(): void
    {
        $user = new StubPrincipal;
        $user->forceFill(['email' => 'resolution@example.test', 'password' => 'irrelevant'])->save();

        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $token = $manager->jwt('api')->issueAccessToken($user, $user, null);

        Route::get('/logout', static function (): array {

            $before = Auth::check();

            Auth::logout();

            return ['before' => $before, 'after' => Auth::check(), 'id' => Auth::id()];
        });

        $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/logout')
            ->assertOk()
            ->assertExactJson(['before' => true, 'after' => false, 'id' => null]);
    }

    /**
     * A request that binds another identity with `Auth::setUser()` and then
     * calls `Auth::logout()` stays signed out: its still-valid bearer token
     * does not sign the token's identity back in.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testLogoutAfterSetUserKeepsTheRequestSignedOut(): void
    {
        $bearer = new StubPrincipal;
        $bearer->forceFill(['email' => 'bearer@example.test', 'password' => 'irrelevant'])->save();

        $acting = new StubPrincipal;
        $acting->forceFill(['email' => 'acting@example.test', 'password' => 'irrelevant'])->save();

        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $token = $manager->jwt('api')->issueAccessToken($bearer, $bearer, null);

        Route::get('/act-then-logout', static function () use ($acting): array {

            Auth::setUser($acting);

            $actingId = Auth::id();

            Auth::logout();

            return ['acting' => $actingId, 'after' => Auth::check(), 'id' => Auth::id()];
        });

        $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/act-then-logout')
            ->assertOk()
            ->assertExactJson(['acting' => $acting->getKey(), 'after' => false, 'id' => null]);
    }

    /**
     * Configure the JWT guard against the stub identity provider.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('auth.defaults.guard', 'api');

        $config->set('auth.guards.api', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);
    }
}
