<?php

declare(strict_types = 1);

namespace Tests\Feature\Runtime;

use Illuminate\Auth\RequestGuard;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\ApiKeyGuard;
use SineMacula\Laravel\Authentication\Runtime\JwtGuardContexts;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Feature tests of finding a jwt guard's context by its name, as the queued
 * delivery jobs do: the named guard's own context, and each refusal in the
 * order the guard is checked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuardContexts::class)]
final class JwtGuardContextsTest extends TestCase
{
    use InteractsWithSessions;

    /**
     * A guard `auth.guards` configures with the `jwt` driver answers with its
     * own context, the one its flows run on.
     *
     * @return void
     */
    public function testAJwtGuardAnswersWithItsOwnContext(): void
    {
        $guard = $this->freshGuard('admin');

        self::assertSame($guard->context(), JwtGuardContexts::named(app(), 'admin', 'password resets'));
    }

    /**
     * A guard no one configured is refused as Laravel refuses it, before its
     * driver is checked.
     *
     * @return void
     */
    public function testAnUndefinedGuardKeepsLaravelsRefusal(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [nowhere] is not defined.');

        JwtGuardContexts::named(app(), 'nowhere', 'password resets');
    }

    /**
     * A guard of another driver is not a jwt guard, whether or not it is one of
     * the package's guards with a context of its own.
     *
     * @return void
     */
    public function testAGuardOfAnotherDriverIsNotAJwtGuard(): void
    {
        self::assertInstanceOf(ApiKeyGuard::class, Auth::manager()->guard('keys'));

        foreach (['keys', 'web'] as $name) {
            try {
                JwtGuardContexts::named(app(), $name, 'one-time codes');
                self::fail("Guard [{$name}] was taken for a jwt guard.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame("Auth guard [{$name}] is not a jwt guard, so it sends no one-time codes.", $exception->getMessage());
            }
        }
    }

    /**
     * A `jwt` driver the application replaced with a guard that is not the
     * package's has no context to answer with.
     *
     * @return void
     */
    public function testAJwtDriverReplacedByAnotherGuardHasNoContext(): void
    {
        Auth::extend('jwt', static fn (): RequestGuard => new RequestGuard(static fn (): null => null, request()));
        Auth::forgetGuards();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf('Auth guard [api] has the jwt driver but resolves to %s, not a package guard, so it sends no password resets.', RequestGuard::class));

        JwtGuardContexts::named(app(), 'api', 'password resets');
    }

    /**
     * `JwtGuardContexts` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(JwtGuardContexts::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(JwtGuardContexts::class, $instance);
    }

    /**
     * Configure the jwt guards, a guard of the API key driver and a session
     * guard.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.guards.keys', ['driver' => 'api_key', 'provider' => 'identities']);
        $config->set('auth.guards.web', ['driver' => 'session', 'provider' => 'identities']);
    }
}
