<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\BindingForgetting;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Feature tests of forgetting what a revocation ended on every guard already
 * resolved: each guard bound to the identity, or to one of the sessions,
 * forgets it, whatever its name, but a guard bound to the session kept, to
 * another identity or to another session stays bound, and no guard is created;
 * the guards asked are the package guards already resolved, in their configured
 * order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BindingForgetting::class)]
final class BindingForgettingTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string A third guard over the same identities as `api` and `admin`. */
    private const string CONSOLE = 'console';

    /**
     * Create the tables and the identities.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();
        $this->seedIdentity();
        $this->seedIdentity('grace@example.test');
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * Every resolved guard bound to the identity forgets it, creating none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryResolvedGuardBoundToTheIdentityForgetsIt(): void
    {
        $api   = $this->signedIn('api');
        $admin = $this->signedIn('admin');
        $grace = $this->signedIn(self::CONSOLE, 'grace@example.test');

        [$apiGuard, $adminGuard, $graceGuard] = $this->boundGuards($api, $admin, $grace);

        BindingForgetting::identity($api->identity);

        self::assertFalse($apiGuard->check());
        self::assertFalse($adminGuard->check());
        self::assertSame($grace->record->getKey(), $graceGuard->session()?->getSessionIdentifier());
        self::assertNull(Auth::resolvedGuard('members'));
    }

    /**
     * A guard bound to the session kept stays bound while the others forget.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardBoundToTheSessionKeptStaysBound(): void
    {
        $kept  = $this->signedIn('api');
        $ended = $this->signedIn('admin');

        [$keptGuard, $endedGuard] = $this->boundGuards($kept, $ended);

        BindingForgetting::identity($kept->identity, $kept->record);

        self::assertSame($kept->record->getKey(), $keptGuard->session()?->getSessionIdentifier());
        self::assertFalse($endedGuard->check());
    }

    /**
     * Every resolved guard bound to one of the sessions forgets it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryResolvedGuardBoundToOneOfTheSessionsForgetsIt(): void
    {
        $api     = $this->signedIn('api');
        $admin   = $this->signedIn('admin');
        $console = $this->signedIn(self::CONSOLE);

        [$apiGuard, $adminGuard, $consoleGuard] = $this->boundGuards($api, $admin, $console);

        BindingForgetting::sessions([$api->record, $admin->record]);

        self::assertFalse($apiGuard->check());
        self::assertFalse($adminGuard->check());
        self::assertSame($console->record->getKey(), $consoleGuard->session()?->getSessionIdentifier());
    }

    /**
     * The resolved package guards are listed in their configured order.
     *
     * @return void
     */
    public function testResolvedGuardsAreThePackageGuardsAlreadyResolvedInTheirConfiguredOrder(): void
    {
        Auth::forgetGuards();

        $auth = app('auth');

        $auth->extend('mocked', fn (): Guard => \Mockery::mock(Guard::class));
        config()->set('auth.guards.mocked', ['driver' => 'mocked']);

        self::assertSame([], BindingForgetting::resolvedGuards());

        $console = $auth->guard(self::CONSOLE);

        $auth->guard('mocked');

        $api = $auth->guard('api');

        self::assertSame([$api, $console], BindingForgetting::resolvedGuards());
        self::assertNull(Auth::resolvedGuard('admin'));
    }

    /**
     * The constructor is private.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(BindingForgetting::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(BindingForgetting::class, $instance);
    }

    /**
     * Register the session guards and a third guard over the same identities.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.guards.' . self::CONSOLE, ['driver' => 'jwt', 'provider' => 'identities', 'application' => ['methods' => ['password']]]);
    }

    /**
     * Sign the identity with the email in to the guard with its password.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(string $guard, string $email = 'ada@example.test'): SignedInSession
    {
        $session = $this->sessions($guard)->signIn('password', self::credentials($email), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }
}
