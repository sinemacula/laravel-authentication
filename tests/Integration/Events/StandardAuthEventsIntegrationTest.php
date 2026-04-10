<?php

declare(strict_types = 1);

namespace Tests\Integration\Events;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\Validated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Guards\BasicGuard;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Integration test for the six standard Laravel auth events.
 *
 * Boots a Testbench application, registers a `cli` guard driven by the
 * package's `basic` driver against a `StubPrincipal` identity table seeded
 * with a single user, and exercises the successful `attempt`, failed
 * `attempt`, and `logout` paths to assert the dispatched standard events
 * (`Attempting`, `Validated`, `Login`, `Authenticated`, `Failed`, `Logout`)
 * match Laravel's first-party contract with the expected constructor payload
 * shapes.
 *
 * The `cli` guard uses the package's `basic` driver so credentials can be
 * passed directly via `attempt()` without needing an HTTP Authorization
 * header, keeping the assertions focused on the event-emission contract.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(BasicGuard::class)]
final class StandardAuthEventsIntegrationTest extends TestCase
{
    /** @var string The guard name under test. */
    private const string GUARD_NAME = 'cli';

    /** @var string The email of the seeded test user. */
    private const string USER_EMAIL = 'user@example.test';

    /** @var string The plain-text password of the seeded test user. */
    private const string USER_PASSWORD = 'correct horse battery staple';

    /**
     * Create the identity table, hash a password, and insert one user that the
     * successful-attempt tests authenticate against.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {

            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $hasher = app(Hasher::class);

        $user           = new StubPrincipal;
        $user->email    = self::USER_EMAIL;
        $user->password = $hasher->make(self::USER_PASSWORD);
        $user->save();
    }

    /**
     * Drop the seeded identity table so each test starts with a clean schema.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_principals');

        parent::tearDown();
    }

    /**
     * A successful `attempt()` dispatches all four success-path standard
     * events: `Attempting`, `Validated`, `Login`, and `Authenticated`.
     *
     * @return void
     */
    public function testSuccessfulAttemptDispatchesAttemptingThenValidatedThenLoginThenAuthenticated(): void
    {
        Event::fake([
            Attempting::class,
            Validated::class,
            Login::class,
            Authenticated::class,
            Failed::class,
            Logout::class,
        ]);

        $result = Auth::guard(self::GUARD_NAME)->attempt([
            'email'    => self::USER_EMAIL,
            'password' => self::USER_PASSWORD,
        ]);

        self::assertTrue($result);

        Event::assertDispatched(Attempting::class);
        Event::assertDispatched(Validated::class);
        Event::assertDispatched(Login::class);
        Event::assertDispatched(Authenticated::class);
        Event::assertNotDispatched(Failed::class);
    }

    /**
     * A failed `attempt()` dispatches `Attempting` and `Failed`, but NOT
     * `Validated`, `Login`, or `Authenticated`.
     *
     * @return void
     */
    public function testFailedAttemptDispatchesAttemptingThenFailed(): void
    {
        Event::fake([
            Attempting::class,
            Validated::class,
            Login::class,
            Authenticated::class,
            Failed::class,
            Logout::class,
        ]);

        $result = Auth::guard(self::GUARD_NAME)->attempt([
            'email'    => self::USER_EMAIL,
            'password' => 'wrong-password',
        ]);

        self::assertFalse($result);

        Event::assertDispatched(Attempting::class);
        Event::assertDispatched(Failed::class);
        Event::assertNotDispatched(Validated::class);
        Event::assertNotDispatched(Login::class);
        Event::assertNotDispatched(Authenticated::class);
    }

    /**
     * Calling `logout()` on a guard with a bound identity dispatches the
     * standard Laravel `Logout` event.
     *
     * @return void
     */
    public function testLogoutDispatchesLogoutEvent(): void
    {
        // Fake the Logout event BEFORE resolving the guard so the guard
        // captures the faked dispatcher in its constructor.
        Event::fake([Logout::class]);

        $guard = Auth::guard(self::GUARD_NAME);

        self::assertTrue($guard->attempt([
            'email'    => self::USER_EMAIL,
            'password' => self::USER_PASSWORD,
        ]));

        self::assertInstanceOf(ContextualGuard::class, $guard);

        $guard->logout();

        Event::assertDispatched(Logout::class, 1);
    }

    /**
     * The dispatched `Authenticated` instance carries the guard name and the
     * resolved identity on its public properties, matching Laravel's
     * first-party guard payload shape.
     *
     * @return void
     */
    public function testStandardAuthenticatedEventConstructorReceivesGuardNameAndUser(): void
    {
        Event::fake([Authenticated::class]);

        self::assertTrue(Auth::guard(self::GUARD_NAME)->attempt([
            'email'    => self::USER_EMAIL,
            'password' => self::USER_PASSWORD,
        ]));

        Event::assertDispatched(Authenticated::class, function (Authenticated $event): bool {

            self::assertSame(self::GUARD_NAME, $event->guard);
            self::assertInstanceOf(Identity::class, $event->user);
            self::assertInstanceOf(StubPrincipal::class, $event->user);
            self::assertSame(self::USER_EMAIL, $event->user->getAttribute('email'));

            return true;
        });
    }

    /**
     * The dispatched `Login` instance carries the guard name, the resolved
     * identity, and a `false` remember flag on its public properties, matching
     * Laravel's first-party guard payload shape.
     *
     * @return void
     */
    public function testStandardLoginEventConstructorReceivesGuardNameUserAndRememberFlag(): void
    {
        Event::fake([Login::class]);

        self::assertTrue(Auth::guard(self::GUARD_NAME)->attempt([
            'email'    => self::USER_EMAIL,
            'password' => self::USER_PASSWORD,
        ]));

        Event::assertDispatched(Login::class, function (Login $event): bool {

            self::assertSame(self::GUARD_NAME, $event->guard);
            self::assertInstanceOf(Identity::class, $event->user);
            self::assertInstanceOf(StubPrincipal::class, $event->user);
            self::assertSame(self::USER_EMAIL, $event->user->getAttribute('email'));
            self::assertFalse($event->remember);

            return true;
        });
    }

    /**
     * The dispatched `Failed` instance carries the guard name, the resolved
     * user (or null), and the supplied credentials on its public properties,
     * matching Laravel's first-party guard payload shape.
     *
     * @return void
     */
    public function testStandardFailedEventConstructorReceivesGuardNameUserAndCredentials(): void
    {
        Event::fake([Failed::class]);

        $credentials = [
            'email'    => self::USER_EMAIL,
            'password' => 'wrong-password',
        ];

        self::assertFalse(Auth::guard(self::GUARD_NAME)->attempt($credentials));

        Event::assertDispatched(Failed::class, function (Failed $event) use ($credentials): bool {

            self::assertSame(self::GUARD_NAME, $event->guard);
            self::assertInstanceOf(Identity::class, $event->user);
            self::assertSame($credentials, $event->credentials);

            return true;
        });
    }

    /**
     * Register the `cli` guard against the `basic` driver and the `cli_users`
     * provider pointing at the `StubPrincipal` identity model before the
     * Testbench application boots so the package service provider picks up the
     * driver registration at the appropriate time.
     *
     * @param  mixed  $app
     * @return void
     */
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof \Illuminate\Foundation\Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.providers.cli_users', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);

        $config->set('auth.guards.' . self::GUARD_NAME, [
            'driver'   => 'basic',
            'provider' => 'cli_users',
        ]);
    }
}
