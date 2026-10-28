<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * An account stored without a password hash, as one created through another
 * sign-in method might be, is an ordinary failed sign-in: the attempt is
 * rejected and reported, not answered with a server error.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ModelProvider::class)]
final class PasswordlessAccountIntegrationTest extends TestCase
{
    /** @var string Email of the seeded account. */
    private const string EMAIL = 'passwordless@example.test';

    /**
     * Create the identity table with a nullable password and seed an account
     * without one.
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
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $account = new StubPrincipal;
        $account->forceFill(['email' => self::EMAIL, 'password' => null])->save();
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
     * The provider rejects any password for the account.
     *
     * @return void
     */
    public function testProviderRejectsAPasswordForAnAccountWithoutOne(): void
    {
        $provider = new ModelProvider(app(Hasher::class), StubPrincipal::class);
        $account  = $provider->retrieveByCredentials(['email' => self::EMAIL]);

        self::assertNotNull($account);
        self::assertFalse($provider->validateCredentials($account, ['password' => 'anything at all']));
    }

    /**
     * Signing in over HTTP answers with a rejection and dispatches `Attempting`
     * then `Failed` naming the account.
     *
     * @return void
     */
    public function testSignInRejectsAnAccountWithoutAPassword(): void
    {
        $dispatched = [];

        Event::listen([Attempting::class, Failed::class], static function (object $event) use (&$dispatched): void {
            $dispatched[] = $event;
        });

        Route::post('/sign-in', static fn (): array => [
            'signed_in' => Auth::guard('api')->attempt(['email' => self::EMAIL, 'password' => 'anything at all']),
            'identity'  => Auth::guard('api')->id(),
        ]);

        $this->postJson('/sign-in')->assertOk()->assertExactJson(['signed_in' => false, 'identity' => null]);

        self::assertSame([Attempting::class, Failed::class], array_map(static fn (object $event): string => $event::class, $dispatched));
        self::assertInstanceOf(Failed::class, $dispatched[1]);
        self::assertInstanceOf(StubPrincipal::class, $dispatched[1]->user);
        self::assertSame(self::EMAIL, $dispatched[1]->user->email);
    }

    /**
     * Configure the JWT guard over the identity table.
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

        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities']);
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => StubPrincipal::class]);

        // Failed attempts wait out the timebox; keep it short.
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }
}
