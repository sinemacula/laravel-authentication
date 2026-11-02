<?php

declare(strict_types = 1);

namespace Tests\Integration\Config;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\RevocationWriter;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Fixtures\Database\ShippedMigrations;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\TestCase;
use Tests\Unit\Stubs\StubLookupIdentityProvider;
use Tests\Unit\Stubs\StubPrincipal;
use Tests\Unit\Stubs\StubTwoDPrincipalResolver;

/**
 * Integration test for the Session model override via package config.
 *
 * Verifies that overriding `config('authentication.session.model')` with a
 * custom `Session` subclass and `session.table` with a custom table name causes
 * the model, the shipped migration body, and the JWT guard's session-hydration
 * path to route through the override.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationServiceProvider::class)]
#[CoversClass(Session::class)]
#[CoversClass(RefreshTokenExchange::class)]
final class SessionModelOverrideTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessionRecords;

    /** @var class-string<\SineMacula\Laravel\Authentication\Models\Session> */
    private string $customModel;

    /**
     * Configure the custom session model class and table name, then replay the
     * shipped migration body inline against the in-memory connection so the
     * custom table exists for the test, and run the shipped rate limits
     * migration, whose table the refresh exchange counts failures in, and the
     * proofs and provenance migrations, whose proofs the refreshed tokens'
     * `auth_time` and `amr` are derived from.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $anonymous = new class extends Session {};

        /** @var class-string<\SineMacula\Laravel\Authentication\Models\Session> $class */
        $class = $anonymous::class;

        $this->customModel = $class;

        config()->set('authentication.session.model', $this->customModel);
        config()->set('authentication.session.table', 'custom_sessions');

        self::createSessionRecordTable('custom_sessions');

        ShippedMigrations::up('2026_04_06_000002_create_rate_limits_table.php');
        self::migrateProofTables();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the custom tables on tear-down so each test starts clean.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('custom_sessions');
        Schema::dropIfExists('stub_principals');
        Schema::dropIfExists('rate_limits');
        Schema::dropIfExists('authentication_proofs');
        Schema::dropIfExists('authentication_provenance');

        parent::tearDown();
    }

    /**
     * Instantiating the custom subclass yields a model whose table matches the
     * configured `session.table` value.
     *
     * @return void
     */
    public function testCustomTableNameAppliesToSessionModel(): void
    {
        $model = new $this->customModel;

        self::assertSame('custom_sessions', $model->getTable());
        self::assertInstanceOf(EloquentSession::class, $model);
    }

    /**
     * The shipped migration body creates the custom table (not the default
     * `authentication_sessions` table) when `session.table` is overridden.
     *
     * @return void
     */
    public function testCustomTableNameAppliesToShippedMigration(): void
    {
        self::assertTrue(Schema::hasTable('custom_sessions'));
        self::assertFalse(Schema::hasTable('authentication_sessions'));
    }

    /**
     * Refreshing through the session service with a refresh token whose `sid`
     * claim points at a row in the custom table returns a refreshed access
     * token sourced from the overridden model class, binding an instance of
     * that class as the active session.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testGuardResolvesSessionThroughCustomModelClass(): void
    {
        $principal = new StubPrincipal;
        $principal->forceFill(['is_active' => true])->save();

        $plainRotationId = 'plain-rotation-id';

        /** @var \SineMacula\Laravel\Authentication\Models\Session $session */
        $session = new $this->customModel;
        $session->forceFill([
            ...self::liveSession('custom-jwt', $principal),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $principal->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $jwtService = PackageAuth::jwt('custom-jwt');

        $refreshToken = $jwtService->issueRefreshToken($session, $plainRotationId)->reveal();

        $guard = $this->makeJwtGuard();

        $result = GuardSessions::of($guard)->refresh($refreshToken)->session?->tokens;

        self::assertInstanceOf(TokenPair::class, $result);
        self::assertNotSame('', $result->accessToken->reveal());
        self::assertNotSame('', $result->refreshToken?->reveal());
        self::assertInstanceOf($this->customModel, $guard->session());
    }

    /**
     * Skip the parent's default `authentication_sessions` migration so this
     * test can verify that the custom-table override is the only
     * `authentication_sessions`-shaped table on the connection.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void {}

    /**
     * Register the manual `custom-jwt` guard config used by the guard-scoped
     * `Auth::jwt('custom-jwt')` issuance surface in this test.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('auth.guards.custom-jwt', [
            'driver'      => 'jwt',
            'provider'    => 'principals',
            'application' => ['methods' => ['password']],
        ]);

        config()->set('auth.providers.principals', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);
    }

    /**
     * Build a `JwtGuard` wired against a stub identity provider that echoes a
     * persisted `StubPrincipal` for any identifier lookup, and a resolver that
     * treats the identity as its own principal (2D mode).
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function makeJwtGuard(): JwtGuard
    {
        $provider = new StubLookupIdentityProvider;
        $resolver = new StubTwoDPrincipalResolver;
        $tokens   = PackageAuth::jwt('custom-jwt');
        $events   = app(Dispatcher::class);

        return new JwtGuard(
            'custom-jwt',
            $provider,
            $resolver,
            $events,
            app('request'),
            app(Timebox::class),
            $tokens,
            static fn (GuardContext $context): SessionRevocations => new SessionRevocations(
                $context,
                new RevocationWriter(app(ConnectionResolverInterface::class), static fn (): mixed => app('db.transactions')),
                app(),
            ),
            static fn (): RefreshTokenTransport => RefreshTokenTransport::forGuard('custom-jwt', config()),
        );
    }
}
