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
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
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
 * Tests that an overridden session model and table reach the model, the
 * migration and the guard.
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
     * Configure the custom session model and table, and run the shipped
     * migrations against it.
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
     * Drop the custom tables.
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
        Schema::dropIfExists('authentication_connection_guards');

        parent::tearDown();
    }

    /**
     * The custom model uses the configured table.
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
     * The shipped migration creates the configured table.
     *
     * @return void
     */
    public function testCustomTableNameAppliesToShippedMigration(): void
    {
        self::assertTrue(Schema::hasTable('custom_sessions'));
        self::assertFalse(Schema::hasTable('authentication_sessions'));
    }

    /**
     * A refresh resolves its session through the custom model class.
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

        $result = GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($refreshToken), self::requestClient($guard->getRequest()))->session?->tokens;

        self::assertInstanceOf(TokenPair::class, $result);
        self::assertNotSame('', $result->accessToken->reveal());
        self::assertNotSame('', $result->refreshToken?->reveal());
        self::assertInstanceOf($this->customModel, $guard->session());
    }

    /**
     * Skip the default sessions migration so the custom table is the only one.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void {}

    /**
     * Register the `custom-jwt` guard.
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
     * Build a `JwtGuard` over a stub provider and a resolver that treats the
     * identity as its own principal.
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
