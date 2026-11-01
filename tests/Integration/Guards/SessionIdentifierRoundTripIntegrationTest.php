<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Concerns\ActsAsSession;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\Integration\Fixtures\RenamedKeySession;
use Tests\Integration\Fixtures\RenamedKeySessionIdentity;
use Tests\TestCase;

/**
 * The session identifier a token carries is always the session's primary key,
 * so a session model whose key column is not `id` is found again by both the
 * bearer path and the refresh exchange, which look sessions up by primary key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversTrait(ActsAsSession::class)]
final class SessionIdentifierRoundTripIntegrationTest extends TestCase
{
    use InteractsWithSessionRecords;

    /** @var string Plaintext rotation id stored on the seeded session. */
    private const string ROTATION_ID = 'stored-rotation-id';

    /**
     * Create the identity and session tables.
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

        self::createSessionRecordTable('renamed_key_sessions', 'session_uuid');
    }

    /**
     * Drop the identity and session tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('renamed_key_sessions');
        Schema::dropIfExists('stub_principals');

        parent::tearDown();
    }

    /**
     * An access token names the session by its `session_uuid` key, and a
     * request carrying it through the `auth` middleware binds that session.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRequestBindsTheSessionTheTokenNamesByPrimaryKey(): void
    {
        [$identity, $session] = $this->seedIdentityWithSession();

        $token = $this->tokens()->issueAccessToken($identity, $identity, null, $session);

        self::assertSame($session->getKey(), $this->tokens()->parse($token, TokenType::ACCESS)[Claims::SESSION_ID->value] ?? null);

        Route::middleware('auth:api')->get('/session', static fn (): array => ['session' => Auth::session()?->getSessionIdentifier()]);

        $this->withHeaders(['Authorization' => 'Bearer ' . $token])
            ->getJson('/session')
            ->assertOk()
            ->assertExactJson(['session' => $session->getKey()]);
    }

    /**
     * A refresh token names the session by its `session_uuid` key, and the
     * exchange finds and rotates that session.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshRotatesTheSessionTheTokenNamesByPrimaryKey(): void
    {
        [$identity, $session] = $this->seedIdentityWithSession();

        $tokens = GuardSessions::of($this->guard())->refresh($this->tokens()->issueRefreshToken($session, self::ROTATION_ID, $identity))->session?->tokens;

        self::assertNotNull($tokens);
        self::assertNotSame(RefreshTokenHasher::hash(self::ROTATION_ID), RenamedKeySession::query()->whereKey($session->getKey())->firstOrFail()->getRefreshKey());
    }

    /**
     * Configure the `api` guard and the session model.
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

        $config->set('authentication.session.model', RenamedKeySession::class);

        $config->set('auth.guards.api', [
            'driver'      => 'jwt',
            'provider'    => 'identities',
            'application' => ['methods' => ['password']],
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => RenamedKeySessionIdentity::class,
        ]);
    }

    /**
     * Persist an identity with one live session holding the stored rotation.
     *
     * @return array{0: \Tests\Integration\Fixtures\RenamedKeySessionIdentity, 1: \Tests\Integration\Fixtures\RenamedKeySession}
     */
    private function seedIdentityWithSession(): array
    {
        $identity = new RenamedKeySessionIdentity;
        $identity->forceFill(['email' => 'renamed-key@example.test', 'password' => 'irrelevant'])->save();

        $session = new RenamedKeySession;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => RenamedKeySessionIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        return [$identity, $session];
    }

    /**
     * The `api` guard's token service.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokens(): JwtTokenService
    {
        $tokens = Auth::jwt('api');

        self::assertNotNull($tokens);

        return $tokens;
    }

    /**
     * The `api` guard.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guard(): JwtGuard
    {
        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $guard = $manager->guard('api');

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
