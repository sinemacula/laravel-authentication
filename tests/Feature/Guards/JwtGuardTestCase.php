<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Timebox;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\RevocationWriter;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use Tests\Concerns\BindsSignInPolicyDoubles;
use Tests\Concerns\BuildsPlainValues;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Fixtures\Sessions\FirstFactorRecorder;
use Tests\Unit\Stubs\StubInjectableSession;
use Tests\Unit\Stubs\StubSession;

/**
 * Shared base case for the JwtGuard split tests.
 *
 * Owns collaborator mocks, the in-memory `stub_sessions` schema with the
 * shipped proofs and provenance tables (each saved session row given the
 * first-factor proof its sign-in would record), the frozen Carbon and JWT
 * clocks, and the helper factories used by every concrete `JwtGuardTest`
 * variant. Each subclass covers one slice of JwtGuard's behaviour.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class JwtGuardTestCase extends TestCase
{
    use BindsSignInPolicyDoubles, BuildsPlainValues, InteractsWithProofs, InteractsWithSessionRecords, MockeryPHPUnitIntegration;

    /** @var string The guard name forwarded to JwtGuard's constructor. */
    protected const string GUARD_NAME = 'jwt-test';

    /** @var string Issuer the test token service writes into and checks in `iss`. */
    protected const string ISSUER = 'https://issuer.example.test';

    /** @var string Audience the test token service writes into and checks in `aud`. */
    protected const string AUDIENCE = 'https://api.example.test';

    /** @var string Shared secret for the hand-rolled JWT tokens. */
    protected const string SECRET = 'test-secret-key-with-at-least-32-bytes!';

    /** @var string Kid the test secret is registered under. */
    protected const string KID = 'test-kid';

    /** @var string HMAC algorithm for the hand-rolled JWT tokens. */
    protected const string ALGORITHM = 'HS256';

    /** @var int Access-token TTL in minutes. */
    protected const int ACCESS_TTL = 15;

    /** @var int Refresh-token TTL in minutes. */
    protected const int REFRESH_TTL = 60 * 24 * 30;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\IdentityProvider The mocked identity provider collaborator. */
    protected MockInterface $provider;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\PrincipalResolver The mocked principal resolver collaborator. */
    protected MockInterface $resolver;

    /** @var \Illuminate\Contracts\Events\Dispatcher&\Mockery\MockInterface The mocked event dispatcher collaborator. */
    protected MockInterface $events;

    /** @var \Illuminate\Support\Timebox&\Mockery\MockInterface The mocked timebox collaborator. */
    protected MockInterface $timebox;

    /** @var \SineMacula\Laravel\Authentication\Jwt\JwtTokenService Real token service used to decode the tokens the guard parses. */
    protected JwtTokenService $tokens;

    /** @var \Carbon\Carbon Frozen clock reference shared by the Carbon and JWT test clocks. */
    protected Carbon $now;

    /**
     * Build fresh collaborator mocks, freeze the clock, and create the
     * in-memory schema for StubSession.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        assert($this->app !== null);

        $this->now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

        $this->provider = \Mockery::mock(IdentityProvider::class);
        $this->resolver = \Mockery::mock(PrincipalResolver::class);
        $this->events   = \Mockery::mock(Dispatcher::class);
        $this->timebox  = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('dontReturnEarly')->andReturnSelf();
        $this->tokens = new JwtTokenService(
            JwtKeyring::fromKeyMap([self::KID => self::SECRET], self::KID, self::ALGORITHM),
            self::GUARD_NAME,
            new TokenLifetimes(self::ACCESS_TTL, self::REFRESH_TTL, 60 * 24 * 180, 30),
            30,
            self::ISSUER,
            self::AUDIENCE,
        );

        // Every principal's sessions last as long as the token service says.
        self::bindSignInPolicyDoubles($this->app, $this->tokens->lifetimes());

        // Default: Timebox::call() invokes the callback directly so credential
        // validation paths run deterministically.
        $this->timebox->shouldReceive('call')
            ->byDefault()
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox));

        self::createSessionRecordTable('stub_sessions');
        self::migrateProofTables();

        // A session row a test saves records the first factor its sign-in would
        // have, so the tokens issued for it carry `auth_time` and `amr`.
        FirstFactorRecorder::listen($this->app->make(Dispatcher::class), static fn (): bool => true);
    }

    /**
     * Release the frozen clocks and drop the in-memory schema.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_sessions');

        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * Define the Testbench environment: an in-memory sqlite connection (so the
     * refresh path can hit a real Eloquent query), the guard's `auth.guards`
     * entry, and the package config keys the guard reads.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        $config->set('authentication.session.model', StubSession::class);
        $config->set('authentication.session.table', 'stub_sessions');

        // Every refresh reads the guard's transport, so the guard is configured
        // as `auth.guards` would configure it, over the package's defaults.
        $config->set('auth.guards.' . self::GUARD_NAME, ['driver' => 'jwt', 'provider' => 'users']);
        $config->set('authentication.refresh_token', [
            'transport'  => 'body',
            'body_field' => 'refresh_token',
            'header'     => 'X-Refresh-Token',
            'cookie'     => ['name' => null, 'path' => null, 'allowed_origins' => [], 'csrf_header' => 'X-Requested-With'],
        ]);
    }

    /**
     * Instantiate JwtGuard with the current set of collaborator mocks and the
     * supplied request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function makeGuard(Request $request): JwtGuard
    {
        $app = $this->app;

        assert($app !== null);

        return new JwtGuard(
            self::GUARD_NAME,
            $this->provider,
            $this->resolver,
            $this->events,
            $request,
            $this->timebox,
            $this->tokens,
            static fn (GuardContext $context): SessionRevocations => new SessionRevocations(
                $context,
                new RevocationWriter($app->make(ConnectionResolverInterface::class), static fn (): mixed => $app->make('db.transactions')),
                $app,
            ),
            static fn (): RefreshTokenTransport => RefreshTokenTransport::forGuard(self::GUARD_NAME, config()),
        );
    }

    /**
     * Build a real Illuminate Request with (or without) a bearer token
     * Authorization header.
     *
     * @param  string|null  $token
     * @return \Illuminate\Http\Request
     */
    protected function makeRequest(?string $token): Request
    {
        $headers = [];

        if ($token !== null) {
            $headers['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
        }

        return Request::create('/test', 'GET', [], [], [], $headers);
    }

    /**
     * Encode an access-token-style JWT with `iat`, `exp`, the service's `iss`
     * and `aud`, and the guard's `client_id` baked in, under the `at+jwt`
     * header type, plus a default `jti` and the `person` subject type the
     * claims may override, and, for a token that names a session, an
     * `auth_time` of now and a password `amr` it may override too, so the real
     * `JwtTokenService::parse(..., TokenType::ACCESS)` path accepts it.
     *
     * @param  array<string, mixed>  $claims
     * @return string
     */
    protected function encodeAccessToken(array $claims): string
    {
        $now      = $this->now->getTimestamp();
        $defaults = ['jti' => 'access-token-id', 'sub_type' => 'person'];

        if (($claims['sid'] ?? null) !== null) {
            $defaults += ['auth_time' => $now, 'amr' => ['pwd']];
        }

        return $this->encodeToken([...$defaults, ...$claims, ...$this->bindingClaims($now, $now + (self::ACCESS_TTL * 60))]);
    }

    /**
     * Encode a raw payload as a JWT of the type using the shared test secret.
     *
     * @param  array<string, mixed>  $payload
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @return string
     */
    protected function encodeToken(array $payload, TokenType $type = TokenType::ACCESS): string
    {
        return JWT::encode($payload, self::SECRET, self::ALGORITHM, self::KID, ['typ' => $type->value]);
    }

    /**
     * Encode a refresh-token-style JWT with `iat`, `exp`, the service's `iss`
     * and `aud`, and the guard's `client_id`, under the `refresh+jwt` header
     * type, so the real refresh parse path accepts it.
     *
     * @param  array<string, mixed>  $claims
     * @return string
     */
    protected function encodeRefreshToken(array $claims): string
    {
        $now = $this->now->getTimestamp();

        return $this->encodeToken([...$claims, ...$this->bindingClaims($now, $now + (self::REFRESH_TTL * 60))], TokenType::REFRESH);
    }

    /**
     * The claims that bind a token to the test service, and its issue and
     * expiry times.
     *
     * @param  int  $issuedAt
     * @param  int  $expiresAt
     * @return array<string, mixed>
     */
    protected function bindingClaims(int $issuedAt, int $expiresAt): array
    {
        return [
            'iss'       => self::ISSUER,
            'aud'       => self::AUDIENCE,
            'client_id' => self::GUARD_NAME,
            'iat'       => $issuedAt,
            'exp'       => $expiresAt,
        ];
    }

    /**
     * Swap the configured session model to `StubInjectableSession`, whose
     * `newQuery()` yields a Builder mock that returns the supplied in-memory
     * session from `find()`, so the refresh tests control the exact session row
     * the exchange sees without a database round trip. The session is reloaded
     * first so it carries every column, as the exchange's own lookup would.
     *
     * @param  \Tests\Unit\Stubs\StubSession  $session
     * @return void
     */
    protected function swapSessionModelToInMemoryInstance(StubSession $session): void
    {
        $session->refresh();

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')
            ->atLeast()->once()
            ->andReturnSelf();
        $builder->shouldReceive('find')
            ->with($session->id)
            ->andReturn($session);
        $builder->shouldReceive('find')
            ->andReturn(null);

        StubInjectableSession::$injectedBuilder = $builder;

        config()->set('authentication.session.model', StubInjectableSession::class);
    }

    /**
     * Expect the guard's identity provider to reload the session's owner once,
     * by the owner key stored on the session row, and answer with the supplied
     * identity.
     *
     * @param  \Tests\Unit\Stubs\StubSession  $session
     * @param  mixed  $identity
     * @return void
     */
    protected function expectOwnerReload(StubSession $session, mixed $identity): void
    {
        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with($session->getAttribute('authenticatable_id'))
            ->andReturn($identity);
    }
}
