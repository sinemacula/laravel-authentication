<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubActiveAwarePrincipal;
use Tests\Unit\Stubs\StubMutablePrincipalResolver;

/**
 * The bearer and refresh paths read identity, principal and session state live
 * on every request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
final class JwtGuardResolutionFreshnessIntegrationTest extends TestCase
{
    use InteractsWithSessionRecords;

    /** @var string Guard name used by all freshness tests. */
    private const string GUARD = 'api';

    /** @var string Container alias for the fixed principal resolver. */
    private const string RESOLVER = 'freshness-resolver';

    /** @var string HS256 signing secret for freshness test tokens. */
    private const string JWT_SECRET = 'freshness-secret-with-at-least-32-bytes!';

    /** @var string Kid the signing secret is registered under. */
    private const string JWT_KID = 'test-kid';

    /**
     * Provision the identity table and register the mutable principal resolver.
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
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        assert($this->app !== null);

        $this->app->instance(self::RESOLVER, new StubMutablePrincipalResolver);
    }

    /**
     * Drop the shared identity table.
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
     * Bearer auth rejects the next request once the identity becomes inactive.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testBearerRejectsPreviouslyIssuedTokenWhenIdentityBecomesInactiveBetweenRequests(): void
    {
        $identity  = $this->seedIdentity();
        $principal = new PlainPrincipalFixture('principal-live', $identity);

        $this->resolver()->setHintedPrincipal('principal-live', $principal);

        $jwt = PackageAuth::jwt(self::GUARD);

        $token = $jwt->issueAccessToken($identity, $principal, null, null)->reveal();

        self::assertTrue($this->guardForBearer($token)->check());

        $identity->is_active = false;
        $identity->save();

        self::assertFalse($this->guardForBearer($token)->check());
    }

    /**
     * Principals stay live-resolved on every bearer request.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testBearerRejectsPreviouslyIssuedTokenWhenResolvedPrincipalBecomesInactiveBetweenRequests(): void
    {
        $identity = $this->seedIdentity('principal-change@example.test');

        $activePrincipal   = new PlainPrincipalFixture('principal-live', $identity, null, true);
        $inactivePrincipal = new PlainPrincipalFixture('principal-live', $identity, null, false);

        $this->resolver()->setHintedPrincipal('principal-live', $activePrincipal);

        $jwt = PackageAuth::jwt(self::GUARD);

        $token = $jwt->issueAccessToken($identity, $activePrincipal, null, null)->reveal();

        self::assertTrue($this->guardForBearer($token)->check());

        $this->resolver()->setHintedPrincipal('principal-live', $inactivePrincipal);

        self::assertFalse($this->guardForBearer($token)->check());
    }

    /**
     * Deleting the session row fails the next bearer request with that `sid`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testBearerRejectsPreviouslyIssuedTokenWhenHintedSessionIsDeletedBetweenRequests(): void
    {
        $identity = $this->seedIdentity('session-delete@example.test');
        $session  = $this->seedSession($identity);

        $this->resolver()->setHintedPrincipal((string) $identity->getKey(), $identity); // @phpstan-ignore cast.string

        $jwt = PackageAuth::jwt(self::GUARD);

        $token = $jwt->issueAccessToken($identity, $identity, null, $session)->reveal();

        self::assertTrue($this->guardForBearer($token)->check());

        $session->delete();

        self::assertFalse($this->guardForBearer($token)->check());
    }

    /**
     * Refresh re-checks the live identity row on every exchange.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshRejectsTokenWhenIdentityBecomesInactiveAfterIssuance(): void
    {
        $identity = $this->seedIdentity('refresh-identity@example.test');
        $session  = $this->seedSession($identity, 'stored-rotation-id');

        $jwt = PackageAuth::jwt(self::GUARD);

        $token = $jwt->issueRefreshToken($session, 'stored-rotation-id', $identity)->reveal();

        $identity->is_active = false;
        $identity->save();

        self::assertNull(GuardSessions::of($this->freshGuard())->refresh(PresentedRefreshToken::fromBody($token), self::requestClient())->session);
    }

    /**
     * Refresh re-checks the live principal on every exchange.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshRejectsTokenWhenPrincipalBecomesInactiveAfterIssuance(): void
    {
        $identity = $this->seedIdentity('refresh-principal@example.test');
        $session  = $this->seedSession($identity, 'refresh-principal-rotation');

        $activePrincipal   = new PlainPrincipalFixture('principal-refresh', $identity, null, true);
        $inactivePrincipal = new PlainPrincipalFixture('principal-refresh', $identity, null, false);

        $jwt = PackageAuth::jwt(self::GUARD);

        $token = $jwt->issueRefreshToken($session, 'refresh-principal-rotation', $activePrincipal)->reveal();

        $this->resolver()->setHintedPrincipal('principal-refresh', $inactivePrincipal);

        self::assertNull(GuardSessions::of($this->freshGuard())->refresh(PresentedRefreshToken::fromBody($token), self::requestClient())->session);
    }

    /**
     * Refresh fails once the referenced session has been deleted.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshRejectsTokenWhenSessionIsDeletedAfterIssuance(): void
    {
        $identity = $this->seedIdentity('refresh-session-delete@example.test');
        $session  = $this->seedSession($identity, 'refresh-session-delete');

        $jwt = PackageAuth::jwt(self::GUARD);

        $token = $jwt->issueRefreshToken($session, 'refresh-session-delete', $identity)->reveal();

        $session->delete();

        self::assertNull(GuardSessions::of($this->freshGuard())->refresh(PresentedRefreshToken::fromBody($token), self::requestClient())->session);
    }

    /**
     * A token is rejected once the resolver stops mapping its `principal`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBearerSeesChangedResolverMappingOnFreshRequest(): void
    {
        $identity = $this->seedIdentity('resolver-change@example.test');

        $this->resolver()->setHintedPrincipal('staff-actor', new PlainPrincipalFixture('staff-actor', $identity));

        $token = $this->encodeAccessToken([
            'sub'       => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal' => 'staff-actor',
            'iat'       => time(),
            'exp'       => time() + 600,
        ]);

        $firstGuard = $this->guardForBearer($token);

        self::assertTrue($firstGuard->check());
        self::assertSame('staff-actor', $firstGuard->principal()?->getPrincipalIdentifier());

        $this->resolver()->setHintedPrincipal('staff-actor', new PlainPrincipalFixture('customer-actor', $identity));

        self::assertFalse($this->guardForBearer($token)->check());
    }

    /**
     * Configure the single JWT guard used by this suite.
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

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.defaults.guard', self::GUARD);

        $config->set('auth.guards.' . self::GUARD, [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'principal_resolver' => self::RESOLVER,
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubActiveAwarePrincipal::class,
        ]);

        $config->set('authentication.jwt.keys', [self::JWT_KID => self::JWT_SECRET]);
        $config->set('authentication.jwt.active_kid', self::JWT_KID);
        $config->set('authentication.jwt.algorithm', 'HS256');
    }

    /**
     * Persist and return an active identity row.
     *
     * @param  string  $email
     * @return \Tests\Unit\Stubs\StubActiveAwarePrincipal
     */
    private function seedIdentity(string $email = 'freshness@example.test'): StubActiveAwarePrincipal
    {
        $hasher = app(Hasher::class);

        $identity            = new StubActiveAwarePrincipal;
        $identity->email     = $email;
        $identity->password  = $hasher->make('correct horse battery staple');
        $identity->is_active = true;
        $identity->save();

        return $identity;
    }

    /**
     * Return the mutable principal resolver bound for the suite.
     *
     * @return \Tests\Unit\Stubs\StubMutablePrincipalResolver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolver(): StubMutablePrincipalResolver
    {
        assert($this->app !== null);

        $resolver = $this->app->make(self::RESOLVER);

        assert($resolver instanceof StubMutablePrincipalResolver);

        return $resolver;
    }

    /**
     * Resolve a fresh guard against a bearer-authenticated request.
     *
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guardForBearer(#[\SensitiveParameter] string $token): JwtGuard
    {
        app()->instance('request', Request::create('/freshness', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $token,
        ]));

        return $this->freshGuard();
    }

    /**
     * Resolve a fresh guard against the current request binding.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function freshGuard(): JwtGuard
    {
        $manager = PackageAuth::manager();
        $manager->forgetGuards();

        $guard = $manager->guard(self::GUARD);

        self::assertInstanceOf(JwtGuard::class, $guard);

        return $guard;
    }

    /**
     * Persist and return a session row for the supplied identity.
     *
     * @param  \Tests\Unit\Stubs\StubActiveAwarePrincipal  $identity
     * @param  ?string  $rotationId
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function seedSession(StubActiveAwarePrincipal $identity, ?string $rotationId = null): Session
    {
        $session = new Session;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => StubActiveAwarePrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => $rotationId === null ? null : RefreshTokenHasher::hash($rotationId),
        ])->save();

        return $session;
    }

    /**
     * Encode a signed access token with test defaults and the given claims.
     *
     * @param  array<string, mixed>  $claims
     * @return string
     */
    private function encodeAccessToken(array $claims): string
    {
        $defaults = [Claims::JWT_ID->value => 'access-token-id', Claims::SUBJECT_TYPE->value => 'person'];

        if (($claims[Claims::SESSION_ID->value] ?? null) !== null) {
            $defaults += [Claims::AUTH_TIME->value => $claims[Claims::ISSUED_AT->value] ?? time(), Claims::AUTHENTICATION_METHODS->value => ['pwd']];
        }

        return JWT::encode(
            [...$defaults, ...$claims, Claims::ISSUER->value => self::JWT_ISSUER, Claims::AUDIENCE->value => self::JWT_AUDIENCE, Claims::CLIENT_ID->value => self::GUARD],
            self::JWT_SECRET,
            'HS256',
            self::JWT_KID,
            ['typ' => TokenType::ACCESS->value],
        );
    }
}
