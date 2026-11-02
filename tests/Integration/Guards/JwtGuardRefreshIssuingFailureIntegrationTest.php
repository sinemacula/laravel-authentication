<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\Integration\Fixtures\SingleIdentifierReadPrincipal;
use Tests\TestCase;
use Tests\Unit\Stubs\StubMutablePrincipalResolver;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * A refresh that fails while issuing either token of the new pair leaves the
 * presented refresh token valid, on the suite's configured database.
 *
 * Both tokens are issued before the rotation commits, so a failure while
 * issuing cannot consume the stored digest and sign the session out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(JwtGuard::class)]
final class JwtGuardRefreshIssuingFailureIntegrationTest extends TestCase
{
    use InteractsWithSessionRecords;

    /** @var string Plaintext rotation id stored on the seeded session. */
    private const string ROTATION_ID = 'stored-rotation-id';

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
     * The resolver hands back a principal whose identifier can be read once,
     * which the check that the session records it uses up, so the token service
     * fails while issuing the access token: the refresh throws, the stored
     * digest is unchanged in the database, and the same refresh token rotates
     * once the resolver returns a principal that can be read again.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshTokenStaysValidWhenIssuingTheAccessTokenFails(): void
    {
        $this->assertIssuingFailureLeavesTheTokenValid(1);
    }

    /**
     * The resolver hands back a principal whose identifier can be read twice,
     * so the access token is issued and the refresh token is not: the refresh
     * throws after the first token exists, the stored digest is unchanged in
     * the database, and the same refresh token rotates once the resolver
     * returns a principal that can be read again.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshTokenStaysValidWhenIssuingTheRefreshTokenFails(): void
    {
        $this->assertIssuingFailureLeavesTheTokenValid(2);
    }

    /**
     * Configure the `api` guard against the stub identity provider.
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

        $config->set('auth.guards.api', [
            'driver'      => 'jwt',
            'provider'    => 'identities',
            'application' => ['methods' => ['password']],
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);
    }

    /**
     * Persist an identity with a session holding the stored rotation, and issue
     * the refresh token that presents it.
     *
     * @return array{0: \Tests\Unit\Stubs\StubPrincipal, 1: \SineMacula\Laravel\Authentication\Models\Session, 2: string}
     */
    private function seedRefreshableSession(): array
    {
        $identity = new StubPrincipal;
        $identity->forceFill(['email' => 'issuing@example.test', 'password' => 'irrelevant'])->save();

        $session = new Session;
        $session->forceFill([
            ...self::liveSession('api', $identity),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        return [$identity, $session, $this->authManager()->jwt('api')->issueRefreshToken($session, self::ROTATION_ID)->reveal()];
    }

    /**
     * Refresh with a principal whose identifier fails after the given number of
     * reads, and assert the failure propagated after one more read and left the
     * presented refresh token valid.
     *
     * @param  int  $readsAllowed
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    private function assertIssuingFailureLeavesTheTokenValid(int $readsAllowed): void
    {
        [$identity, $session, $refreshToken] = $this->seedRefreshableSession();

        $principal = SingleIdentifierReadPrincipal::query()->findOrFail($identity->getKey());

        assert($principal instanceof SingleIdentifierReadPrincipal);

        $principal->readsAllowed = $readsAllowed;

        DB::table('authentication_sessions')->where('id', $session->getKey())->update(['principal_type' => SingleIdentifierReadPrincipal::class]);

        $resolver = new StubMutablePrincipalResolver;
        $resolver->setDefaultPrincipal($principal);

        try {
            GuardSessions::of($this->guard($resolver))->refresh($refreshToken);

            self::fail('The issuing failure should have propagated.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The principal identifier cannot be read again.', $exception->getMessage());
        }

        self::assertSame($readsAllowed + 1, $principal->identifierReads);

        DB::table('authentication_sessions')->where('id', $session->getKey())->update(['principal_type' => StubPrincipal::class]);

        $this->assertRefreshTokenStillRotates($identity, $session, $refreshToken, $resolver);
    }

    /**
     * Assert the failed refresh left the stored digest alone, then that the
     * same refresh token rotates once the resolver returns the saved identity.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @param  string  $refreshToken
     * @param  \Tests\Unit\Stubs\StubMutablePrincipalResolver  $resolver
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function assertRefreshTokenStillRotates(
        StubPrincipal $identity,
        Session $session,
        #[\SensitiveParameter] string $refreshToken,
        StubMutablePrincipalResolver $resolver,
    ): void {
        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), $this->storedDigest($session));

        $resolver->setDefaultPrincipal($identity);

        $guard = $this->guard($resolver);

        self::assertTrue(GuardSessions::of($guard)->refresh($refreshToken)->isRefreshed());
        self::assertTrue($identity->is($guard->user()));
        self::assertNotSame(RefreshTokenHasher::hash(self::ROTATION_ID), $this->storedDigest($session));
    }

    /**
     * Read the session's stored refresh digest from the database.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @return ?string
     */
    private function storedDigest(Session $session): ?string
    {
        $fresh = Session::query()->findOrFail($session->getKey());

        assert($fresh instanceof Session);

        return $fresh->getRefreshKey();
    }

    /**
     * Resolve a fresh `api` guard for a new request, bound to the resolver.
     *
     * @param  \Tests\Unit\Stubs\StubMutablePrincipalResolver  $resolver
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guard(StubMutablePrincipalResolver $resolver): JwtGuard
    {
        app()->instance('request', Request::create('/refresh', 'POST'));

        $guard = $this->authManager()->guard('api');

        assert($guard instanceof JwtGuard);

        $guard->setPrincipalResolver($resolver);

        return $guard;
    }

    /**
     * Resolve the package auth manager with no cached guards.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     */
    private function authManager(): AuthManager
    {
        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $manager->forgetGuards();

        return $manager;
    }
}
