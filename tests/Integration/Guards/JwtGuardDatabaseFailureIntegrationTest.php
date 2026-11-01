<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\Integration\Fixtures\UnreachableSession;
use Tests\Integration\Fixtures\UnreachableSessionIdentity;
use Tests\TestCase;

/**
 * A database that cannot be reached surfaces as a server error on refresh and
 * on bearer requests, not as an unknown session.
 *
 * The session model lives on a connection whose database does not exist, so the
 * session lookup fails while connecting, and an outage must not read as an
 * unknown session (a silent sign-out, or a 401 for every request).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(JwtGuard::class)]
final class JwtGuardDatabaseFailureIntegrationTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessionRecords;

    /** @var string Connection whose database cannot be opened. */
    private const string UNREACHABLE_CONNECTION = 'unreachable';

    /** @var string Well-formed id of the session the token names. */
    private const string SESSION_ID = '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70';

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
     * The connection failure propagates out of `refresh()` as a
     * `QueryException` naming the unreachable connection.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshPropagatesAConnectionFailureDuringSessionLookup(): void
    {
        config()->set('authentication.storage.connection', self::UNREACHABLE_CONNECTION);
        config()->set('authentication.rate_limits.connection', 'testing');
        config()->set('authentication.session.model', UnreachableSession::class);

        $session = new UnreachableSession;
        $session->forceFill([...self::liveSession(), 'id' => self::SESSION_ID]);

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($session, 'rotation-id');

        app()->instance('request', Request::create('/refresh', 'POST'));

        $guard = $this->authManager()->guard('api');

        assert($guard instanceof JwtGuard);

        $this->expectException(QueryException::class);
        $this->expectExceptionMessage('Connection: ' . self::UNREACHABLE_CONNECTION);

        GuardSessions::of($guard)->refresh($refreshToken);
    }

    /**
     * A bearer request whose `sid` lookup cannot connect answers with a server
     * error carrying the connection failure, not a 401.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerAnswersAConnectionFailureDuringSessionLookupWithAServerError(): void
    {
        $identity = new UnreachableSessionIdentity;
        $identity->forceFill(['email' => 'outage@example.test', 'password' => 'irrelevant'])->save();

        $session = new UnreachableSession;
        $session->forceFill([
            ...self::liveSession(),
            'id'                   => self::SESSION_ID,
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
        ]);

        // Its sign-in's proof is on the storage connection; only its own row is
        // out of reach.
        self::recordProof($session, ProofKind::FIRST_FACTOR, Carbon::now(), ['pwd']);

        $token = $this->authManager()->jwt('api')->issueAccessToken($identity, $identity, null, $session);

        Route::middleware('auth:api')->get('/me', static fn (): string => 'ok');

        $response = $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/me');

        $response->assertInternalServerError();

        self::assertInstanceOf(QueryException::class, $response->exception);
        self::assertStringContainsString('Connection: ' . self::UNREACHABLE_CONNECTION, $response->exception->getMessage());
    }

    /**
     * Configure the `api` guard and a connection whose database file does not
     * exist.
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

        $config->set('database.connections.' . self::UNREACHABLE_CONNECTION, [
            'driver'   => 'sqlite',
            'database' => sys_get_temp_dir() . '/laravel-authentication-missing/auth.sqlite',
            'prefix'   => '',
        ]);

        $config->set('auth.guards.api', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => UnreachableSessionIdentity::class,
        ]);
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
