<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Integration\Fixtures\RelationSessionsIdentity;
use Tests\TestCase;

/**
 * Bearer `sid` resolution through a real `morphMany` sessions relation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
final class JwtGuardSessionRelationIntegrationTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessionRecords;

    /**
     * Freeze the clocks and create the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        Schema::create('relation_sessions_identities', static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Release the frozen clocks and drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('relation_sessions_identities');

        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A `sid` naming one of the identity's sessions binds that session.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerBindsASessionLoadedThroughTheRelation(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity);

        $guard = $this->guardForBearer($this->accessToken($identity, $session));

        self::assertTrue($guard->check());
        self::assertSame($session->getKey(), $guard->session()?->getSessionIdentifier());
    }

    /**
     * A session revoked after the token was issued is rejected like a missing
     * one.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsARevokedSessionLoadedThroughTheRelation(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity);
        $token    = $this->accessToken($identity, $session);

        Session::query()->whereKey($session->getKey())->update(['revoked_at' => Carbon::now()]);

        self::assertFalse($this->guardForBearer($token)->check());
    }

    /**
     * A `sid` that cannot be a key of the relation's session model is rejected
     * without querying the sessions table.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsAMalformedDidWithoutQueryingTheRelation(): void
    {
        $identity = $this->seedIdentity();

        $malformed = new Session;
        $malformed->forceFill([
            ...self::liveSession(),
            'id'                   => 'not-a-uuid',
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
        ]);

        // The proofs table stores any key as a string; the session has no row,
        // so the token skips the issuance guard that writes to it.
        self::recordProof($malformed, ProofKind::FIRST_FACTOR, Carbon::now(), ['pwd']);

        $token = $this->authManager()->jwt('api')->issueGuardedAccessToken($identity, $identity, null, $malformed, Carbon::now())->token->reveal();

        DB::enableQueryLog();

        self::assertFalse($this->guardForBearer($token)->check());

        $sessionQueries = array_filter(
            DB::getQueryLog(),
            static fn (array $entry): bool => preg_match('/[`"]sessions[`"]/', $entry['query']) === 1,
        );

        self::assertSame([], $sessionQueries);
    }

    /**
     * Configure the `api` guard over the relation-backed identity.
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
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => RelationSessionsIdentity::class]);
    }

    /**
     * Persist an identity.
     *
     * @return \Tests\Integration\Fixtures\RelationSessionsIdentity
     */
    private function seedIdentity(): RelationSessionsIdentity
    {
        $identity = new RelationSessionsIdentity;
        $identity->forceFill([
            'email'    => 'relation@example.test',
            'password' => 'hashed',
        ])->save();

        return $identity;
    }

    /**
     * Persist a session owned by the identity through the relation.
     *
     * @param  \Tests\Integration\Fixtures\RelationSessionsIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function seedSession(RelationSessionsIdentity $identity): Session
    {
        $session = $identity->sessions()->make();
        $session->forceFill(self::liveSession(principal: $identity))->save();

        return $session;
    }

    /**
     * Issue an access token for the identity and session through the guard's
     * token service.
     *
     * @param  \Tests\Integration\Fixtures\RelationSessionsIdentity  $identity
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function accessToken(RelationSessionsIdentity $identity, Session $session): string
    {
        return $this->authManager()->jwt('api')->issueAccessToken($identity, $identity, null, $session)->reveal();
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

    /**
     * Resolve a fresh `api` guard for a request carrying the bearer token.
     *
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guardForBearer(string $token): JwtGuard
    {
        app()->instance('request', Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]));

        $guard = $this->authManager()->guard('api');

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
