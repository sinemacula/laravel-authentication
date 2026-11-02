<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session as SessionContract;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\ProvenSessions;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests for what proves a client holds a session: its current refresh
 * token, validly signed for the guard and possibly expired, for a session of
 * the guard that the identity signing in owns, for the same principal, and that
 * is not revoked. Anything less proves nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProvenSessions::class)]
final class ProvenSessionsTest extends TestCase
{
    use InteractsWithSessions;

    /** @var \Tests\Integration\Fixtures\IntegrationIdentity The identity whose session is proven. */
    private IntegrationIdentity $identity;

    /** @var \SineMacula\Laravel\Authentication\Sessions\SignedInSession The session that is proven. */
    private SignedInSession $session;

    /**
     * Freeze the clocks, create the tables, and start a session to prove.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        $this->createSessionTables();

        $this->identity = $this->seedIdentity();

        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        $this->session = $session;
    }

    /**
     * Release the clocks and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * The current refresh token proves its session, live or expired.
     *
     * @return void
     */
    public function testTheCurrentRefreshTokenProvesItsSession(): void
    {
        $proven = $this->prove($this->session->tokens->refreshToken->reveal());

        self::assertInstanceOf(Session::class, $proven);
        self::assertSame($this->session->record->getKey(), $proven->getKey());

        JWT::$timestamp = Carbon::now()->addYears(2)->getTimestamp();

        self::assertSame($this->session->record->getKey(), $this->prove($this->session->tokens->refreshToken->reveal())?->getSessionIdentifier());
    }

    /**
     * A session that is revoked, holds no refresh credential, or holds another
     * rotation id is not proven.
     *
     * @return void
     */
    public function testTheSessionMustBeLiveAndHoldTheRotationId(): void
    {
        $token = $this->session->tokens->refreshToken->reveal();

        $this->updateSession(['refresh_key' => hash('sha256', 'another-rotation-id')]);
        self::assertNull($this->prove($token));

        $this->updateSession(['refresh_key' => null]);
        self::assertNull($this->prove($token));

        $digest = hash('sha256', (string) $this->claims($token)[Claims::JWT_ID->value]); // @phpstan-ignore cast.string

        $this->updateSession(['refresh_key' => $digest, 'revoked_at' => Carbon::now()]);
        self::assertNull($this->prove($token));

        $this->updateSession(['revoked_at' => null]);
        self::assertNotNull($this->prove($token));
    }

    /**
     * A session that returned to pending keeps its refresh digest but proves
     * nothing until it is active again, so a factor policy is never told of a
     * session that may not refresh.
     *
     * @return void
     */
    public function testASessionReturnedToPendingProvesNothing(): void
    {
        $token = $this->session->tokens->refreshToken->reveal();

        $this->updateSession(['status' => 'pending', 'requires' => '["mfa"]']);
        self::assertNull($this->prove($token));

        $this->updateSession(['status' => 'active', 'requires' => null]);
        self::assertNotNull($this->prove($token));
    }

    /**
     * The session must be the identity's own, record the guard proving it, and
     * record the principal signing in.
     *
     * @return void
     */
    public function testTheSessionMustBeTheIdentitysForTheGuardAndPrincipal(): void
    {
        $token = $this->session->tokens->refreshToken->reveal();
        $other = $this->seedIdentity('bea@example.test');

        self::assertNull($this->prove($token, $other));
        self::assertNull((new ProvenSessions(Auth::manager()->jwt('api')))->provenSession('admin', $this->admitted($this->identity), $token));

        $this->updateSession(['guard' => 'admin']);
        self::assertNull($this->prove($token));

        $this->updateSession(['guard' => 'api']);

        [$member, $membership] = $this->seedMember();

        self::assertNull($this->prove($token, $this->identity, $membership));
        self::assertNull($this->prove($token, $member, $membership));
        self::assertNotNull($this->prove($token));
    }

    /**
     * A proof for a sign-in that has no principal yet (one waiting for a
     * choice) needs the session to be the identity's own for the guard, live,
     * and holding the rotation id, whatever principal it records.
     *
     * @return void
     */
    public function testAProofWithoutAPrincipalIgnoresTheRecordedPrincipal(): void
    {
        $token = $this->session->tokens->refreshToken->reveal();
        $proof = new ProvenSessions(Auth::manager()->jwt('api'));

        $this->updateSession(['principal_id' => '999']);

        self::assertSame($this->session->record->getKey(), $proof->provenSessionOf('api', $this->identity, null, $token)?->getSessionIdentifier());
        self::assertNull($proof->provenSessionOf('api', $this->identity, $this->identity, $token));
        self::assertNull($proof->provenSessionOf('api', $this->seedIdentity('bea@example.test'), null, $token));
        self::assertNull($proof->provenSessionOf('admin', $this->identity, null, $token));

        $this->updateSession(['revoked_at' => Carbon::now()]);

        self::assertNull($proof->provenSessionOf('api', $this->identity, null, $token));
    }

    /**
     * Only a refresh token of this guard naming an existing session is a proof:
     * garbage, an access token, another guard's refresh token, and one naming
     * no session prove nothing.
     *
     * @return void
     */
    public function testOnlyARefreshTokenOfTheGuardNamingASessionIsAProof(): void
    {
        $admin = Auth::manager()->jwt('admin');
        $api   = Auth::manager()->jwt('api');

        $claims = $this->claims($this->session->tokens->refreshToken->reveal());

        self::assertNull($this->prove('not-a-jwt'));
        self::assertNull($this->prove($this->session->tokens->accessToken->reveal()));
        self::assertNull($this->prove($admin->issueRefreshToken($this->session->record, (string) $claims[Claims::JWT_ID->value], $this->identity))); // @phpstan-ignore cast.string

        $this->session->record->delete();

        self::assertNull($this->prove($api->issueRefreshToken($this->session->record, (string) $claims[Claims::JWT_ID->value], $this->identity))); // @phpstan-ignore cast.string
    }

    /**
     * A refresh token whose rotation id is not a string proves nothing, even
     * when it is validly signed.
     *
     * @return void
     */
    public function testARotationIdThatIsNotAStringProvesNothing(): void
    {
        $claims = $this->claims($this->session->tokens->refreshToken->reveal());

        $claims[Claims::JWT_ID->value] = 12345;

        self::assertNull($this->prove(JWT::encode($claims, 'test-secret-key-with-at-least-32-bytes!', 'HS256', 'test-kid')));
    }

    /**
     * Configure the guards.
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

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * Ask the `api` guard's proof for the session the token proves for the
     * identity (the seeded one by default) acting as the principal (itself by
     * default).
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $token
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     */
    private function prove(#[\SensitiveParameter] Secret|string $token, ?Identity $identity = null, ?Principal $principal = null): ?SessionContract
    {
        return (new ProvenSessions(Auth::manager()->jwt('api')))->provenSession('api', $this->admitted($identity ?? $this->identity, $principal), $token);
    }

    /**
     * An admitted sign-in of the identity as the principal (itself by default).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted
     */
    private function admitted(Identity $identity, ?Principal $principal = null): Admitted
    {
        self::assertTrue($principal !== null || $identity instanceof Principal);

        /** @var \SineMacula\Laravel\Authentication\Contracts\Principal $acting */
        $acting = $principal ?? $identity;

        return new Admitted($identity, $acting, null);
    }

    /**
     * The claims of the token, accepting an expired one.
     *
     * @param  string  $token
     * @return array<string, mixed>
     */
    private function claims(#[\SensitiveParameter] string $token): array
    {
        $claims = Auth::manager()->jwt('api')->parse($token, TokenType::REFRESH);

        self::assertIsArray($claims);

        return $claims;
    }

    /**
     * Write values onto the session row.
     *
     * @param  array<string, mixed>  $values
     * @return void
     */
    private function updateSession(array $values): void
    {
        Session::query()->whereKey($this->session->record->getKey())->update($values);
    }
}
