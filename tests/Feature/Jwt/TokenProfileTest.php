<?php

declare(strict_types = 1);

namespace Tests\Feature\Jwt;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\BearerAuthentication;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\TokenProfile;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithJwtTokens;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Feature tests for the token profile through Laravel: the tokens a sign-in
 * through the session service issues, and what a request behind the `auth`
 * middleware accepts. A token that breaks the profile in any way (its binding
 * to the guard, the issuer and the audience, its header type, its claim names,
 * its subject type, its session's authentication) is a 401 reported as
 * `token_invalid`, however well it is signed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtTokenService::class)]
#[CoversClass(TokenProfile::class)]
#[CoversClass(BearerAuthentication::class)]
final class TokenProfileTest extends TestCase
{
    use InteractsWithJwtTokens, InteractsWithSessionRecords, InteractsWithSessions;

    /** @var string The signing key every test guard shares. */
    private const string SECRET = 'test-secret-key-with-at-least-32-bytes!';

    /** @var string The kid the signing key is registered under. */
    private const string KID = 'test-kid';

    /**
     * Freeze the clocks, create the tables, and add a route behind the `auth`
     * middleware of the 2D guard.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();

        Route::middleware('auth:api')->get('/me', static fn (): array => ['identity' => Auth::id()]);
        Route::middleware('auth:members')->get('/members/me', static fn (): array => ['identity' => Auth::guard('members')->id()]);
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
     * A sign-in's access token is an `at+jwt` naming the issuer, audience and
     * guard, the identity as a person, its principal, its session and the
     * session's password authentication, with no tenant in 2D; its refresh
     * token is a `refresh+jwt` naming the session; and the access token
     * authenticates a request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInsTokensKeepTheProfile(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();
        $access   = $this->claims($session->tokens->accessToken->reveal(), TokenType::ACCESS);
        $refresh  = $this->claims($session->tokens->refreshToken?->reveal(), TokenType::REFRESH);

        self::assertSame('at+jwt', $this->jwtHeader($session->tokens->accessToken->reveal())['typ'] ?? null);
        self::assertSame('refresh+jwt', $this->jwtHeader($session->tokens->refreshToken?->reveal())['typ'] ?? null);

        self::assertSame([self::JWT_ISSUER, self::JWT_AUDIENCE, 'api'], [$access['iss'], $access['aud'], $access['client_id']]);
        $key = IdentifierCoercion::stringify($identity->getKey());

        self::assertSame([$key, 'person', $key], [$access['sub'], $access['sub_type'], $access['principal']]);
        self::assertSame([$session->record->getKey(), CarbonImmutable::now()->getTimestamp(), ['pwd']], [$access['sid'], $access['auth_time'], $access['amr']]);
        self::assertArrayNotHasKey('tenant_id', $access);

        self::assertSame([self::JWT_ISSUER, self::JWT_AUDIENCE, 'api', $session->record->getKey()], [$refresh['iss'], $refresh['aud'], $refresh['client_id'], $refresh['sid']]);
        self::assertArrayNotHasKey('sub_type', $refresh);

        $this->bearer($session->tokens->accessToken->reveal())->assertOk()->assertJson(['identity' => $identity->getKey()]);
    }

    /**
     * A session's authentication recorded after the token's issue time (another
     * server's clock ahead of this one's) is carried as the issue time, so the
     * token never claims an authentication fresher than itself and still
     * parses.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATokenNeverCarriesAnAuthenticationAfterItsIssueTime(): void
    {
        $identity = $this->seedIdentity();
        $session  = new Session;

        $session->forceFill([
            ...self::liveSession('api', $identity),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => IdentifierCoercion::stringify($identity->getKey()),
            'signed_in_at'         => CarbonImmutable::now()->addSeconds(5),
        ])->save();

        $token = Auth::jwt('api')->issueAccessToken($identity, $identity, null, $session)->reveal();

        self::assertSame(CarbonImmutable::now()->getTimestamp(), $this->claims($token, TokenType::ACCESS)['auth_time'] ?? null);
    }

    /**
     * A member's access token carries the tenant its principal acts within, and
     * authenticates a request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantPrincipalsTokenCarriesTheTenant(): void
    {
        [$member, , $tenant] = $this->seedMember();

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);
        $claims = $this->claims($session->tokens->accessToken->reveal(), TokenType::ACCESS, 'members');

        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $claims['tenant_id'] ?? null);

        $this->bearer($session->tokens->accessToken->reveal(), '/members/me')->assertOk()->assertJson(['identity' => $member->getKey()]);
    }

    /**
     * A token is never issued naming a tenant the principal does not act
     * within: a member's principal with another tenant given is refused, and
     * with its own the token names it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenNeverNamesATenantThePrincipalIsNotIn(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();
        [, , $other]                    = $this->seedMember('other@example.test');

        $tokens = Auth::jwt('members');

        $claims = $this->claims($tokens->issueAccessToken($member, $membership, $tenant, null)->reveal(), TokenType::ACCESS, 'members');

        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $claims['tenant_id'] ?? null);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot issue a token naming a tenant the principal does not act within');

        $tokens->issueAccessToken($member, $membership, $other, null)->reveal();
    }

    /**
     * A token of a session names the session's active tenant and no other:
     * issued for the session with any other tenant, or with none, it is
     * refused, and once the session acts in another tenant (one below the
     * principal's own, say) its tokens name that one, which a token without a
     * session never could.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionsTokenNamesTheSessionsActiveTenant(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();
        [, , $other]                    = $this->seedMember('other@example.test');

        $signedIn = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($signedIn);

        $record = $signedIn->record;
        $tokens = Auth::jwt('members');

        foreach ([$other, null] as $given) {

            try {
                $tokens->issueAccessToken($member, $membership, $given, $record)->reveal();

                self::fail('Expected a tenant the session does not act in to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertStringContainsString('naming another tenant than the one the session acts in', $exception->getMessage());
            }
        }

        $record->forceFill(['tenant_id' => IdentifierCoercion::stringify($other->getKey())])->save();

        $claims = $this->claims($tokens->issueAccessToken($member, $membership, $other, $record)->reveal(), TokenType::ACCESS, 'members');

        self::assertSame(IdentifierCoercion::stringify($other->getKey()), $claims['tenant_id'] ?? null);
        self::assertNotSame(IdentifierCoercion::stringify($tenant->getKey()), $claims['tenant_id']);
    }

    /**
     * A grace retry, the refresh token a refresh replaced presented again
     * inside the grace window, is handed an access token that names the tenant
     * the session's principal acts within, as the refresh's own does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAccessTokenOfAGraceRetryCarriesTheTenant(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);

        $this->clockAt(CarbonImmutable::now()->addMinute());

        $refreshed = $this->sessions('members')->refresh($session->tokens->refreshToken?->reveal())->session;

        self::assertNotNull($refreshed);

        $this->clockAt(CarbonImmutable::now()->addSeconds(5));

        $retried = $this->sessions('members')->refresh($session->tokens->refreshToken?->reveal())->session;

        self::assertNotNull($retried);

        $current = $this->claims($refreshed->tokens->refreshToken?->reveal(), TokenType::REFRESH, 'members');
        $handed  = $this->claims($retried->tokens->refreshToken?->reveal(), TokenType::REFRESH, 'members');

        self::assertSame($current['jti'] ?? null, $handed['jti'] ?? null);
        self::assertSame(
            IdentifierCoercion::stringify($tenant->getKey()),
            $this->claims($retried->tokens->accessToken->reveal(), TokenType::ACCESS, 'members')['tenant_id'] ?? null,
        );
    }

    /**
     * Rows of `[a change to a session's access token: claims to merge, claims
     * to remove, its header type]` that break the profile.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: list<string>, 2: ?string}>
     */
    public static function provideBrokenTokens(): iterable
    {
        yield from [
            'another guard'                  => [['client_id' => 'admin'], [], 'at+jwt'],
            'another issuer'                 => [['iss' => 'https://elsewhere.example.test'], [], 'at+jwt'],
            'another audience'               => [['aud' => 'https://elsewhere.example.test'], [], 'at+jwt'],
            'an audience list'               => [['aud' => [self::JWT_AUDIENCE]], [], 'at+jwt'],
            'no issuer'                      => [[], ['iss'], 'at+jwt'],
            'no audience'                    => [[], ['aud'], 'at+jwt'],
            'no header type'                 => [[], [], null],
            'the default header type'        => [[], [], 'JWT'],
            'the refresh header type'        => [[], [], 'refresh+jwt'],
            'the old typ and grd claims'     => [['typ' => 'access', 'grd' => 'api'], ['client_id'], 'JWT'],
            'a machine without a key'        => [['sub_type' => 'machine'], [], 'at+jwt'],
            'a person with a key'            => [['cid' => '0195f4a2-7b1c-7000-8000-000000000001', 'scope' => ''], ['sid', 'auth_time', 'amr'], 'at+jwt'],
            'no subject type'                => [[], ['sub_type'], 'at+jwt'],
            'no authentication time'         => [[], ['auth_time'], 'at+jwt'],
            'a malformed amr'                => [['amr' => 'pwd'], [], 'at+jwt'],
            'authentication with no session' => [[], ['sid'], 'at+jwt'],
            'an empty tenant'                => [['tenant_id' => ''], [], 'at+jwt'],
        ];
    }

    /**
     * A request whose access token breaks the profile is a 401, reported once
     * as `token_invalid`, however well it is signed.
     *
     * @param  array<string, mixed>  $merge
     * @param  list<string>  $remove
     * @param  ?string  $typ
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideBrokenTokens')]
    public function testARequestRejectsATokenThatBreaksTheProfile(array $merge, array $remove, ?string $typ): void
    {
        $this->seedIdentity();

        $token = $this->resigned($this->signedIn()->tokens->accessToken->reveal(), $merge, $remove, $typ);

        $this->recordEvents([AuthenticationFailed::class]);

        $this->bearer($token)->assertUnauthorized();

        self::assertSame(FailureReason::TOKEN_INVALID, $this->recordedEvent(AuthenticationFailed::class)->reason);
    }

    /**
     * The header type may carry the `application/` media type prefix, in any
     * case, and a token signed so is accepted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestAcceptsTheMediaTypeOfTheHeaderType(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();

        foreach (['application/at+jwt', 'Application/AT+JWT'] as $typ) {
            $this->bearer($this->resigned($session->tokens->accessToken->reveal(), [], [], $typ))->assertOk()->assertJson(['identity' => $identity->getKey()]);
        }
    }

    /**
     * A refresh token offered as proof of the client's previous session still
     * has its header and claims checked once it has expired: an expired refresh
     * token replaces its session, while the same token with an access token's
     * header type, or another issuer, proves nothing and replaces none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExpiredRefreshTokenOfferedAsProofKeepsItsChecks(): void
    {
        $this->seedIdentity();

        $first   = $this->signedIn();
        $expired = ['exp' => CarbonImmutable::now()->getTimestamp() - 60];

        foreach ([[[], 'at+jwt'], [['iss' => 'https://elsewhere.example.test'], 'refresh+jwt']] as [$merge, $typ]) {

            $proof = $this->resigned($first->tokens->refreshToken?->reveal(), [...$expired, ...$merge], [], $typ);

            self::assertNotNull($this->signInWithProof($proof));
            self::assertNull($this->stored($first)->revoked_at);
        }

        self::assertNotNull($this->signInWithProof($this->resigned($first->tokens->refreshToken?->reveal(), $expired, [], 'refresh+jwt')));
        self::assertSame('superseded', $this->stored($first)->revoked_reason);
    }

    /**
     * Configure the session guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * Sign the identity in with its password on the 2D guard.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(): SignedInSession
    {
        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Sign the identity in again with its password, offering the refresh token
     * as proof of its previous session.
     *
     * @param  string  $proof
     * @return ?\SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signInWithProof(string $proof): ?SignedInSession
    {
        $context = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), refreshToken: $proof);

        return $this->sessions()->signIn('password', self::credentials(), $context)->session;
    }

    /**
     * The signed-in session's row as it is stored now.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function stored(SignedInSession $session): Session
    {
        $stored = Session::query()->find($session->record->getKey());

        self::assertInstanceOf(Session::class, $stored);

        return $stored;
    }

    /**
     * Move every clock to the time given.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function clockAt(CarbonImmutable $time): void
    {
        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }

    /**
     * The claims the guard's token service reads from a token of the type.
     *
     * @param  string  $token
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @param  string  $guard
     * @return array<string, mixed>
     */
    private function claims(string $token, TokenType $type, string $guard = 'api'): array
    {
        $claims = Auth::jwt($guard)->parse($token, $type);

        self::assertIsArray($claims);

        return $claims;
    }

    /**
     * The token's own claims, changed, signed again with the guards' key under
     * the given header type, or none.
     *
     * @param  string  $token
     * @param  array<string, mixed>  $merge
     * @param  list<string>  $remove
     * @param  ?string  $typ
     * @return string
     */
    private function resigned(string $token, array $merge, array $remove, ?string $typ): string
    {
        $claims = json_decode(JWT::urlsafeB64Decode(explode('.', $token)[1]), true);

        self::assertIsArray($claims);

        $claims = [...array_diff_key($claims, array_flip($remove)), ...$merge];
        $header = ['alg' => 'HS256', 'kid' => self::KID, ...($typ === null ? [] : ['typ' => $typ])];
        $signed = JWT::urlsafeB64Encode((string) json_encode($header)) . '.' . JWT::urlsafeB64Encode((string) json_encode($claims));

        return $signed . '.' . JWT::urlsafeB64Encode(JWT::sign($signed, self::SECRET, 'HS256'));
    }

    /**
     * Send a request with the bearer token, on guards resolved afresh.
     *
     * @param  string  $token
     * @param  string  $uri
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(string $token, string $uri = '/me'): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson($uri);
    }
}
