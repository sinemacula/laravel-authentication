<?php

declare(strict_types = 1);

namespace Tests\Feature\Jwt;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Firebase\JWT\JWT;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\SessionTokens;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Concerns\PretendsStorageEngines;
use Tests\TestCase;
use Tests\Unit\Stubs\StubIdentity;

/**
 * Feature tests of issuing a session's token pair against a real session: the
 * access token for what was admitted and the refresh token carrying the
 * rotation id, with the access token's expiry and lifetime as the claims it was
 * signed with give them, capped as the token is by the session's deadlines.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionTokens::class)]
final class SessionTokensTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessionRecords, PretendsStorageEngines;

    /** @var string The secret the test keyring signs with. */
    private const string SECRET = 'test-secret-key-with-at-least-32-bytes!';

    /** @var string The rotation id the refresh token carries. */
    private const string ROTATION_ID = 'rotation-id-1';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);
        CarbonImmutable::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();
    }

    /**
     * Release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * The pair says when its access token expires and how long it lives as the
     * token's `exp` and `iat` do, the guard's access lifetime for a long
     * session, in the timezone of the time it was issued at; its refresh token
     * carries the rotation id and the principal, in the body.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePairSaysWhenItsAccessTokenExpiresAsTheTokenDoes(): void
    {
        $session = $this->storedSession();
        $pair    = SessionTokens::pair(self::tokens(), self::admitted(), $session, self::ROTATION_ID, $this->now->setTimezone('Europe/Paris'));
        $access  = self::claimsOf($pair);

        self::assertIsInt($access['exp']);
        self::assertIsInt($access['iat']);
        self::assertSame($access['exp'], $pair->expiresAt->getTimestamp());
        self::assertSame($access['exp'] - $access['iat'], $pair->expiresIn);
        self::assertSame(15 * 60, $pair->expiresIn);
        self::assertSame($this->now->getTimestamp(), $access['iat']);
        self::assertSame('Europe/Paris', $pair->expiresAt->getTimezone()->getName());
        self::assertNull($pair->refreshCookie);

        $refresh = self::tokens()->parse($pair->refreshToken?->reveal() ?? '', TokenType::REFRESH);

        self::assertIsArray($refresh);
        self::assertSame([self::ROTATION_ID, 'principal-3', $session->getSessionIdentifier()], [$refresh['jti'], $refresh['principal'], $refresh['sid']]);
    }

    /**
     * An access token is never issued past the end of its session, so the pair
     * says it expires at the session's idle deadline, or its absolute one, when
     * that comes before the access lifetime ends.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePairsExpiryIsCappedByTheSessionsDeadlines(): void
    {
        foreach ([[$this->now->addMinutes(4), $this->now->addDay()], [$this->now->addDay(), $this->now->addMinutes(3)]] as [$idle, $absolute]) {

            $session = $this->storedSession($idle, $absolute);
            $pair    = SessionTokens::pair(self::tokens(), self::admitted(), $session, self::ROTATION_ID, $this->now);
            $ends    = min($idle->getTimestamp(), $absolute->getTimestamp());

            self::assertSame([$ends, $ends - $this->now->getTimestamp()], [$pair->expiresAt->getTimestamp(), $pair->expiresIn]);
            self::assertSame($ends, self::claimsOf($pair)['exp']);
        }
    }

    /**
     * The expiry is the one the access token was signed with, read once: a
     * session whose idle deadline comes nearer each time it is read still gets
     * a pair whose expiry is its access token's `exp`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheExpiryIsTheOneTheAccessTokenWasSignedWith(): void
    {
        $session = new class extends Session {
            /** @var int How many times the idle deadline was read. */
            public int $reads = 0;

            /**
             * The stored idle deadline, a minute nearer at each read.
             *
             * @return ?\Carbon\CarbonInterface
             */
            #[\Override]
            public function getIdleExpiresAt(): ?CarbonInterface
            {
                return parent::getIdleExpiresAt()?->subMinutes($this->reads++);
            }
        };

        $session->forceFill([
            ...self::sessionEndingAt($this->now->addMinutes(10), $this->now->addDay()),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '1',
        ])->save();

        self::recordProof($session, ProofKind::FIRST_FACTOR, $this->now, ['pwd']);

        $pair = SessionTokens::pair(self::tokens(), self::admitted(), $session, self::ROTATION_ID, $this->now);

        self::assertGreaterThan(1, $session->reads);
        self::assertSame(self::claimsOf($pair)['exp'], $pair->expiresAt->getTimestamp());
        self::assertSame($this->now->addMinutes(10)->getTimestamp(), $pair->expiresAt->getTimestamp());
    }

    /**
     * A pair for a session its issuer's transaction inserted reads the
     * session's proofs as that transaction sees them, without the shared lock a
     * pair for any other session reads them with on MySQL.
     *
     * @return void
     */
    public function testAPairForAnInsertedSessionReadsItsProofsWithoutALock(): void
    {
        $issue = fn (bool $inserted): \Closure => function () use ($inserted): void {

            $session = (new Session)->forceFill([...self::liveSession(), 'id' => '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70']);

            try {
                SessionTokens::pair(self::tokens(), self::admitted(), $session, self::ROTATION_ID, $this->now, $inserted);
            } catch (\LogicException $exception) {
                self::assertStringContainsString('no counting first factor', $exception->getMessage());
            }
        };

        $current  = self::statementsOn('mysql', $issue(false));
        $inserted = self::statementsOn('mysql', $issue(true));

        self::assertCount(1, $current);
        self::assertCount(1, $inserted);
        self::assertStringEndsWith(' lock in share mode', $current[0]);
        self::assertStringEndsNotWith(' lock in share mode', $inserted[0]);
    }

    /**
     * A stored live session with a first-factor proof, ending at the deadlines
     * given (90 and 180 days by default).
     *
     * @param  ?\Carbon\CarbonImmutable  $idle
     * @param  ?\Carbon\CarbonImmutable  $absolute
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function storedSession(?CarbonImmutable $idle = null, ?CarbonImmutable $absolute = null): Session
    {
        $session = new Session;

        $session->forceFill([
            ...self::sessionEndingAt($idle ?? $this->now->addDays(90), $absolute ?? $this->now->addDays(180)),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '1',
        ])->save();

        self::recordProof($session, ProofKind::FIRST_FACTOR, $this->now, ['pwd']);

        return $session;
    }

    /**
     * The claims of the pair's access token.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenPair  $pair
     * @return array<string, mixed>
     */
    private static function claimsOf(TokenPair $pair): array
    {
        $claims = self::tokens()->parse($pair->accessToken->reveal(), TokenType::ACCESS);

        self::assertIsArray($claims);

        return $claims;
    }

    /**
     * The token service under test: a 15-minute access lifetime.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private static function tokens(): JwtTokenService
    {
        return new JwtTokenService(
            JwtKeyring::fromKeyMap(['test-kid' => self::SECRET], 'test-kid', 'HS256'),
            'api',
            new TokenLifetimes(15, 60 * 24 * 30, 60 * 24 * 180, 30),
            30,
            'https://issuer.example.test',
            'https://api.example.test',
        );
    }

    /**
     * What was admitted: the identity `identity-7` acting as the principal
     * `principal-3`, in no tenant.
     *
     * @return \SineMacula\Laravel\Authentication\Admission\Admitted
     */
    private static function admitted(): Admitted
    {
        $identity  = \Mockery::mock(Identity::class);
        $principal = \Mockery::mock(Principal::class);

        $identity->shouldReceive('getAuthIdentifier')->andReturn('identity-7');
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('principal-3');
        $principal->shouldReceive('getTenant')->andReturnNull();

        return new Admitted($identity, $principal, null);
    }
}
