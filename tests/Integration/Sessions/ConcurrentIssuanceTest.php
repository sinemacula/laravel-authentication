<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationClaims;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\SessionRecords\IssuanceGuard;
use SineMacula\Laravel\Authentication\Sessions\ProofIssuance;
use SineMacula\Laravel\Authentication\Sessions\SessionSwitch;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithIsolationLevels;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Races every issuer of a session's access token against a step-up of that
 * session, on two connections to one database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IssuanceGuard::class)]
#[CoversClass(JwtTokenService::class)]
#[CoversClass(AuthenticationClaims::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(SessionSwitch::class)]
#[CoversClass(ProofIssuance::class)]
final class ConcurrentIssuanceTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithIsolationLevels, InteractsWithProofs, InteractsWithSessions;

    /** @var string The second connection to the test database, the step-up's. */
    private const string STEP_UP_CONNECTION = 'stepping_up';

    /** @var \Carbon\CarbonImmutable When the session signed in. */
    private CarbonImmutable $signedInAt;

    /** @var \Carbon\CarbonImmutable When the session was stepped up, and every issuer issues. */
    private CarbonImmutable $steppedUpAt;

    /**
     * Skip where two connections cannot share the database, add the second
     * connection, freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() === 'sqlite') {
            self::markTestSkipped('Two connections need a shared database server.');
        }

        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::STEP_UP_CONNECTION, $config->get('database.connections.' . $config->string('database.default')));

        $this->signedInAt  = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);
        $this->steppedUpAt = $this->signedInAt->addHour();

        $this->freezeAt($this->signedInAt);

        $this->createSessionTables();
    }

    /**
     * Close the second connection, drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::disconnect(self::STEP_UP_CONNECTION);

        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * Rows of `[issuer, isolation level]`.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideIssuersAndIsolationLevels(): iterable
    {
        foreach (['refresh', 'switch', 'step-up', 'reauthentication', 'external reauthentication', 'direct issue'] as $issuer) {
            foreach (self::provideIsolationLevels() as $name => [$level]) {
                yield "{$issuer} at {$name}" => [$issuer, $level];
            }
        }
    }

    /**
     * An issuer that read before a step-up committed never issues an older
     * token.
     *
     * @param  string  $issuer
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIssuersAndIsolationLevels')]
    public function testAnIssuerThatReadBeforeAStepUpCommittedNeverIssuesAnOlderToken(string $issuer, string $level): void
    {
        $identity = $this->seedIdentity();
        $session  = $issuer === 'external reauthentication'
            ? $this->sessions()->signInExternally($this->linkedResult($identity, subject: 'subject-1', authenticatedAt: $this->signedInAt), self::requestContext())->session
            : $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        $this->freezeAt($this->steppedUpAt);

        $issue = fn (): string => $this->issue($issuer, $identity, $session);

        self::beginTransactionAt($level);

        self::assertSame(1, DB::table('authentication_proofs')->count());

        $this->stepUpOnTheOtherConnection($identity, $session);

        if (self::readsASnapshot($level)) {
            self::assertSame('40001', self::serializationFailure($issue));

            self::beginTransactionAt($level);
        }

        $token = $issue();

        DB::commit();

        $claims = Auth::manager()->jwt('api')->parse($token, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame($this->steppedUpAt->getTimestamp(), $claims['auth_time']);
        self::assertIsArray($claims['amr']);
        self::assertContains('hwk', $claims['amr']);
        self::assertContains('mfa', $claims['amr']);
    }

    /**
     * Register the guards.
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
     * Issue an access token for the session through the named issuer.
     *
     * @param  string  $issuer
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return string
     *
     * @throws \Throwable
     */
    private function issue(string $issuer, IntegrationIdentity $identity, SignedInSession $session): string
    {
        $key      = $session->record->getKey();
        $refresh  = $session->tokens->refreshToken?->reveal() ?? '';
        $sessions = $this->sessions();
        $stepUp   = self::adapterProof($identity, 'api', $key, methods: ['otp'], evaluation: new Evaluation(true, false));
        $external = new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: $this->steppedUpAt);

        $issuers = [
            'refresh' => static fn (): ?Secret => $sessions->refresh(
                PresentedRefreshToken::fromBody($refresh),
                self::requestClient(),
            )->session?->tokens->accessToken,
            'switch' => static fn (): ?Secret => $sessions->switchTo(
                PresentedRefreshToken::fromBody($refresh),
                SwitchTarget::principal($identity),
                self::requestClient(),
            )->session?->tokens->accessToken,
            'step-up'          => static fn (): ?Secret => $sessions->stepUp($stepUp, self::requestClient())->accessToken,
            'reauthentication' => static fn (): ?Secret => $sessions->reauthenticate(
                $session->record,
                'password',
                self::credentials(),
                self::requestClient(),
            )->accessToken,
            'external reauthentication' => static fn (): ?Secret => $sessions->reauthenticateExternally($key, $external, self::requestClient())->accessToken,
            'direct issue'              => static fn (): Secret => Auth::manager()->jwt('api')->issueAccessToken($identity, $identity, null, $session->record),
        ];

        $token = $issuers[$issuer]();

        self::assertNotNull($token, "The {$issuer} issued no token.");

        return $token->reveal();
    }

    /**
     * Step the session up with a hardware key on the second connection.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return void
     *
     * @throws \Throwable
     */
    private function stepUpOnTheOtherConnection(IntegrationIdentity $identity, SignedInSession $session): void
    {
        $manager = app(DatabaseManager::class);
        $default = $manager->getDefaultConnection();

        $manager->setDefaultConnection(self::STEP_UP_CONNECTION);

        try {
            $proof = self::adapterProof($identity, 'api', $session->record->getKey(), methods: ['hwk'], evaluation: new Evaluation(true, true));

            self::assertTrue($this->sessions()->stepUp($proof, self::requestClient())->isIssued());
        } finally {
            $manager->setDefaultConnection($default);
        }
    }

    /**
     * Freeze every clock at the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function freezeAt(CarbonImmutable $time): void
    {
        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }
}
