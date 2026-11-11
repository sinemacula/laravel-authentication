<?php

declare(strict_types = 1);

namespace Tests\Feature\Proofs;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationClaims;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\PretendsStorageEngines;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainSessionFixture;

/**
 * Feature tests of the `auth_time` and `amr` claims a session's access token
 * carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationClaims::class)]
final class AuthenticationClaimsTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessions, PretendsStorageEngines;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks and create the tables.
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

        $this->createSessionTables();
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
     * A session's claims are its newest counting proof's time and the values of
     * all its counting proofs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionsClaimsAreItsNewestTimeAndItsValues(): void
    {
        $this->seedIdentity();

        $record = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session?->record;

        self::assertNotNull($record);

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinute(), ['otp'], new Evaluation(true, true));

        foreach ([AuthenticationClaims::forSession($record), AuthenticationClaims::forSession($record, false)] as $summary) {
            self::assertSame($this->now->addMinute()->getTimestamp(), $summary->authenticatedAt->getTimestamp());
            self::assertSame(['pwd', 'otp', 'mfa'], $summary->methods);
        }
    }

    /**
     * A session whose proofs hold no counting first factor has no claims.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionWithoutACountingFirstFactorHasNoClaims(): void
    {
        $this->seedIdentity();

        $record = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session?->record;

        self::assertNotNull($record);

        DB::table('authentication_proofs')->update(['voided_at' => $this->now]);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The session records no counting first factor, so no access token can say when or how it authenticated.');

        AuthenticationClaims::forSession($record);
    }

    /**
     * The claims are read with a shared lock on MySQL and MariaDB unless asked
     * otherwise.
     *
     * @param  string  $driver
     * @return void
     */
    #[DataProvider('provideStorageEngines')]
    public function testTheClaimsAreReadCurrentUnlessAskedOtherwise(string $driver): void
    {
        $session = new PlainSessionFixture('0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70');

        $current = self::statementsOn($driver, static fn () => self::assertHasNoClaims(static fn () => AuthenticationClaims::forSession($session)));
        $plain   = self::statementsOn($driver, static fn () => self::assertHasNoClaims(static fn () => AuthenticationClaims::forSession($session, false)));

        self::assertCount(1, $current);
        self::assertCount(1, $plain);
        self::assertSame(in_array($driver, ['mysql', 'mariadb'], true), str_ends_with($current[0], ' lock in share mode'));
        self::assertStringEndsNotWith(' lock in share mode', $plain[0]);
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
     * Assert the read finds no counting first factor.
     *
     * @param  \Closure(): mixed  $read
     * @return void
     */
    private static function assertHasNoClaims(\Closure $read): void
    {
        try {
            $read();
        } catch (\LogicException $exception) {
            self::assertStringContainsString('no counting first factor', $exception->getMessage());

            return;
        }

        self::fail('A session with no proofs had claims.');
    }
}
