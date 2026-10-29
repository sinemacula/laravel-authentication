<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\CodeRequest;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passwords\PasswordService;
use SineMacula\Laravel\Authentication\Passwords\ResetRequests;
use SineMacula\Laravel\Authentication\Passwords\ResetResult;
use SineMacula\Laravel\Authentication\Passwords\ResetSubmissions;
use SineMacula\Laravel\Authentication\Testing\FakePasswordResetLinkSender;
use Tests\Concerns\InteractsWithPasswords;

/**
 * Query-budget contracts for password reset: a request writes its limits and
 * the token and reads no identity; a reset counts its submission, reads the
 * identity and the token once each, spends the token, writes the password and
 * the cutoff, revokes each device with one statement after one read of them,
 * ends the pending sign-ins, and gives its slots back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResetRequests::class)]
#[CoversClass(ResetSubmissions::class)]
final class PasswordResetQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithPasswords;

    /** @var string The seeded identity's email address. */
    private const string EMAIL = 'ada@example.test';

    /** @var list<string> Every statement run since the list was last cleared. */
    private array $statements = [];

    /** @var \SineMacula\Laravel\Authentication\Testing\FakePasswordResetLinkSender The link sender. */
    private FakePasswordResetLinkSender $links;

    /**
     * Freeze the immutable clock with the performance clock, create the table,
     * fake the sender and record every statement.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(CarbonImmutable::instance($this->now));

        self::createPasswordTables();

        $this->links = FakePasswordResetLinkSender::fake(app());

        DB::listen(function (QueryExecuted $query): void {
            $this->statements[] = $query->sql;
        });
    }

    /**
     * Drop the table and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropPasswordTables();

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A first request writes four limiter statements and the token's failed
     * update and its insert, and reads nothing; a request after the cooldown in
     * the same window writes the two counters and replaces the token in one
     * update. Neither touches an identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestWritesItsLimitsAndTheTokenAndReadsNoIdentity(): void
    {
        self::seedPasswordIdentity(self::EMAIL);

        $passwords = $this->passwords();

        $this->statements = [];

        self::assertTrue($this->assertQueryBudget(0, 6, static fn (): CodeRequest => $passwords->sendResetLink(['email' => self::EMAIL]))->isSent());

        CarbonImmutable::setTestNow(CarbonImmutable::instance($this->now)->addSeconds(60));

        self::assertTrue($this->assertQueryBudget(0, 3, static fn (): CodeRequest => $passwords->sendResetLink(['email' => self::EMAIL]))->isSent());
        self::assertSame([], array_filter($this->statements, static fn (string $sql): bool => str_contains($sql, 'password_identities')));
    }

    /**
     * A reset of an identity with two devices reads the identity, its row under
     * the lock taken before the token, the token and the devices once each, and
     * the row it updated once more, and writes the submission's limits, the
     * token's use, the password, one `DELETE` of every other reset link and
     * code, the cutoff, one revocation per device, the pending sign-ins' end,
     * and the slots it gives back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetSpendsTheTokenWithThePasswordAndTheRevocations(): void
    {
        self::seedPasswordIdentity(self::EMAIL);

        $this->signInWithPassword('web', self::EMAIL);
        $this->signInWithPassword('admin', self::EMAIL);

        $passwords = $this->passwords();

        $passwords->sendResetLink(['email' => self::EMAIL]);
        app()->terminate();

        $token = (string) $this->links->lastTokenFor(self::EMAIL);

        $input  = ['email' => self::EMAIL, 'token' => $token, 'password' => 'a brand new passphrase'];
        $result = $this->assertQueryBudget(5, 13, static fn (): ResetResult => $passwords->reset($input));

        self::assertSame(2, $result->revoked);
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

        self::configurePasswordGuards($app->make(ConfigRepository::class));
    }

    /**
     * The `web` guard's password service, on a guard resolved for a fresh
     * request.
     *
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordService
     */
    private function passwords(): PasswordService
    {
        $this->freshGuard('web');

        return Auth::passwords('web');
    }
}
