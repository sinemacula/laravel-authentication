<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passwords\PasswordChanges;
use SineMacula\Laravel\Authentication\Passwords\PasswordResult;
use Tests\Concerns\InteractsWithPasswords;
use Tests\Fixtures\Proofs\UndescribedFirstFactor;

/**
 * Query-budget contracts for changing and establishing a password from a
 * session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasswordChanges::class)]
final class PasswordChangesQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithPasswords;

    /** @var string A new password the default policy accepts. */
    private const string NEW_PASSWORD = 'a brand new passphrase';

    /**
     * Freeze the clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(CarbonImmutable::instance($this->now));

        self::createPasswordTables();
    }

    /**
     * Drop the tables and release the clock.
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
     * A change that keeps one of two sessions has a fixed budget.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeHasAFixedBudget(): void
    {
        self::seedPasswordIdentity();

        $kept = $this->signInWithPassword()->record;

        $this->signInWithPassword();

        DB::table('rate_limits')->delete();

        $passwords = Auth::passwords('web');

        self::assertSame(
            1,
            $this->assertQueryBudget(6, 10, static fn (): PasswordResult => $passwords->change($kept, self::PASSWORD, self::NEW_PASSWORD, self::requestClient()))->revoked,
        );
    }

    /**
     * An establishment has a fixed budget and takes no counter.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEstablishmentHasAFixedBudget(): void
    {
        $identity = self::seedPasswordIdentity(attributes: ['password' => null]);
        $kept     = $this->sessions('web')->start(UndescribedFirstFactor::of($identity), null, 'password', self::requestContext())->session?->record;

        $this->sessions('admin')->start(UndescribedFirstFactor::of($identity), null, 'password', self::requestContext());

        self::assertNotNull($kept);

        $passwords = Auth::passwords('web');

        self::assertSame(1, $this->assertQueryBudget(8, 4, static fn (): PasswordResult => $passwords->establish($kept, self::NEW_PASSWORD, self::requestClient()))->revoked);
    }

    /**
     * A wrong current password reads the session and its owner and takes its
     * two sign-in counters, and nothing more.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWrongPasswordWritesOnlyItsCounters(): void
    {
        self::seedPasswordIdentity();

        $session = $this->signInWithPassword()->record;

        DB::table('rate_limits')->delete();

        $passwords = Auth::passwords('web');

        $change = static fn (): PasswordResult => $passwords->change($session, 'not the password', self::NEW_PASSWORD, self::requestClient());

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->assertQueryBudget(2, 4, $change)->reason);
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
}
