<?php

declare(strict_types = 1);

namespace Tests\Integration\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passwords\Enums\ResetStatus;
use SineMacula\Laravel\Authentication\Passwords\ResetRecipient;
use SineMacula\Laravel\Authentication\Passwords\ResetSubmissions;
use SineMacula\Laravel\Authentication\Passwords\SendPasswordReset;
use SineMacula\Laravel\Authentication\Testing\FakePasswordResetLinkSender;
use Tests\Concerns\InteractsWithApplicationGrants;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithPasswords;
use Tests\Fixtures\Sessions\GrantedApplicationPolicy;
use Tests\Integration\Fixtures\PasswordIdentity;
use Tests\TestCase;

/**
 * Proves every read that decides a password reset is from the write connection:
 * an identity registered moments ago, and a link issued for it, which only the
 * primary holds yet, are found while the replica lags behind, by the queued job
 * that delivers the link and by the reset that spends it; and an application
 * policy of the application's own decides from the rows the primary holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SendPasswordReset::class)]
#[CoversClass(ResetRecipient::class)]
#[CoversClass(ResetSubmissions::class)]
final class ReplicaPasswordResetsTest extends TestCase
{
    use InteractsWithApplicationGrants, InteractsWithLaggingReplica, InteractsWithPasswords;

    /** @var string The new password the reset sets. */
    private const string NEW_PASSWORD = 'a brand new passphrase';

    /** @var \SineMacula\Laravel\Authentication\Testing\FakePasswordResetLinkSender The link sender. */
    private FakePasswordResetLinkSender $links;

    /**
     * Freeze the clock, create the identities table on the primary and the
     * replica, where no identity is copied, and fake the link sender.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::freezeClock(CarbonImmutable::parse('2026-10-29 09:30:00'));
        self::createPasswordTables(self::PRIMARY_CONNECTION);
        self::createPasswordTables(self::REPLICA_CONNECTION);

        $this->links = FakePasswordResetLinkSender::fake($this->app);
    }

    /**
     * Release the clock and remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::freezeClock(null);

        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * A link for an identity only the primary holds is delivered to it, and
     * resets its password.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkIsDeliveredAndSpentOnThePrimary(): void
    {
        self::seedPasswordIdentity();

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('password_identities')->count());
        self::assertTrue(Auth::passwords('web')->sendResetLink(['email' => 'ada@example.test'])->isSent());

        app()->terminate();

        $token = $this->links->lastTokenFor('ada@example.test');

        self::assertIsString($token);
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('one_time_codes')->count());
        self::assertSame(ResetStatus::RESET, Auth::passwords('web')->reset(['email' => 'ada@example.test', 'token' => $token, 'password' => self::NEW_PASSWORD])->status);
        $stored = PasswordIdentity::query()->useWritePdo()->value('password');

        self::assertIsString($stored);
        self::assertTrue(app(Hasher::class)->check(self::NEW_PASSWORD, $stored));
    }

    /**
     * An application policy of the application's own is asked on the primary
     * whether the identity may reset its password with the identifier: a link
     * is delivered on a verification only the primary holds, and none once the
     * primary withdraws it while the replica still holds it, past the resend
     * cooldown.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheApplicationPolicyIsAskedOnThePrimary(): void
    {
        $this->bindGrantedApplicationPolicy();

        $verification = $this->verify(self::seedPasswordIdentity());

        self::assertTrue(Auth::passwords('web')->sendResetLink(['email' => 'ada@example.test'])->isSent());

        app()->terminate();

        self::assertSame(1, $this->links->count());

        $this->withdrawOnThePrimary(GrantedApplicationPolicy::VERIFICATIONS, $verification);

        self::freezeClock(CarbonImmutable::parse('2026-10-29 10:30:00'));
        self::assertTrue(Auth::passwords('web')->sendResetLink(['email' => 'ada@example.test'])->isSent());

        app()->terminate();

        self::assertSame(1, $this->links->count());
    }

    /**
     * Create the package tables, the codes among them, on the primary and the
     * replica.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica('2026_04_06_000003_create_one_time_codes_table.php');
    }

    /**
     * Configure the password guards over a lagging read/write split.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        self::configurePasswordGuards($config);

        $this->configureLaggingReplica($config);
    }
}
