<?php

declare(strict_types = 1);

namespace Tests\Integration\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Codes\CodeSignIn;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Codes\SendOneTimeCode;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification;
use Tests\Concerns\InteractsWithCodeIdentities;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Integration\Fixtures\CodeIdentity;
use Tests\TestCase;

/**
 * Proves every read that decides a one-time code is from the write connection:
 * a code issued moments ago, and an identity's number verified or changed
 * moments ago, which only the primary holds yet, decide the sign-in, the
 * verification and the delivery while the replica lags behind.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OneTimeCodes::class)]
#[CoversClass(CodeSignIn::class)]
#[CoversClass(CodeService::class)]
#[CoversClass(SendOneTimeCode::class)]
final class ReplicaOneTimeCodesTest extends TestCase
{
    use InteractsWithCodeIdentities, InteractsWithLaggingReplica;

    /** @var string The code the engine issues first. */
    private const string CODE = '135790';

    /** @var \SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender The sender the job delivers through. */
    private FakeOneTimeCodeSender $sender;

    /** @var \Tests\Integration\Fixtures\CodeIdentity The identity, as both copies hold it: its number unverified. */
    private CodeIdentity $identity;

    /**
     * Freeze the clock, create the identities table on the primary and the
     * replica with one unverified identity both hold, issue known codes and
     * fake the sender.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createOnPrimaryAndReplica('code_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('phone')->nullable()->unique();
            $blueprint->dateTime('phone_verified_at', 0)->nullable();
            $blueprint->string('email')->nullable()->unique();
            $blueprint->dateTime('email_verified_at', 0)->nullable();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->datetimes(0);
        });

        $this->identity = self::seedCodeIdentity(verified: false);

        $this->copyRowToReplica('code_identities', $this->identity->getKey());

        self::issueCodes([self::CODE, '246802']);

        $this->sender = FakeOneTimeCodeSender::fake($this->app);
    }

    /**
     * Release the clock and remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * A code only the primary holds, for a number only the primary records as
     * verified, signs in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeAndAVerificationTheReplicaHasNotSeenSignIn(): void
    {
        $this->verifyOnThePrimary();

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('one_time_codes')->count());
        self::assertTrue($this->sessions('mobile')->signIn('phone_code', ['phone' => self::PHONE, 'code' => self::CODE])->isSignedIn());
    }

    /**
     * The delivery job finds a code only the primary holds current, and sends
     * it to a number only the primary records as verified.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDeliveryDecidesOnThePrimary(): void
    {
        $binding = CodeBinding::signIn('mobile', 'phone', self::PHONE);
        $issued  = app(OneTimeCodes::class)->issue($binding, CarbonImmutable::now());

        self::assertInstanceOf(IssuedCode::class, $issued);

        (new SendOneTimeCode($binding, $issued))->handle(app());

        self::assertSame(0, $this->sender->count());

        $this->verifyOnThePrimary();

        (new SendOneTimeCode($binding, $issued))->handle(app());

        self::assertSame(self::CODE, $this->sender->lastCodeFor(self::PHONE));
    }

    /**
     * A verification code for an identity loaded as the guard loads it, from
     * the primary, is bound to the number changed moments ago; the delivery,
     * which reads the identity again, sends it there, and the code verifies
     * that number.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationFollowsTheNumberThePrimaryHolds(): void
    {
        DB::connection(self::PRIMARY_CONNECTION)->table('code_identities')->update(['phone' => '+447700900124']);

        $identity = CodeIdentity::query()->useWritePdo()->findOrFail($this->identity->getKey());

        $this->codeService()->sendVerification($identity, 'phone');

        $binding = CodeBinding::verification('mobile', 'phone', '+447700900124', $identity);
        $issueId = DB::connection(self::PRIMARY_CONNECTION)->table('one_time_codes')->value('issue_id');

        self::assertIsString($issueId);
        self::assertTrue(app(OneTimeCodes::class)->isCurrent($binding, $issueId, CarbonImmutable::now()));

        (new SendOneTimeCode($binding, new IssuedCode(self::CODE, $issueId, CarbonImmutable::now()->addSeconds(600)), $this->identity))->handle(app());

        self::assertSame(self::CODE, $this->sender->lastCodeFor('+447700900124'));
        self::assertSame(IdentifierVerification::VERIFIED, $this->codeService()->verify($identity, 'phone', self::CODE));
    }

    /**
     * Configure the guards over a lagging read/write split.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        self::configureCodeGuards($config);

        $this->configureLaggingReplica($config);
    }

    /**
     * Create the package tables, the codes table among them, on the primary and
     * the replica.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();

        /** @var \Illuminate\Database\DatabaseManager $manager */
        $manager   = app(DatabaseManager::class);
        $migration = require __DIR__ . '/../../../database/migrations/2026_04_06_000003_create_one_time_codes_table.php';

        foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
            $manager->setDefaultConnection($connection);
            $migration->up();
        }

        $manager->setDefaultConnection(self::SPLIT_CONNECTION);
    }

    /**
     * Record the identity's number as verified on the primary only.
     *
     * @return void
     */
    private function verifyOnThePrimary(): void
    {
        DB::connection(self::PRIMARY_CONNECTION)->table('code_identities')->update(['phone_verified_at' => '2026-04-06 11:00:00']);
    }
}
