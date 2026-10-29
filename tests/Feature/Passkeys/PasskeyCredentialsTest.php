<?php

declare(strict_types = 1);

namespace Tests\Feature\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyCredentials;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySummary;
use SineMacula\Laravel\Authentication\Passkeys\RelyingParty;
use Tests\Concerns\InteractsWithFoldingCollations;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Passkeys\VirtualAuthenticator;
use Tests\TestCase;
use Webauthn\CredentialRecord;

/**
 * Feature tests for the passkey store: what a registration stores, the
 * compare-and-set a verified use is written with, the library's record a stored
 * passkey becomes, and the exact owner listing and removal hold to whatever the
 * collation counts as equal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyCredentials::class)]
final class PasskeyCredentialsTest extends TestCase
{
    use InteractsWithFoldingCollations, InteractsWithPasskeys, InteractsWithSessions;

    /** @var string The key of an identity keyed by name. */
    private const string NAMED = 'alice';

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

        $this->createSessionTables();
    }

    /**
     * Drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A registration stores the backup and verification flags as the
     * authenticator reported them, and hands back the stored passkey as a saved
     * model in step with its row.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationStoresTheFlagsAndHandsBackTheSavedPasskey(): void
    {
        $this->authenticator()->backupEligible = false;
        $this->authenticator()->backedUp       = false;

        $this->registerPasskey($this->seedIdentity());

        $stored = Passkey::query()->sole();

        self::assertSame([false, false, true], [$stored->backup_eligible, $stored->backup_state, $stored->uv_initialized]);

        $record = PasskeyCredentials::record($stored);

        $record->publicKeyCredentialId = 'another credential';

        $passkey = PasskeyCredentials::register($this->rp(), $this->seedIdentity('grace@example.test'), $record, null, $this->now);

        self::assertNotNull($passkey);
        self::assertTrue($passkey->exists);
        self::assertFalse($passkey->isDirty());
        self::assertSame(2, Passkey::query()->count());
    }

    /**
     * A use read against a count that has since moved is not written: the
     * passkey keeps the count the other use wrote, and the model the use read
     * keeps what it read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAUseReadAgainstAStaleCountIsNotWritten(): void
    {
        $this->registerPasskey($this->seedIdentity());

        $read = Passkey::query()->sole();

        DB::table('passkeys')->update(['sign_count' => 5]);

        self::assertFalse(PasskeyCredentials::use($read, self::verified($read, 6), $this->now));
        self::assertSame([5, null], [Passkey::query()->sole()->sign_count, Passkey::query()->sole()->last_used_at]);
        self::assertSame([0, null], [$read->sign_count, $read->last_used_at]);
    }

    /**
     * A use read against a count above 0 that has since moved is not written
     * whatever count it presents, 0 included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAUseReadAgainstAMovedCountAboveZeroIsNotWritten(): void
    {
        $this->registerPasskey($this->seedIdentity());

        DB::table('passkeys')->update(['sign_count' => 1]);

        $read = Passkey::query()->sole();

        DB::table('passkeys')->update(['sign_count' => 5]);

        self::assertFalse(PasskeyCredentials::use($read, self::verified($read, 0), $this->now));
        self::assertSame(5, Passkey::query()->sole()->sign_count);
    }

    /**
     * A use that moves the count is written, with the backup state and the last
     * use, and mirrored on the model, which stays in step with its row.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAUseThatMovesTheCountIsWrittenAndMirrored(): void
    {
        $this->registerPasskey($this->seedIdentity());

        $read = Passkey::query()->sole();

        self::assertTrue(PasskeyCredentials::use($read, self::verified($read, 3, backedUp: false), $this->now));
        self::assertSame([3, false, true], [$read->sign_count, $read->backup_state, $read->uv_initialized]);
        self::assertTrue($read->last_used_at?->equalTo($this->now));
        self::assertFalse($read->isDirty());

        $stored = Passkey::query()->sole();

        self::assertSame([3, false, true], [$stored->sign_count, $stored->backup_state, $stored->uv_initialized]);
        self::assertTrue($stored->last_used_at?->equalTo($this->now));
    }

    /**
     * A use writes only what a use changes: a name changed since the passkey
     * was read is kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAUseWritesOnlyWhatAUseChanges(): void
    {
        $this->registerPasskey($this->seedIdentity());

        $read = Passkey::query()->sole();

        DB::table('passkeys')->update(['name' => 'Renamed']);

        self::assertTrue(PasskeyCredentials::use($read, self::verified($read, 1), $this->now));
        self::assertSame('Renamed', Passkey::query()->sole()->name);
    }

    /**
     * A count of 0 against a stored 0 is accepted when the update reports no
     * row, as MySQL reports a second use within the same second: there is no
     * count to race for. A count above 0 is not. SQLite is made to report it by
     * a trigger that leaves every update of a passkey undone; MySQL needs none,
     * and `PasskeySignInTest` signs in twice within a second there.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAZeroCountAgainstAZeroIsAcceptedWhenTheUpdateReportsNoRow(): void
    {
        if (DB::connection()->getDriverName() !== 'sqlite') {
            self::markTestSkipped('The trigger that leaves an update undone is written for SQLite.');
        }

        $this->registerPasskey($this->seedIdentity());

        $read = Passkey::query()->sole();

        DB::unprepared('CREATE TRIGGER passkeys_unchanged BEFORE UPDATE ON passkeys BEGIN SELECT RAISE(IGNORE); END');

        self::assertTrue(PasskeyCredentials::use($read, self::verified($read, 0), $this->now));
        self::assertFalse(PasskeyCredentials::use($read, self::verified($read, 1), $this->now));
    }

    /**
     * A passkey removed after it was read records no use, whatever the count:
     * the sign-in that read it is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovedPasskeyRecordsNoUse(): void
    {
        $this->registerPasskey($this->seedIdentity());

        $read = Passkey::query()->sole();

        DB::table('passkeys')->delete();

        self::assertFalse(PasskeyCredentials::use($read, self::verified($read, 0), $this->now));
        self::assertFalse(PasskeyCredentials::use($read, self::verified($read, 1), $this->now));
    }

    /**
     * A stored passkey becomes the library's record of it: its raw id, public
     * key and user handle decoded, its transports, count and flags, recorded as
     * unattested, with no AAGUID read as the nil one and a stored one kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStoredPasskeyBecomesTheLibrarysRecord(): void
    {
        $this->registerPasskey($this->seedIdentity());

        $passkey = Passkey::query()->sole();
        $record  = PasskeyCredentials::record($passkey);

        self::assertSame(VirtualAuthenticator::decode($this->authenticator()->lastCredentialId()), $record->publicKeyCredentialId);
        self::assertSame(VirtualAuthenticator::decode($passkey->public_key), $record->credentialPublicKey);
        self::assertSame(VirtualAuthenticator::decode($passkey->user_handle), $record->userHandle);
        self::assertSame(['public-key', ['internal', 'hybrid'], 'none', 0], [$record->type, $record->transports, $record->attestationType, $record->counter]);
        self::assertSame([true, true, true], [$record->backupEligible, $record->backupStatus, $record->uvInitialized]);
        self::assertSame('00000000-0000-0000-0000-000000000000', $record->aaguid->toRfc4122());

        $passkey->aaguid = 'adce0002-35bc-c60a-648b-0b25f1f05503';

        self::assertSame('adce0002-35bc-c60a-648b-0b25f1f05503', PasskeyCredentials::record($passkey)->aaguid->toRfc4122());
    }

    /**
     * `PasskeyCredentials` is a static utility; instantiation is disallowed via
     * the private constructor. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(PasskeyCredentials::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(PasskeyCredentials::class, $instance);
    }

    /**
     * With the owner columns under a collation that counts distinct keys as
     * equal, an identity whose key differs from the owner's only in case or
     * accent is offered none of the owner's passkeys to exclude from a
     * registration or to answer a factor ceremony with, lists none, and removes
     * none, which is left with nothing reported; the owner still lists and
     * removes it.
     *
     * @param  string  $folded
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFoldedKeys')]
    public function testAnotherKeyTheCollationCountsAsEqualHoldsNoPasskeys(string $folded): void
    {
        self::foldColumns('passkeys', ['authenticatable_type', 'authenticatable_id']);

        $owner   = self::namedIdentity(self::NAMED);
        $passkey = $this->registerPasskey($owner);
        $other   = self::namedIdentity($folded);

        self::assertColumnFolds('passkeys', 'authenticatable_id', $folded);

        Event::fake([PasskeyRemoved::class]);

        $passkeys = Auth::passkeys('api');

        self::assertSame([], $passkeys->passkeys($other));
        self::assertSame([], $passkeys->registrationOptions($other, self::USER_NAME)->options['excludeCredentials']);
        self::assertSame([], $passkeys->factorOptions($other)->options['allowCredentials']);
        self::assertFalse($passkeys->remove($other, $passkey->id));
        self::assertSame(1, DB::table('passkeys')->where('id', $passkey->id)->count());

        Event::assertNotDispatched(PasskeyRemoved::class);

        self::assertSame([$passkey->id], array_map(static fn (PasskeySummary $summary): string => $summary->id, $passkeys->passkeys($owner)));
        self::assertTrue($passkeys->remove($owner, $passkey->id));
        self::assertSame(0, DB::table('passkeys')->count());
    }

    /**
     * With the relying party column under a collation that counts distinct ids
     * as equal, a passkey recorded for an id that differs from the relying
     * party's only in case is not found for a sign-in, offered to exclude from
     * a registration or to answer a factor ceremony with, listed or removed,
     * and nothing is reported; recorded for the relying party's own id, it is
     * removed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasskeyOfALookAlikeRelyingPartyIsAbsent(): void
    {
        self::foldColumns('passkeys', ['rp_id']);

        $identity = $this->seedIdentity();
        $passkey  = $this->registerPasskey($identity);
        $raw      = PasskeyCredentials::record(Passkey::query()->sole())->publicKeyCredentialId;

        DB::table('passkeys')->update(['rp_id' => strtoupper(self::RP_ID)]);

        self::assertColumnFolds('passkeys', 'rp_id', self::RP_ID);

        Event::fake([PasskeyRemoved::class]);

        $passkeys = Auth::passkeys('api');

        self::assertNull(PasskeyCredentials::find($this->rp(), $raw));
        self::assertSame([], $passkeys->passkeys($identity));
        self::assertSame([], $passkeys->registrationOptions($identity, self::USER_NAME)->options['excludeCredentials']);
        self::assertSame([], $passkeys->factorOptions($identity)->options['allowCredentials']);
        self::assertFalse($passkeys->remove($identity, $passkey->id));
        self::assertSame(1, DB::table('passkeys')->count());

        Event::assertNotDispatched(PasskeyRemoved::class);

        DB::table('passkeys')->update(['rp_id' => self::RP_ID]);

        self::assertSame($passkey->id, PasskeyCredentials::find($this->rp(), $raw)?->id);
        self::assertTrue($passkeys->remove($identity, $passkey->id));
    }

    /**
     * Configure the guards and their relying party.
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

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);
        self::configurePasskeys($config);
    }

    /**
     * The passkey as an assertion verified with the count would leave it.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @param  int  $count
     * @param  bool  $backedUp
     * @return \Webauthn\CredentialRecord
     */
    private static function verified(Passkey $passkey, int $count, bool $backedUp = true): CredentialRecord
    {
        $record = PasskeyCredentials::record($passkey);

        $record->counter       = $count;
        $record->backupStatus  = $backedUp;
        $record->uvInitialized = true;

        return $record;
    }

    /**
     * The `api` guard's relying party.
     *
     * @return \SineMacula\Laravel\Authentication\Passkeys\RelyingParty
     */
    private function rp(): RelyingParty
    {
        return RelyingParty::forGuard('api', app(ConfigRepository::class));
    }
}
