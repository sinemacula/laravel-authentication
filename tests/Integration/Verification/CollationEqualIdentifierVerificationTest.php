<?php

declare(strict_types = 1);

namespace Tests\Integration\Verification;

use Carbon\Carbon;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Events\IdentifierVerified;
use SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;
use Tests\Concerns\InteractsWithVerifiableIdentities;
use Tests\TestCase;

/**
 * Integration tests for an address replaced, after the identity was read, by a
 * distinct one its column's collation counts as equal: MySQL's default
 * `utf8mb4_unicode_ci`, a PostgreSQL ICU collation that ignores case and
 * accents, and SQLite's `NOCASE`. A proof of the old address must not verify
 * the new one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierVerifier::class)]
#[CoversTrait(ProvidesIdentifierVerification::class)]
final class CollationEqualIdentifierVerificationTest extends TestCase
{
    use InteractsWithVerifiableIdentities;

    /** @var string The address the identity was read with, and proved. */
    private const string PROVEN = 'ben@example.com';

    /**
     * Create the identities table with the address under a collation that
     * counts the variants as equal, and freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::parse('2027-03-01 08:30:00'));

        $collation = match (DB::connection()->getDriverName()) {
            'mysql' => 'utf8mb4_unicode_ci',
            'pgsql' => self::createPostgresCollation(),
            default => 'NOCASE',
        };

        Schema::create('verifiable_identities', static function (Blueprint $blueprint) use ($collation): void {
            $blueprint->increments('id');
            $blueprint->string('email')->collation($collation)->nullable();
            $blueprint->dateTime('email_verified_at', 0)->nullable();
            $blueprint->string('phone')->nullable();
            $blueprint->dateTime('phone_verified_at', 0)->nullable();
            $blueprint->string('password');
            $blueprint->datetimes(0);
        });
    }

    /**
     * Drop the identities table and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('verifiable_identities');
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Distinct addresses the collation counts as equal to the proven one.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideCollationEqualAddresses(): iterable
    {
        yield from [
            'another case'   => ['Ben@Example.com'],
            'another accent' => ["b\u{E9}n@example.com"],
        ];
    }

    /**
     * Marking the proven address refuses a row that now holds a variant, and
     * records nothing.
     *
     * @param  string  $variant
     * @return void
     */
    #[DataProvider('provideCollationEqualAddresses')]
    public function testMarkingRefusesACollationEqualReplacement(string $variant): void
    {
        $identity = self::seedVerifiableIdentity(self::PROVEN);

        $this->replaceAddressWith($variant);

        self::assertFalse($identity->markIdentifierAsVerified('email', self::PROVEN));
        self::assertNull(DB::table('verifiable_identities')->value('email_verified_at'));
        self::assertNull($identity->getAttribute('email_verified_at'));
    }

    /**
     * Verifying the address the identity was read with reports a mismatch once
     * the row holds a variant, and neither records the verification nor reports
     * it.
     *
     * @param  string  $variant
     * @return void
     */
    #[DataProvider('provideCollationEqualAddresses')]
    public function testVerifyingRefusesACollationEqualReplacement(string $variant): void
    {
        Event::fake([IdentifierVerified::class]);

        $identity = self::seedVerifiableIdentity(self::PROVEN);

        $this->replaceAddressWith($variant);

        self::assertSame(IdentifierVerification::MISMATCH, app(IdentifierVerifier::class)->verify('api', $identity, 'email', self::PROVEN));
        self::assertNull(DB::table('verifiable_identities')->value('email_verified_at'));

        Event::assertNotDispatched(IdentifierVerified::class);
    }

    /**
     * Replace the stored address with the variant behind the model's back, and
     * check the column's collation still finds the row by the proven address,
     * which is what made a collation-bound condition match it.
     *
     * @param  string  $variant
     * @return void
     */
    private function replaceAddressWith(string $variant): void
    {
        if (DB::connection()->getDriverName() === 'sqlite' && !mb_check_encoding($variant, 'ASCII')) {
            self::markTestSkipped('SQLite\'s NOCASE folds ASCII case only.');
        }

        DB::table('verifiable_identities')->update(['email' => $variant]);

        self::assertSame($variant, DB::table('verifiable_identities')->value('email'));
        self::assertSame(1, DB::table('verifiable_identities')->where('email', self::PROVEN)->count());
    }

    /**
     * Create a PostgreSQL collation that compares text ignoring case and
     * accents, and return its name.
     *
     * @return string
     */
    private static function createPostgresCollation(): string
    {
        DB::statement('create collation if not exists accent_insensitive (provider = icu, locale = \'und-u-ks-level1\', deterministic = false)');

        return 'accent_insensitive';
    }
}
