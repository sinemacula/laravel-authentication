<?php

declare(strict_types = 1);

namespace Tests\Integration\IdentifierChanges;

use Carbon\Carbon;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierChanges;
use Tests\Concerns\InteractsWithChangeableIdentities;
use Tests\TestCase;
use Tests\Unit\Stubs\StubChangeableModel;

/**
 * Integration tests for the default `replaceIdentifier()` of an Eloquent
 * identity: the row read again under a lock, the identifier compared byte for
 * byte, and the replacement written with its verification time in the same
 * transaction, on every engine the suite runs against.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ProvidesIdentifierChanges::class)]
final class ReplaceIdentifierTest extends TestCase
{
    use InteractsWithChangeableIdentities;

    /**
     * Create the identities table and freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::parse('2027-03-01 08:30:00'));

        self::createChangeableIdentitiesTable();
    }

    /**
     * Drop the identities table and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropChangeableIdentitiesTable();
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Replacing reads the row again under a lock and writes the new identifier,
     * its verification time and `updated_at` to the row and the model, all in
     * one transaction; it fires no model event, leaves the model clean, and
     * reports that it replaced the identifier.
     *
     * @return void
     */
    public function testReplacingWritesTheIdentifierAndItsVerificationUnderALock(): void
    {
        $identity   = self::seedChangeable();
        $statements = $this->recordStatements();
        $events     = $this->recordModelEvents();
        $lock       = DB::connection()->getDriverName() === 'sqlite' ? '' : ' for update';

        Carbon::setTestNow(Carbon::parse('2027-03-01 09:00:00'));

        self::assertTrue($identity->replaceIdentifier('email', self::EMAIL, self::NEW_EMAIL));
        self::assertCount(4, $statements());
        self::assertSame('begin', $statements()[0]);
        self::assertStringStartsWith('select', $statements()[1]);
        self::assertStringEndsWith('limit 1' . $lock, $statements()[1]);
        self::assertStringStartsWith('update', $statements()[2]);
        self::assertSame('commit', $statements()[3]);

        $row = (array) DB::table('changeable_identities')->first();

        self::assertSame([self::NEW_EMAIL, '2027-03-01 09:00:00', '2027-03-01 09:00:00'], [$row['email'], $row['email_verified_at'], $row['updated_at']]);
        self::assertSame(self::NEW_EMAIL, $identity->email);
        self::assertSame('2027-03-01 09:00:00', $identity->email_verified_at?->format('Y-m-d H:i:s'));
        self::assertSame('2027-03-01 09:00:00', $identity->updated_at?->format('Y-m-d H:i:s'));
        self::assertTrue($identity->hasVerifiedIdentifier('email'));
        self::assertFalse($identity->isDirty());
        self::assertSame([], $events());
    }

    /**
     * Replacing writes nothing when the row's identifier is not the one given
     * byte for byte (a look-alike the column's collation would match included),
     * whatever the model in memory holds, or when the row is gone.
     *
     * @return void
     */
    public function testReplacingIsConditionalOnTheStoredIdentifier(): void
    {
        $identity = self::seedChangeable();

        self::assertFalse($identity->replaceIdentifier('email', 'someone@example.test', self::NEW_EMAIL));

        DB::table('changeable_identities')->update(['email' => 'ADA@example.test']);

        self::assertFalse($identity->replaceIdentifier('email', self::EMAIL, self::NEW_EMAIL));
        self::assertSame('ADA@example.test', DB::table('changeable_identities')->value('email'));
        self::assertSame(self::EMAIL, $identity->email);

        DB::table('changeable_identities')->delete();

        self::assertFalse($identity->replaceIdentifier('email', 'ADA@example.test', self::NEW_EMAIL));
    }

    /**
     * Without a current identifier, the row's column must hold none, `null` or
     * empty; one that holds an identifier is not replaced.
     *
     * @return void
     */
    public function testNoCurrentIdentifierMatchesOnlyAnEmptyColumn(): void
    {
        $identity = self::seedChangeable(self::EMAIL, null);

        self::assertTrue($identity->replaceIdentifier('phone', null, self::PHONE));
        self::assertSame(self::PHONE, DB::table('changeable_identities')->value('phone'));

        DB::table('changeable_identities')->update(['phone' => '']);

        self::assertTrue($identity->replaceIdentifier('phone', null, self::NEW_PHONE));
        self::assertSame(self::NEW_PHONE, DB::table('changeable_identities')->value('phone'));
        self::assertFalse($identity->replaceIdentifier('phone', null, self::PHONE));
        self::assertSame(self::NEW_PHONE, DB::table('changeable_identities')->value('phone'));
    }

    /**
     * An identifier changed between the decision to replace it and the write is
     * not replaced: the row the replacement reads again no longer holds it.
     *
     * @return void
     */
    public function testIdentifierChangedJustBeforeTheReplacementIsKept(): void
    {
        $identity = self::seedChangeable();

        $ran = false;

        DB::connection()->beforeExecuting(static function (string $query) use (&$ran): void {
            if ($ran || !str_starts_with(strtolower($query), 'select')) {
                return;
            }

            $ran = true;

            DB::connection()->getPdo()->exec('update changeable_identities set email = \'other@example.test\'');
        });

        self::assertFalse($identity->replaceIdentifier('email', self::EMAIL, self::NEW_EMAIL));
        self::assertSame('other@example.test', DB::table('changeable_identities')->value('email'));
    }

    /**
     * A replacement another identity holds violates the unique index: the
     * violation propagates, and the row keeps its identifier.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAUniqueIndexViolationPropagates(): void
    {
        $identity = self::seedChangeable();

        self::seedChangeable(self::NEW_EMAIL);

        try {
            $identity->replaceIdentifier('email', self::EMAIL, self::NEW_EMAIL);
            self::fail('Expected the unique index to refuse the replacement.');
        } catch (UniqueConstraintViolationException) {
            self::assertSame(self::EMAIL, DB::table('changeable_identities')->where('id', $identity->getKey())->value('email'));
            self::assertSame(self::EMAIL, $identity->email);
        }
    }

    /**
     * A model without timestamps gets no `updated_at`, and one that names its
     * verification column differently has that column written.
     *
     * @return void
     */
    public function testTimestampsAndTheVerificationColumnFollowTheModel(): void
    {
        DB::table('changeable_identities')->insert(['email' => self::EMAIL, 'updated_at' => '2026-01-01 00:00:00']);

        $model = new class extends StubChangeableModel {
            /** @var bool Whether the model keeps `created_at` and `updated_at`. */
            public $timestamps = false;

            /** @var string|null The table associated with the model. */
            protected $table = 'changeable_identities';

            /**
             * Column holding when the identifier was verified.
             *
             * @param  string  $type
             * @return string
             */
            #[\Override]
            protected function getVerifiedAtName(string $type): string
            {
                return 'phone_verified_at';
            }
        };

        $stored = $model->newQuery()->firstOrFail();

        self::assertTrue($stored->replaceIdentifier('email', self::EMAIL, self::NEW_EMAIL));

        $row = (array) DB::table('changeable_identities')->first();

        self::assertSame([self::NEW_EMAIL, null], [$row['email'], $row['email_verified_at']]);
        self::assertSame(['2027-03-01 08:30:00', '2026-01-01 00:00:00'], [$row['phone_verified_at'], $row['updated_at']]);
    }

    /**
     * Malformed identifier types.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedTypes(): iterable
    {
        yield from [
            'upper case'       => ['Email'],
            'a column list'    => ['email, password'],
            'a qualified name' => ['users.email'],
        ];
    }

    /**
     * A type that is not a valid identifier type never reaches a column name.
     *
     * @param  string  $type
     * @return void
     */
    #[DataProvider('provideMalformedTypes')]
    public function testMalformedTypesAreRefused(string $type): void
    {
        $identity = self::seedChangeable();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Identifier type [{$type}] must be");

        $identity->replaceIdentifier($type, self::EMAIL, self::NEW_EMAIL);
    }

    /**
     * Record the SQL run from now on.
     *
     * @return \Closure(): list<string>
     */
    private function recordStatements(): \Closure
    {
        $statements = [];

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = $query->sql;
        });

        Event::listen(TransactionBeginning::class, static function () use (&$statements): void {
            $statements[] = 'begin';
        });

        Event::listen(TransactionCommitted::class, static function () use (&$statements): void {
            $statements[] = 'commit';
        });

        return static function () use (&$statements): array {
            return $statements;
        };
    }

    /**
     * Record the Eloquent model events dispatched from now on.
     *
     * @return \Closure(): list<string>
     */
    private function recordModelEvents(): \Closure
    {
        $events = [];

        Event::listen('eloquent.*', static function (string $event) use (&$events): void {
            $events[] = $event;
        });

        return static function () use (&$events): array {
            return $events;
        };
    }
}
