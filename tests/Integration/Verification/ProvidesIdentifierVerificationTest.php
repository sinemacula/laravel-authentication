<?php

declare(strict_types = 1);

namespace Tests\Integration\Verification;

use Carbon\Carbon;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use Tests\Concerns\InteractsWithVerifiableIdentities;
use Tests\Integration\Fixtures\VerifiableIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubVerifiableModel;

/**
 * Integration tests for the default identifier verification of an Eloquent
 * identity: an identifier column per type and a `<type>_verified_at` column
 * beside it, marked with one conditional update.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ProvidesIdentifierVerification::class)]
final class ProvidesIdentifierVerificationTest extends TestCase
{
    use InteractsWithVerifiableIdentities;

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

        self::createVerifiableIdentitiesTable();
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
     * The identifier of a type is the column named after it; a missing or empty
     * one is no identifier.
     *
     * @return void
     */
    public function testReadsTheIdentifierFromTheColumnNamedAfterItsType(): void
    {
        $identity = self::seedVerifiableIdentity('Ben@Example.com', '+447700900123');

        self::assertSame('ben@example.com', $identity->getIdentifierForVerification('email'));
        self::assertSame('+447700900123', $identity->getIdentifierForVerification('phone'));

        $identity->setRawAttributes(['email' => '', 'phone' => null]);

        self::assertNull($identity->getIdentifierForVerification('email'));
        self::assertNull($identity->getIdentifierForVerification('phone'));
    }

    /**
     * An identifier is verified when its `<type>_verified_at` is set.
     *
     * @return void
     */
    public function testAnIdentifierIsVerifiedWhenItHasAVerificationTime(): void
    {
        $identity = self::seedVerifiableIdentity();

        self::assertFalse($identity->hasVerifiedIdentifier('email'));

        $identity->setRawAttributes(['email_verified_at' => '2027-01-01 00:00:00', 'phone_verified_at' => null]);

        self::assertTrue($identity->hasVerifiedIdentifier('email'));
        self::assertFalse($identity->hasVerifiedIdentifier('phone'));
    }

    /**
     * Marking reads the row again under a lock and writes the verification time
     * to the row and the model, all in one transaction; it fires no model
     * event, leaves `updated_at` alone and the model clean, and reports that it
     * recorded the verification.
     *
     * @return void
     */
    public function testMarkingRecordsTheVerificationUnderALock(): void
    {
        $identity   = self::seedVerifiableIdentity();
        $updated    = DB::table('verifiable_identities')->value('updated_at');
        $statements = $this->recordStatements();
        $events     = $this->recordModelEvents();
        $lock       = DB::connection()->getDriverName() === 'sqlite' ? '' : ' for update';

        Carbon::setTestNow(Carbon::parse('2027-03-01 09:00:00'));

        self::assertTrue($identity->markIdentifierAsVerified('email', 'ben@example.com'));
        self::assertCount(4, $statements());
        self::assertSame('begin', $statements()[0]);
        self::assertStringStartsWith('select', $statements()[1]);
        self::assertStringEndsWith('limit 1' . $lock, $statements()[1]);
        self::assertStringStartsWith('update', $statements()[2]);
        self::assertSame('commit', $statements()[3]);
        self::assertSame('2027-03-01 09:00:00', DB::table('verifiable_identities')->value('email_verified_at'));
        self::assertSame('2027-03-01 09:00:00', $identity->email_verified_at?->format('Y-m-d H:i:s'));
        self::assertTrue($identity->hasVerifiedIdentifier('email'));
        self::assertFalse($identity->isDirty());
        self::assertSame($updated, DB::table('verifiable_identities')->value('updated_at'));
        self::assertSame([], $events());
    }

    /**
     * Marking records nothing when the identifier is already verified, when the
     * row's identifier is not the one given, whatever the model in memory
     * holds, or when the row is gone.
     *
     * @return void
     */
    public function testMarkingIsConditionalOnTheStoredIdentifierAndState(): void
    {
        $identity = self::seedVerifiableIdentity();

        self::assertFalse($identity->markIdentifierAsVerified('email', 'someone@example.com'));
        self::assertFalse($identity->hasVerifiedIdentifier('email'));

        DB::table('verifiable_identities')->update(['email' => 'changed@example.com']);

        self::assertFalse($identity->markIdentifierAsVerified('email', 'ben@example.com'));
        self::assertNull(DB::table('verifiable_identities')->value('email_verified_at'));

        self::assertTrue($identity->markIdentifierAsVerified('email', 'changed@example.com'));
        self::assertFalse($identity->markIdentifierAsVerified('email', 'changed@example.com'));

        DB::table('verifiable_identities')->delete();

        self::assertFalse($identity->markIdentifierAsVerified('email', 'changed@example.com'));
    }

    /**
     * An identifier changed between the decision to mark it and the mark is not
     * verified: the row the mark reads again no longer holds it.
     *
     * @return void
     */
    public function testIdentifierChangedJustBeforeTheMarkIsNotVerified(): void
    {
        $identity = self::seedVerifiableIdentity();

        $ran = false;

        DB::connection()->beforeExecuting(static function (string $query) use (&$ran): void {
            if ($ran || !str_starts_with(strtolower($query), 'select')) {
                return;
            }

            $ran = true;

            DB::connection()->getPdo()->exec('update verifiable_identities set email = \'thief@example.com\'');
        });

        self::assertFalse($identity->markIdentifierAsVerified('email', 'ben@example.com'));
        self::assertNull(DB::table('verifiable_identities')->value('email_verified_at'));
    }

    /**
     * Each type uses its own columns, and a subclass can name the verification
     * column differently.
     *
     * @return void
     */
    public function testEachTypeUsesItsOwnColumns(): void
    {
        $identity = self::seedVerifiableIdentity('ben@example.com', '+447700900123');

        self::assertTrue($identity->markIdentifierAsVerified('phone', '+447700900123'));
        self::assertTrue($identity->hasVerifiedIdentifier('phone'));
        self::assertFalse($identity->hasVerifiedIdentifier('email'));

        $renamed = new class extends StubVerifiableModel {
            /**
             * Column holding when the identifier was verified.
             *
             * @param  string  $type
             * @return string
             */
            #[\Override]
            protected function getVerifiedAtName(string $type): string
            {
                return "verified_{$type}_at";
            }
        };

        $renamed->setRawAttributes(['email' => 'ben@example.com', 'email_verified_at' => null, 'verified_email_at' => '2027-01-01 00:00:00']);

        self::assertTrue($renamed->hasVerifiedIdentifier('email'));
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
            'trailing newline' => ["email\n"],
        ];
    }

    /**
     * A type that is not a valid identifier type never reaches a column name.
     *
     * @param  string  $type
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedTypes')]
    public function testMalformedTypesAreRefused(string $type): void
    {
        $identity = self::seedVerifiableIdentity();

        $calls = [
            static fn (): mixed => $identity->getIdentifierForVerification($type),
            static fn (): mixed => $identity->hasVerifiedIdentifier($type),
            static fn (): mixed => $identity->markIdentifierAsVerified($type, 'ben@example.com'),
        ];

        foreach ($calls as $call) {
            try {
                $call();
                self::fail('Expected the type to be refused.');
            } catch (\InvalidArgumentException $e) {
                self::assertStringStartsWith("Identifier type [{$type}] must be", $e->getMessage());
            }
        }
    }

    /**
     * An identity loaded without the identifier or verification column throws
     * rather than reading as having no identifier or as unverified.
     *
     * @return void
     */
    public function testPartialSelectIsReported(): void
    {
        self::seedVerifiableIdentity();

        $partial = VerifiableIdentity::query()->select(['id'])->firstOrFail();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Cannot read the verification of ' . VerifiableIdentity::class . ': its `email_verified_at` attribute is not loaded.');

        try {
            $partial->getIdentifierForVerification('email');
            self::fail('Expected the unloaded identifier to be reported.');
        } catch (\LogicException $e) {
            self::assertStringContainsString('its `email` attribute is not loaded', $e->getMessage());
        }

        $partial->hasVerifiedIdentifier('email');
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
