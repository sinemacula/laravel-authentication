<?php

declare(strict_types = 1);

namespace Tests\Integration\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Concerns\ProvidesTokensValidAfter;
use Tests\Integration\Fixtures\CutoffIdentity;
use Tests\TestCase;

/**
 * Integration tests for the "tokens valid after" cutoff an identity or
 * principal records: how it is read, and the forward-only conditional write,
 * against a real table on each supported database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ProvidesTokensValidAfter::class)]
final class TokensValidAfterIntegrationTest extends TestCase
{
    /**
     * Create the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('cutoff_identities');

        parent::tearDown();
    }

    /**
     * An identity without a cutoff reads `null`; once moved, the cutoff is
     * stored to the second, mirrored on the model without a save, and read back
     * from a fresh load.
     *
     * @return void
     */
    public function testMovesAnUnsetCutoffAndMirrorsIt(): void
    {
        $identity = $this->seedIdentity();
        $at       = CarbonImmutable::parse('2027-01-15 10:00:00');

        $before = $identity->getTokensValidAfter();

        self::assertTrue($identity->invalidateTokensIssuedBefore($at));
        self::assertNull($before);

        $mirrored = $identity->getTokensValidAfter();

        self::assertNotNull($mirrored);
        self::assertSame('2027-01-15 10:00:00', $mirrored->format('Y-m-d H:i:s'));
        self::assertFalse($identity->isDirty());
        self::assertSame('2027-01-15 10:00:00', DB::table('cutoff_identities')->value('tokens_valid_after'));
        self::assertSame('2027-01-15 10:00:00', CutoffIdentity::query()->findOrFail($identity->id)->getTokensValidAfter()?->format('Y-m-d H:i:s'));
    }

    /**
     * The cutoff only ever moves forward: an equal or earlier time changes
     * nothing, in the row or in memory, and reports so.
     *
     * @return void
     */
    public function testNeverMovesTheCutoffBack(): void
    {
        $identity = $this->seedIdentity('2027-01-15 10:00:00');

        self::assertFalse($identity->invalidateTokensIssuedBefore(CarbonImmutable::parse('2027-01-15 10:00:00')));
        self::assertFalse($identity->invalidateTokensIssuedBefore(CarbonImmutable::parse('2027-01-15 09:59:59')));
        self::assertSame('2027-01-15 10:00:00', DB::table('cutoff_identities')->value('tokens_valid_after'));
        self::assertSame('2027-01-15 10:00:00', $identity->getTokensValidAfter()?->format('Y-m-d H:i:s'));

        self::assertTrue($identity->invalidateTokensIssuedBefore(CarbonImmutable::parse('2027-01-15 10:00:01')));
        self::assertSame('2027-01-15 10:00:01', DB::table('cutoff_identities')->value('tokens_valid_after'));
    }

    /**
     * The write judges the row, not the model: a later cutoff another writer
     * stored meanwhile is kept, and the stale model is left as it was.
     *
     * @return void
     */
    public function testKeepsALaterCutoffWrittenMeanwhile(): void
    {
        $identity = $this->seedIdentity();

        DB::table('cutoff_identities')->update(['tokens_valid_after' => '2027-01-15 11:00:00']);

        self::assertFalse($identity->invalidateTokensIssuedBefore(CarbonImmutable::parse('2027-01-15 10:00:00')));
        self::assertSame('2027-01-15 11:00:00', DB::table('cutoff_identities')->value('tokens_valid_after'));
        self::assertNull($identity->getTokensValidAfter());
    }

    /**
     * Only the identity's own row is written.
     *
     * @return void
     */
    public function testWritesOnlyTheModelsRow(): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->seedIdentity(null, 'grace@example.test');

        $identity->invalidateTokensIssuedBefore(CarbonImmutable::parse('2027-01-15 10:00:00'));

        self::assertNull(DB::table('cutoff_identities')->where('id', $other->id)->value('tokens_valid_after'));
    }

    /**
     * A model loaded without the column throws rather than reading as having no
     * cutoff.
     *
     * @return void
     */
    public function testAModelLoadedWithoutTheColumnThrows(): void
    {
        $this->seedIdentity('2027-01-15 10:00:00');

        $partial = CutoffIdentity::query()->select(['id', 'email'])->firstOrFail();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Cannot read when the tokens of ' . CutoffIdentity::class . ' become valid: its `tokens_valid_after` attribute is not loaded.');

        $partial->getTokensValidAfter();
    }

    /**
     * Persist an identity with the given cutoff.
     *
     * @param  ?string  $cutoff
     * @param  string  $email
     * @return \Tests\Integration\Fixtures\CutoffIdentity
     */
    private function seedIdentity(?string $cutoff = null, string $email = 'ada@example.test'): CutoffIdentity
    {
        $identity = new CutoffIdentity;

        $identity->forceFill(['email' => $email, 'tokens_valid_after' => $cutoff])->save();

        return CutoffIdentity::query()->findOrFail($identity->id);
    }
}
