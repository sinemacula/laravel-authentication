<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Carbon\Carbon;
use Carbon\CarbonInterface;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Concerns\ProvidesTokensValidAfter;
use Tests\Unit\Stubs\StubCutoffModel;

/**
 * Unit tests for reading the "tokens valid after" cutoff of a model, cast or
 * stored raw, and under a renamed column.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ProvidesTokensValidAfter::class)]
final class ProvidesTokensValidAfterTest extends TestCase
{
    /**
     * A raw stored value, without a `datetime` cast, is read as a time; a
     * stored time is returned as it is; a stored `null` is no cutoff.
     *
     * @return void
     */
    public function testReadsRawCastAndNullValues(): void
    {
        $model = new StubCutoffModel;

        $model->setRawAttributes(['tokens_valid_after' => '2027-01-15 10:00:00']);

        $read = $model->getTokensValidAfter();

        self::assertInstanceOf(CarbonInterface::class, $read);
        self::assertSame('2027-01-15 10:00:00', $read->format('Y-m-d H:i:s'));

        $time = Carbon::parse('2027-01-16 10:00:00');

        $model->setRawAttributes(['tokens_valid_after' => $time]);

        self::assertSame($time, $model->getTokensValidAfter());

        $model->setRawAttributes(['tokens_valid_after' => null]);

        self::assertNull($model->getTokensValidAfter());
    }

    /**
     * The column comes from the overridable name, both for reading and for the
     * error on a model loaded without it.
     *
     * @return void
     */
    public function testHonoursARenamedColumn(): void
    {
        $model = new class extends StubCutoffModel {
            /**
             * Column name holding the cutoff.
             *
             * @return string
             */
            #[\Override]
            protected function getTokensValidAfterName(): string
            {
                return 'sessions_' . parent::getTokensValidAfterName();
            }
        };

        $model->setRawAttributes(['sessions_tokens_valid_after' => '2027-01-15 10:00:00', 'tokens_valid_after' => null]);

        self::assertSame('2027-01-15 10:00:00', $model->getTokensValidAfter()?->format('Y-m-d H:i:s'));

        $model->setRawAttributes(['tokens_valid_after' => null]);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('its `sessions_tokens_valid_after` attribute is not loaded. Select the column or override getTokensValidAfterName().');

        $model->getTokensValidAfter();
    }
}
