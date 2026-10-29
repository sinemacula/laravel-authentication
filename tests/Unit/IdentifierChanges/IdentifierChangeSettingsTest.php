<?php

declare(strict_types = 1);

namespace Tests\Unit\IdentifierChanges;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeSettings;

/**
 * Unit tests for the identifier change settings: their defaults, the forms and
 * ranges they accept, and the key each malformed one is reported under.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierChangeSettings::class)]
final class IdentifierChangeSettingsTest extends TestCase
{
    /**
     * With no `identifier_changes` block, a change waits an hour and must come
     * within fifteen minutes of an authentication.
     *
     * @return void
     */
    public function testDefaultsApplyWhenNothingIsConfigured(): void
    {
        $settings = self::settings([]);

        self::assertSame([3600, 900], [$settings->ttlSeconds(), $settings->recentAuthenticationSeconds()]);
    }

    /**
     * Rows of `[key, value, what the reader returns]`: integers and the digit
     * strings `env()` returns, at each end of their range.
     *
     * @return iterable<string, array{0: string, 1: int|string, 2: int}>
     */
    public static function provideAcceptedNumbers(): iterable
    {
        yield from [
            'shortest wait'   => ['ttl_seconds', 300, 300],
            'longest wait'    => ['ttl_seconds', '86400', 86400],
            'shortest window' => ['recent_authentication_seconds', '60', 60],
            'longest window'  => ['recent_authentication_seconds', 86400, 86400],
        ];
    }

    /**
     * Each number is read as an integer, from an integer or its digit string.
     *
     * @param  string  $key
     * @param  int|string  $value
     * @param  int  $expected
     * @return void
     */
    #[DataProvider('provideAcceptedNumbers')]
    public function testReadsNumbersWithinTheirRange(string $key, int|string $value, int $expected): void
    {
        $settings = self::settings([$key => $value]);
        $readers  = [
            'ttl_seconds'                   => $settings->ttlSeconds(...),
            'recent_authentication_seconds' => $settings->recentAuthenticationSeconds(...),
        ];

        self::assertSame($expected, $readers[$key]());
    }

    /**
     * Rows of `[key, value, message]`: values out of range, of another type, or
     * strings that are not the canonical digits of an integer.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideMalformedNumbers(): iterable
    {
        $wait   = 'authentication.identifier_changes.ttl_seconds must be an integer from 300 to 86400.';
        $window = 'authentication.identifier_changes.recent_authentication_seconds must be an integer from 60 to 86400.';

        yield from [
            'wait too short'    => ['ttl_seconds', 299, $wait],
            'wait too long'     => ['ttl_seconds', '86401', $wait],
            'wait null'         => ['ttl_seconds', null, $wait],
            'wait a float'      => ['ttl_seconds', 3600.0, $wait],
            'wait padded'       => ['ttl_seconds', '03600', $wait],
            'wait spaced'       => ['ttl_seconds', ' 3600', $wait],
            'wait newline'      => ['ttl_seconds', "3600\n", $wait],
            'window too short'  => ['recent_authentication_seconds', 59, $window],
            'window too long'   => ['recent_authentication_seconds', 86401, $window],
            'window a bool'     => ['recent_authentication_seconds', true, $window],
            'window negative'   => ['recent_authentication_seconds', '-900', $window],
            'window ten digits' => ['recent_authentication_seconds', '1000000000', $window],
        ];
    }

    /**
     * A malformed number fails closed, naming the key and its range.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedNumbers')]
    public function testRefusesMalformedNumbers(string $key, mixed $value, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::settings([$key => $value])->validate();
    }

    /**
     * Settings over the given `identifier_changes` block.
     *
     * @param  array<string, mixed>  $block
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeSettings
     */
    private static function settings(array $block): IdentifierChangeSettings
    {
        return new IdentifierChangeSettings(new Repository(['authentication' => ['identifier_changes' => $block]]));
    }
}
