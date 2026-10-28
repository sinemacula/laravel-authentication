<?php

declare(strict_types = 1);

namespace Tests\Feature\ApiKeys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeySettings;
use Tests\TestCase;

/**
 * Feature tests for the `authentication.api_keys` settings: the shipped
 * defaults, the forms accepted, and that every value out of form or range fails
 * closed naming its key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApiKeySettings::class)]
final class ApiKeySettingsTest extends TestCase
{
    /**
     * The shipped defaults: prefix `ak`, a day's overlap of at most a week, a
     * minute's last-use throttle, and pruning 30 days on.
     *
     * @return void
     */
    public function testShippedDefaults(): void
    {
        self::assertSame('ak', ApiKeySettings::prefix());
        self::assertSame(86400, ApiKeySettings::rotationOverlapSeconds());
        self::assertSame(604800, ApiKeySettings::maxRotationOverlapSeconds());
        self::assertSame(60, ApiKeySettings::lastUsedThrottleSeconds());
        self::assertSame(30, ApiKeySettings::pruneAfterDays());
    }

    /**
     * Values missing from the block take their defaults.
     *
     * @return void
     */
    public function testMissingValuesTakeTheirDefaults(): void
    {
        config()->set('authentication.api_keys', []);

        self::assertSame('ak', ApiKeySettings::prefix());
        self::assertSame(86400, ApiKeySettings::rotationOverlapSeconds());
        self::assertSame(604800, ApiKeySettings::maxRotationOverlapSeconds());
        self::assertSame(60, ApiKeySettings::lastUsedThrottleSeconds());
        self::assertSame(30, ApiKeySettings::pruneAfterDays());
    }

    /**
     * Each number is an integer, or its digit string as `env()` returns one, up
     * to each end of its range.
     *
     * @return void
     */
    public function testAcceptsIntegersAndDigitStringsAtTheEdges(): void
    {
        config()->set('authentication.api_keys.max_rotation_overlap_seconds', '2592000');
        config()->set('authentication.api_keys.rotation_overlap_seconds', 2592000);
        config()->set('authentication.api_keys.last_used_throttle_seconds', '86400');
        config()->set('authentication.api_keys.prune_after_days', '3650');

        self::assertSame(2592000, ApiKeySettings::maxRotationOverlapSeconds());
        self::assertSame(2592000, ApiKeySettings::rotationOverlapSeconds());
        self::assertSame(86400, ApiKeySettings::lastUsedThrottleSeconds());
        self::assertSame(3650, ApiKeySettings::pruneAfterDays());

        config()->set('authentication.api_keys.max_rotation_overlap_seconds', '0');
        config()->set('authentication.api_keys.rotation_overlap_seconds', '0');
        config()->set('authentication.api_keys.last_used_throttle_seconds', 0);
        config()->set('authentication.api_keys.prune_after_days', 0);

        self::assertSame(0, ApiKeySettings::maxRotationOverlapSeconds());
        self::assertSame(0, ApiKeySettings::rotationOverlapSeconds());
        self::assertSame(0, ApiKeySettings::lastUsedThrottleSeconds());
        self::assertSame(0, ApiKeySettings::pruneAfterDays());
    }

    /**
     * Rows of `[key, value, message]`: values out of form or range.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideInvalidValues(): iterable
    {
        $overlap  = '`authentication.api_keys.rotation_overlap_seconds` must be an integer from 0 to `max_rotation_overlap_seconds` (604800) seconds.';
        $max      = '`authentication.api_keys.max_rotation_overlap_seconds` must be an integer from 0 to 2592000 seconds.';
        $throttle = '`authentication.api_keys.last_used_throttle_seconds` must be an integer from 0 to 86400 seconds.';
        $prune    = '`authentication.api_keys.prune_after_days` must be an integer from 0 to 3650 days.';

        yield from [
            'overlap above the maximum' => ['rotation_overlap_seconds', 604801, $overlap],
            'negative overlap'          => ['rotation_overlap_seconds', -1, $overlap],
            'overlap as a float'        => ['rotation_overlap_seconds', 60.0, $overlap],
            'overlap with a sign'       => ['rotation_overlap_seconds', '+60', $overlap],
            'overlap with a zero lead'  => ['rotation_overlap_seconds', '060', $overlap],
            'overlap with spaces'       => ['rotation_overlap_seconds', ' 60', $overlap],
            'maximum above 30 days'     => ['max_rotation_overlap_seconds', 2592001, $max],
            'negative maximum'          => ['max_rotation_overlap_seconds', -1, $max],
            'negative maximum string'   => ['max_rotation_overlap_seconds', '-1', $max],
            'maximum with a newline'    => ['max_rotation_overlap_seconds', "60\n", $max],
            'maximum as null'           => ['max_rotation_overlap_seconds', null, $max],
            'throttle above a day'      => ['last_used_throttle_seconds', 86401, $throttle],
            'negative throttle'         => ['last_used_throttle_seconds', -1, $throttle],
            'throttle as a word'        => ['last_used_throttle_seconds', 'sixty', $throttle],
            'retention above 10 years'  => ['prune_after_days', 3651, $prune],
            'negative retention'        => ['prune_after_days', -1, $prune],
            'retention as true'         => ['prune_after_days', true, $prune],
            'retention digits too long' => ['prune_after_days', '12345678901', $prune],
        ];
    }

    /**
     * A value out of form or range fails closed naming its key.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideInvalidValues')]
    public function testRefusesAValueOutOfFormOrRange(string $key, mixed $value, string $message): void
    {
        config()->set("authentication.api_keys.{$key}", $value);

        $read = match ($key) {
            'rotation_overlap_seconds'     => ApiKeySettings::rotationOverlapSeconds(...),
            'max_rotation_overlap_seconds' => ApiKeySettings::maxRotationOverlapSeconds(...),
            'last_used_throttle_seconds'   => ApiKeySettings::lastUsedThrottleSeconds(...),
            default                        => ApiKeySettings::pruneAfterDays(...),
        };

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $read();
    }

    /**
     * The default overlap is held to the configured maximum, not only to 30
     * days.
     *
     * @return void
     */
    public function testHoldsTheDefaultOverlapToTheConfiguredMaximum(): void
    {
        config()->set('authentication.api_keys.max_rotation_overlap_seconds', 60);
        config()->set('authentication.api_keys.rotation_overlap_seconds', 60);

        self::assertSame(60, ApiKeySettings::rotationOverlapSeconds());

        config()->set('authentication.api_keys.rotation_overlap_seconds', 61);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`authentication.api_keys.rotation_overlap_seconds` must be an integer from 0 to `max_rotation_overlap_seconds` (60) seconds.');

        ApiKeySettings::rotationOverlapSeconds();
    }

    /**
     * Rows of `[prefix, valid]`.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function providePrefixes(): iterable
    {
        yield from [
            'one letter'       => ['a', true],
            'sixteen'          => ['abcdefghijklmno1', true],
            'letters, digits'  => ['acme2', true],
            'seventeen'        => ['abcdefghijklmnop1', false],
            'digit first'      => ['2acme', false],
            'upper case'       => ['Acme', false],
            'underscore'       => ['ac_me', false],
            'empty'            => ['', false],
            'trailing newline' => ["acme\n", false],
            'not a string'     => [12, false],
        ];
    }

    /**
     * The prefix is a lower-case letter followed by up to 15 lower-case letters
     * or digits.
     *
     * @param  mixed  $prefix
     * @param  bool  $valid
     * @return void
     */
    #[DataProvider('providePrefixes')]
    public function testHoldsThePrefixToItsForm(mixed $prefix, bool $valid): void
    {
        config()->set('authentication.api_keys.prefix', $prefix);

        if ($valid) {
            self::assertSame($prefix, ApiKeySettings::prefix());

            return;
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`authentication.api_keys.prefix` must be a lower-case letter followed by up to 15 lower-case letters or digits.');

        ApiKeySettings::prefix();
    }
}
