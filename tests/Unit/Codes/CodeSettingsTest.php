<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\CodeSettings;

/**
 * Unit tests for the one-time code settings: their defaults, the forms and
 * ranges they accept, and the key each malformed one is reported under.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeSettings::class)]
final class CodeSettingsTest extends TestCase
{
    /**
     * With no `codes` block, each number takes its default: 6 digits, 600
     * seconds, 5 attempts and a 60-second cooldown; the queue settings are
     * `null`, for the application's defaults.
     *
     * @return void
     */
    public function testDefaultsApplyWhenNothingIsConfigured(): void
    {
        $settings = self::settings([]);

        self::assertSame([6, 600, 5, 60], [$settings->length(), $settings->ttlSeconds(), $settings->maxAttempts(), $settings->cooldownSeconds()]);
        self::assertNull($settings->queueConnection());
        self::assertNull($settings->queueName());
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
            'shortest code'           => ['length', 6, 6],
            'longest code'            => ['length', '10', 10],
            'shortest lifetime'       => ['ttl_seconds', 60, 60],
            'longest lifetime'        => ['ttl_seconds', '3600', 3600],
            'one attempt'             => ['max_attempts', '1', 1],
            'twenty attempts'         => ['max_attempts', 20, 20],
            'no cooldown'             => ['resend_cooldown_seconds', '0', 0],
            'cooldown of the default' => ['resend_cooldown_seconds', 600, 600],
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
            'length'                  => $settings->length(...),
            'ttl_seconds'             => $settings->ttlSeconds(...),
            'max_attempts'            => $settings->maxAttempts(...),
            'resend_cooldown_seconds' => $settings->cooldownSeconds(...),
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
        yield from [
            'code too short'     => ['length', 5, 'authentication.codes.length must be an integer from 6 to 10.'],
            'code too long'      => ['length', '11', 'authentication.codes.length must be an integer from 6 to 10.'],
            'length null'        => ['length', null, 'authentication.codes.length must be an integer from 6 to 10.'],
            'length a float'     => ['length', 6.0, 'authentication.codes.length must be an integer from 6 to 10.'],
            'length padded'      => ['length', '06', 'authentication.codes.length must be an integer from 6 to 10.'],
            'length spaced'      => ['length', ' 6', 'authentication.codes.length must be an integer from 6 to 10.'],
            'length newline'     => ['length', "6\n", 'authentication.codes.length must be an integer from 6 to 10.'],
            'length negative'    => ['length', '-6', 'authentication.codes.length must be an integer from 6 to 10.'],
            'lifetime too short' => ['ttl_seconds', 59, 'authentication.codes.ttl_seconds must be an integer from 60 to 3600.'],
            'lifetime too long'  => ['ttl_seconds', 3601, 'authentication.codes.ttl_seconds must be an integer from 60 to 3600.'],
            'no attempts'        => ['max_attempts', 0, 'authentication.codes.max_attempts must be an integer from 1 to 20.'],
            'too many attempts'  => ['max_attempts', '21', 'authentication.codes.max_attempts must be an integer from 1 to 20.'],
            'attempts a bool'    => ['max_attempts', true, 'authentication.codes.max_attempts must be an integer from 1 to 20.'],
            'negative cooldown'  => ['resend_cooldown_seconds', -1, 'authentication.codes.resend_cooldown_seconds must be an integer from 0 to 600.'],
            'cooldown past ttl'  => ['resend_cooldown_seconds', 601, 'authentication.codes.resend_cooldown_seconds must be an integer from 0 to 600.'],
            'ten-digit string'   => ['ttl_seconds', '1000000000', 'authentication.codes.ttl_seconds must be an integer from 60 to 3600.'],
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
     * The cooldown's greatest value is the configured code lifetime.
     *
     * @return void
     */
    public function testTheCooldownIsBoundedByTheLifetime(): void
    {
        self::assertSame(120, self::settings(['ttl_seconds' => 120, 'resend_cooldown_seconds' => 120])->cooldownSeconds());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('authentication.codes.resend_cooldown_seconds must be an integer from 0 to 120.');

        self::settings(['ttl_seconds' => 120, 'resend_cooldown_seconds' => 121])->cooldownSeconds();
    }

    /**
     * The queue settings are names, and an empty string, as `env()` returns for
     * a variable set to nothing, means the default like `null`.
     *
     * @return void
     */
    public function testReadsTheQueueSettings(): void
    {
        $named = self::settings(['queue' => ['connection' => 'redis', 'name' => 'codes']]);
        $empty = self::settings(['queue' => ['connection' => '', 'name' => '']]);

        self::assertSame(['redis', 'codes'], [$named->queueConnection(), $named->queueName()]);
        self::assertSame([null, null], [$empty->queueConnection(), $empty->queueName()]);
    }

    /**
     * Rows of `[queue block, message]`: settings that are not names.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function provideMalformedQueues(): iterable
    {
        yield from [
            'connection a number' => [['connection' => 1], 'authentication.codes.queue.connection must be a name, or null for the default.'],
            'connection a list'   => [['connection' => ['redis']], 'authentication.codes.queue.connection must be a name, or null for the default.'],
            'queue a boolean'     => [['name' => false], 'authentication.codes.queue.name must be a name, or null for the default.'],
        ];
    }

    /**
     * A queue setting that is not a name fails closed, naming the key.
     *
     * @param  array<string, mixed>  $queue
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedQueues')]
    public function testRefusesMalformedQueueSettings(array $queue, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::settings(['queue' => $queue])->validate();
    }

    /**
     * Delivery is synchronous when the configured connection, or the default
     * one when none is configured, uses the `sync` driver.
     *
     * @return void
     */
    public function testTellsWhetherTheDeliveryConnectionIsSynchronous(): void
    {
        $connections = ['sync' => ['driver' => 'sync'], 'database' => ['driver' => 'database']];

        self::assertTrue(self::settings([], ['default' => 'sync', 'connections' => $connections])->deliversSynchronously());
        self::assertFalse(self::settings([], ['default' => 'database', 'connections' => $connections])->deliversSynchronously());
        self::assertFalse(self::settings(['queue' => ['connection' => 'database']], ['default' => 'sync', 'connections' => $connections])->deliversSynchronously());
        self::assertTrue(self::settings(['queue' => ['connection' => 'sync']], ['default' => 'database', 'connections' => $connections])->deliversSynchronously());
    }

    /**
     * Rows of `[delivery connection, whether it falls back to sync]` over one
     * set of connections.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideFailoverConnections(): iterable
    {
        yield from [
            'sync itself'                       => ['sync', false],
            'a worker-backed connection'        => ['database', false],
            'a failover listing sync'           => ['to_sync', true],
            'a failover listing sync later'     => ['nested', true],
            'a failover of workers only'        => ['workers', false],
            'a failover listing itself'         => ['looping', false],
            'failovers listing each other'      => ['ping', false],
            'a failover leading into a loop'    => ['entry', false],
            'a failover listing nothing'        => ['empty', false],
            'a failover of unknown or no names' => ['unknown', false],
        ];
    }

    /**
     * A `failover` delivery connection falls back to `sync` when it lists a
     * `sync` connection, directly or through other `failover` connections; a
     * connection already on the path is not followed again, and a name that is
     * not a configured connection leads nowhere.
     *
     * @param  string  $connection
     * @param  bool  $fallsBack
     * @return void
     */
    #[DataProvider('provideFailoverConnections')]
    public function testTellsWhetherTheDeliveryConnectionFallsBackToSync(string $connection, bool $fallsBack): void
    {
        $connections = [
            'sync'     => ['driver' => 'sync'],
            'database' => ['driver' => 'database'],
            'redis'    => ['driver' => 'redis'],
            'to_sync'  => ['driver' => 'failover', 'connections' => ['redis', 'sync']],
            'nested'   => ['driver' => 'failover', 'connections' => ['database', 'workers', 'looping', 'to_sync']],
            'workers'  => ['driver' => 'failover', 'connections' => ['redis', 'database']],
            'looping'  => ['driver' => 'failover', 'connections' => ['looping', 'workers']],
            'ping'     => ['driver' => 'failover', 'connections' => ['pong', 'database']],
            'pong'     => ['driver' => 'failover', 'connections' => ['ping', 'redis']],
            'entry'    => ['driver' => 'failover', 'connections' => ['ping']],
            'empty'    => ['driver' => 'failover'],
            'unknown'  => ['driver' => 'failover', 'connections' => ['missing', ['sync'], 7]],
        ];

        $settings = self::settings(['queue' => ['connection' => $connection]], ['default' => 'sync', 'connections' => $connections]);

        self::assertSame($fallsBack, $settings->fallsBackToSync());
        self::assertSame($connection === 'sync', $settings->deliversSynchronously());
    }

    /**
     * Rows of `[codes block, queue configuration]` whose delivery connection is
     * not configured.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>}>
     */
    public static function provideUnconfiguredConnections(): iterable
    {
        yield from [
            'unknown connection named'  => [['queue' => ['connection' => 'redis']], ['default' => 'sync', 'connections' => ['sync' => ['driver' => 'sync']]]],
            'no default connection'     => [[], ['connections' => ['sync' => ['driver' => 'sync']]]],
            'connection without driver' => [[], ['default' => 'sync', 'connections' => ['sync' => []]]],
        ];
    }

    /**
     * A delivery connection that is not configured fails closed.
     *
     * @param  array<string, mixed>  $codes
     * @param  array<string, mixed>  $queue
     * @return void
     */
    #[DataProvider('provideUnconfiguredConnections')]
    public function testRefusesAnUnconfiguredConnection(array $codes, array $queue): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('authentication.codes.queue.connection must name a connection configured in `queue.connections`, or be null for `queue.default`.');

        self::settings($codes, $queue)->validate();
    }

    /**
     * Build the settings over a `codes` block and a queue configuration.
     *
     * @param  array<string, mixed>  $codes
     * @param  array<string, mixed>  $queue
     * @return \SineMacula\Laravel\Authentication\Codes\CodeSettings
     */
    private static function settings(array $codes, array $queue = ['default' => 'sync', 'connections' => ['sync' => ['driver' => 'sync']]]): CodeSettings
    {
        return new CodeSettings(new Repository(['authentication' => ['codes' => $codes], 'queue' => $queue]));
    }
}
