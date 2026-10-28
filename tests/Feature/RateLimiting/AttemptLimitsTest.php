<?php

declare(strict_types = 1);

namespace Tests\Feature\RateLimiting;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptLimit;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptLimits;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use Tests\TestCase;

/**
 * Feature tests for resolving each guard's limits on each flow over the package
 * defaults.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptLimits::class)]
final class AttemptLimitsTest extends TestCase
{
    /** @var string Guard the tests configure. */
    private const string GUARD = 'api';

    /**
     * The shipped defaults: sign-in 5 per identifier and 50 per IP address in
     * five minutes; refresh failures 10 per device and 100 per IP address in a
     * minute; code requests 5 per identifier and 50 per IP address in an hour;
     * passkey sign-in options 100 per IP address in five minutes, with no
     * identifier to count; client credentials failures 10 per client id and 100
     * per IP address in a minute.
     *
     * @return void
     */
    public function testShippedDefaults(): void
    {
        self::assertSame(['per_identifier' => [5, 300], 'per_ip' => [50, 300]], $this->resolved(AttemptFlow::SIGN_IN));
        self::assertSame(['per_identifier' => [10, 60], 'per_ip' => [100, 60]], $this->resolved(AttemptFlow::REFRESH));
        self::assertSame(['per_identifier' => [5, 3600], 'per_ip' => [50, 3600]], $this->resolved(AttemptFlow::CODE_REQUEST));
        self::assertSame(['per_identifier' => null, 'per_ip' => [100, 300]], $this->resolved(AttemptFlow::PASSKEY_OPTIONS));
        self::assertSame(['per_identifier' => [10, 60], 'per_ip' => [100, 60]], $this->resolved(AttemptFlow::CLIENT_CREDENTIALS));
    }

    /**
     * A guard's scope wins, a scope it leaves out is the package's, and a scope
     * it sets to `null` is off; other flows keep the package limits.
     *
     * @return void
     */
    public function testGuardScopesOverrideThePackageScopes(): void
    {
        $this->setGuardLimits(['sign_in' => ['per_identifier' => ['max' => '3', 'decay_seconds' => '900'], 'per_ip' => null]]);

        self::assertSame(['per_identifier' => [3, 900], 'per_ip' => null], $this->resolved(AttemptFlow::SIGN_IN));
        self::assertSame(['per_identifier' => [10, 60], 'per_ip' => [100, 60]], $this->resolved(AttemptFlow::REFRESH));

        $this->setGuardLimits([
            'sign_in' => ['per_ip' => ['max' => 7, 'decay_seconds' => 30]],
            'refresh' => ['per_identifier' => ['max' => 2, 'decay_seconds' => 20]],
        ]);

        self::assertSame(['per_identifier' => [5, 300], 'per_ip' => [7, 30]], $this->resolved(AttemptFlow::SIGN_IN));
        self::assertSame(['per_identifier' => [2, 20], 'per_ip' => [100, 60]], $this->resolved(AttemptFlow::REFRESH));
    }

    /**
     * A flow set to `null`, by the guard or the package, turns both of its
     * limits off; a guard flow block wins over a package one that is off.
     *
     * @return void
     */
    public function testNullFlowTurnsItsLimitsOff(): void
    {
        $this->setGuardLimits(['refresh' => null]);

        self::assertSame(['per_identifier' => null, 'per_ip' => null], $this->resolved(AttemptFlow::REFRESH));

        config()->set('authentication.rate_limits.sign_in', null);
        $this->setGuardLimits(null);

        self::assertSame(['per_identifier' => null, 'per_ip' => null], $this->resolved(AttemptFlow::SIGN_IN));

        $this->setGuardLimits(['sign_in' => ['per_ip' => ['max' => 2, 'decay_seconds' => 10]]]);

        self::assertSame(['per_identifier' => null, 'per_ip' => [2, 10]], $this->resolved(AttemptFlow::SIGN_IN));
    }

    /**
     * Limit values that are not a limit.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedLimits(): iterable
    {
        yield from [
            'a number'              => [5],
            'empty'                 => [[]],
            'no decay'              => [['max' => 5]],
            'no max'                => [['decay_seconds' => 60]],
            'an extra key'          => [['max' => 5, 'decay_seconds' => 60, 'burst' => 2]],
            'a misspelt key'        => [['max' => 5, 'decay' => 60]],
            'a list'                => [[5, 60]],
            'zero attempts'         => [['max' => 0, 'decay_seconds' => 60]],
            'zero seconds'          => [['max' => 5, 'decay_seconds' => 0]],
            'longer than a day'     => [['max' => 5, 'decay_seconds' => 86401]],
            'a float'               => [['max' => 5.0, 'decay_seconds' => 60]],
            'a padded digit string' => [['max' => ' 5', 'decay_seconds' => 60]],
            'a negative string'     => [['max' => '-5', 'decay_seconds' => 60]],
            'true'                  => [['max' => true, 'decay_seconds' => 60]],
        ];
    }

    /**
     * A malformed limit fails closed at either level, naming the guard and the
     * key, rather than being read as off.
     *
     * @param  mixed  $limit
     * @return void
     */
    #[DataProvider('provideMalformedLimits')]
    public function testMalformedLimitFailsClosed(mixed $limit): void
    {
        $message = 'Rate limit `refresh.per_ip` for guard [api] must be null or [\'max\' => an integer of at least 1,'
            . ' \'decay_seconds\' => an integer from 1 to 86400]: set `authentication.rate_limits.refresh.per_ip` or the'
            . ' guard\'s `rate_limits.refresh.per_ip` override.';

        $this->setGuardLimits(['refresh' => ['per_ip' => $limit]]);
        $this->assertFailsClosed($message, AttemptFlow::REFRESH);

        $this->setGuardLimits(null);
        config()->set('authentication.rate_limits.refresh.per_ip', $limit);
        $this->assertFailsClosed($message, AttemptFlow::REFRESH);
    }

    /**
     * A scope missing from the package flow, with no guard value, fails closed:
     * there is no literal default.
     *
     * @return void
     */
    public function testScopeMissingAtBothLevelsFailsClosed(): void
    {
        config()->set('authentication.rate_limits.sign_in', ['per_identifier' => null]);

        $this->assertFailsClosed(
            'Rate limit `sign_in.per_ip` for guard [api] must be null or [\'max\' => an integer of at least 1,'
            . ' \'decay_seconds\' => an integer from 1 to 86400]: set `authentication.rate_limits.sign_in.per_ip` or the'
            . ' guard\'s `rate_limits.sign_in.per_ip` override.',
            AttemptFlow::SIGN_IN,
        );

        config()->set('authentication.rate_limits', ['table' => 'rate_limits', 'connection' => null]);

        $this->assertFailsClosed(
            'Rate limit `sign_in.per_identifier` for guard [api] must be null or [\'max\' => an integer of at least 1,'
            . ' \'decay_seconds\' => an integer from 1 to 86400]: set `authentication.rate_limits.sign_in.per_identifier` or the'
            . ' guard\'s `rate_limits.sign_in.per_identifier` override.',
            AttemptFlow::SIGN_IN,
        );
    }

    /**
     * A `per_identifier` limit on passkey sign-in options, which name no
     * identifier and so could never be counted against one, fails closed from
     * the guard or the package; `null` is accepted.
     *
     * @return void
     */
    public function testAPasskeyOptionsLimitPerIdentifierFailsClosed(): void
    {
        $message = 'Rate limit `passkey_options.per_identifier` for guard [api] must be null: a request for passkey sign-in options'
            . ' names no identifier, so only `per_ip` limits it.';

        $this->setGuardLimits(['passkey_options' => ['per_identifier' => ['max' => 5, 'decay_seconds' => 60]]]);

        $this->assertFailsClosed($message, AttemptFlow::PASSKEY_OPTIONS);

        $this->setGuardLimits(null);

        config()->set('authentication.rate_limits.passkey_options.per_identifier', ['max' => 5, 'decay_seconds' => 60]);

        $this->assertFailsClosed($message, AttemptFlow::PASSKEY_OPTIONS);

        $this->setGuardLimits(['passkey_options' => ['per_identifier' => null]]);

        self::assertSame(['per_identifier' => null, 'per_ip' => [100, 300]], $this->resolved(AttemptFlow::PASSKEY_OPTIONS));
    }

    /**
     * Blocks that are not arrays, or hold keys the limits do not know, fail
     * closed instead of being ignored.
     *
     * @return void
     */
    public function testMalformedBlocksFailClosed(): void
    {
        $this->setGuardLimits('none');
        $this->assertFailsClosed('Rate limits for guard [api]: the guard\'s `rate_limits` must be an array.', AttemptFlow::SIGN_IN);

        $this->setGuardLimits(['signin' => null]);
        $this->assertFailsClosed('Rate limits for guard [api]: the guard\'s `rate_limits` has an unknown key `signin`.', AttemptFlow::SIGN_IN);

        $this->setGuardLimits(['table' => 'other']);
        $this->assertFailsClosed('Rate limits for guard [api]: the guard\'s `rate_limits` has an unknown key `table`.', AttemptFlow::SIGN_IN);

        $this->setGuardLimits(['sign_in' => 'off']);
        $this->assertFailsClosed('Rate limits for guard [api]: the guard\'s `rate_limits` `sign_in` must be an array or null.', AttemptFlow::SIGN_IN);

        $this->setGuardLimits(['sign_in' => ['per_device' => null]]);
        $this->assertFailsClosed('Rate limits for guard [api]: the guard\'s `rate_limits` `sign_in` has an unknown key `per_device`.', AttemptFlow::SIGN_IN);

        $this->setGuardLimits(null);

        config()->set('authentication.rate_limits.magic_link', null);
        $this->assertFailsClosed('Rate limits for guard [api]: `authentication.rate_limits` has an unknown key `magic_link`.', AttemptFlow::SIGN_IN);

        config()->set('authentication.rate_limits', null);
        $this->assertFailsClosed('Rate limits for guard [api]: `authentication.rate_limits` must be an array.', AttemptFlow::SIGN_IN);
    }

    /**
     * A guard that is not configured is reported rather than given the package
     * defaults.
     *
     * @return void
     */
    public function testUnconfiguredGuardFailsClosed(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth guard [missing] is not configured.');

        $this->limits()->for('missing', AttemptFlow::SIGN_IN);
    }

    /**
     * Configure the guard without limits of its own.
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

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.guards.' . self::GUARD, ['driver' => 'jwt', 'provider' => 'users']);
    }

    /**
     * The guard's resolved limits on the flow as `[max, decay]` pairs.
     *
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow  $flow
     * @return array<string, ?array{0: int, 1: int}>
     */
    private function resolved(AttemptFlow $flow): array
    {
        return array_map(
            static fn (?AttemptLimit $limit): ?array => $limit === null ? null : [$limit->max, $limit->decaySeconds],
            $this->limits()->for(self::GUARD, $flow),
        );
    }

    /**
     * The limits resolver.
     *
     * @return \SineMacula\Laravel\Authentication\RateLimiting\AttemptLimits
     */
    private function limits(): AttemptLimits
    {
        $limits = $this->app?->make(AttemptLimits::class);

        self::assertInstanceOf(AttemptLimits::class, $limits);

        return $limits;
    }

    /**
     * Set the guard's `rate_limits` block.
     *
     * @param  mixed  $limits
     * @return void
     */
    private function setGuardLimits(mixed $limits): void
    {
        config()->set('auth.guards.' . self::GUARD . '.rate_limits', $limits);
    }

    /**
     * Assert resolving the guard's limits on the flow throws exactly the
     * message.
     *
     * @param  string  $message
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow  $flow
     * @return void
     */
    private function assertFailsClosed(string $message, AttemptFlow $flow): void
    {
        try {
            $this->limits()->for(self::GUARD, $flow);
        } catch (\InvalidArgumentException $e) {
            self::assertSame($message, $e->getMessage());

            return;
        }

        self::fail('Expected the limits to fail closed with: ' . $message);
    }
}
