<?php

declare(strict_types = 1);

namespace Tests\Unit\ApiKeys;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyRules;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Unit tests for what issuing or rotating an API key accepts: the principal the
 * resolver returned and the audience admitted, a name of 1 to 255 characters of
 * valid UTF-8, an expiry after the current second, and an overlap from 0 to the
 * configured maximum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApiKeyRules::class)]
final class ApiKeyRulesTest extends TestCase
{
    /**
     * Forget the configuration behind the facades.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);

        parent::tearDown();
    }

    /**
     * The principal the resolver returned is accepted when the audience admits
     * it.
     *
     * @return void
     */
    public function testAcceptsAnAdmittedPrincipal(): void
    {
        $principal = new StubPrincipal;

        self::assertSame($principal, ApiKeyRules::principal('machine', $principal, null));
    }

    /**
     * No resolved principal means the identity does not act as the one asked
     * for, which is refused naming the guard.
     *
     * @return void
     */
    public function testRefusesAnUnresolvedPrincipal(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An API key of guard [machine] can only be issued for a principal the identity acts as.');

        ApiKeyRules::principal('machine', null, null);
    }

    /**
     * A principal the audience refused is refused naming the guard and the
     * audience's reason.
     *
     * @return void
     */
    public function testRefusesAPrincipalTheAudienceRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The audience of guard [machine] does not admit the principal an API key was to be issued for (principal_inactive).');

        ApiKeyRules::principal('machine', new StubPrincipal, FailureReason::PRINCIPAL_INACTIVE);
    }

    /**
     * Rows of `[name]`: names a key may be given.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideAcceptedNames(): iterable
    {
        yield from [
            'none'                         => [null],
            'one character'                => ['a'],
            '255 multibyte characters'     => [str_repeat("\u{E9}", 255)],
            'surrounding spaces, as given' => [' Billing sync '],
        ];
    }

    /**
     * An accepted name is returned as given.
     *
     * @param  ?string  $name
     * @return void
     */
    #[DataProvider('provideAcceptedNames')]
    public function testAcceptsANameOfOneTo255Characters(?string $name): void
    {
        self::assertSame($name, ApiKeyRules::name($name));
    }

    /**
     * Rows of `[name]`: names a key may not be given.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedNames(): iterable
    {
        yield from [
            'empty'                    => [''],
            '256 multibyte characters' => [str_repeat("\u{E9}", 256)],
            'invalid UTF-8'            => ["\xC3\x28"],
        ];
    }

    /**
     * A name out of bounds is refused.
     *
     * @param  string  $name
     * @return void
     */
    #[DataProvider('provideRefusedNames')]
    public function testRefusesANameOutOfBounds(string $name): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An API key\'s name must be null or 1 to 255 characters of valid UTF-8.');

        ApiKeyRules::name($name);
    }

    /**
     * No expiry is kept as none, and a future one is cut to its whole second.
     *
     * @return void
     */
    public function testAcceptsNoExpiryOrOneInALaterSecond(): void
    {
        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        self::assertNull(ApiKeyRules::expiry(null, $now));
        self::assertSame('2026-04-06 12:00:01.000000', ApiKeyRules::expiry($now->addMilliseconds(1999), $now)?->format('Y-m-d H:i:s.u'));
    }

    /**
     * Rows of `[seconds from now]`: expiries that are not after the current
     * second.
     *
     * @return iterable<string, array{0: float}>
     */
    public static function provideRefusedExpiries(): iterable
    {
        yield from [
            'now'                      => [0.0],
            'later in the same second' => [0.9],
            'a second ago'             => [-1.0],
        ];
    }

    /**
     * An expiry that does not reach the next second is refused.
     *
     * @param  float  $seconds
     * @return void
     */
    #[DataProvider('provideRefusedExpiries')]
    public function testRefusesAnExpiryThatIsNotInALaterSecond(float $seconds): void
    {
        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An API key\'s expiry must be in the future.');

        ApiKeyRules::expiry($now->addMicroseconds((int) ($seconds * 1000000)), $now);
    }

    /**
     * An overlap given is held from 0 to the configured maximum, and none given
     * takes the configured default.
     *
     * @return void
     */
    public function testAcceptsAnOverlapFromZeroToTheMaximum(): void
    {
        self::configure(['rotation_overlap_seconds' => '3600', 'max_rotation_overlap_seconds' => 7200]);

        self::assertSame(0, ApiKeyRules::overlap(0));
        self::assertSame(7200, ApiKeyRules::overlap(7200));
        self::assertSame(3600, ApiKeyRules::overlap(null));
    }

    /**
     * Rows of `[overlap]`: overlaps out of bounds when the maximum is 7200.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideRefusedOverlaps(): iterable
    {
        yield from [
            'below zero'         => [-1],
            'beyond the maximum' => [7201],
        ];
    }

    /**
     * An overlap out of bounds is refused naming the maximum and its key.
     *
     * @param  int  $overlap
     * @return void
     */
    #[DataProvider('provideRefusedOverlaps')]
    public function testRefusesAnOverlapOutOfBounds(int $overlap): void
    {
        self::configure(['max_rotation_overlap_seconds' => 7200]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An API key\'s rotation overlap must be from 0 to 7200 seconds (`authentication.api_keys.max_rotation_overlap_seconds`).');

        ApiKeyRules::overlap($overlap);
    }

    /**
     * Put the API key settings behind the configuration facade.
     *
     * @param  array<string, int|string>  $settings
     * @return void
     */
    private static function configure(array $settings): void
    {
        $app = new Application;

        $app->instance('config', new Repository(['authentication' => ['api_keys' => $settings]]));

        Facade::setFacadeApplication($app);
    }
}
