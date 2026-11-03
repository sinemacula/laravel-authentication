<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Sessions\RevocationSettings;

/**
 * Unit tests for the revocation settings: each per-event revocation by
 * connection is on unless set, turned off only by `false`, and a value that is
 * not a boolean fails closed under its own key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevocationSettings::class)]
final class RevocationSettingsTest extends TestCase
{
    /**
     * Rows of `[the trigger]`: each one a setting turns off.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason}>
     */
    public static function provideTriggers(): iterable
    {
        yield 'a connection disabled' => [RevocationReason::CONNECTION_DISABLED];
        yield 'a connection deleted' => [RevocationReason::CONNECTION_DELETED];
        yield 'a link removed' => [RevocationReason::LINK_REMOVED];
    }

    /**
     * With nothing configured, every trigger is on; `true` keeps it on and
     * `false` turns it off, leaving the others on.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $trigger
     * @return void
     */
    #[DataProvider('provideTriggers')]
    public function testATriggerIsOnUnlessTurnedOff(RevocationReason $trigger): void
    {
        self::assertTrue(self::settings([])->isEnabled($trigger));
        self::assertTrue(self::settings([$trigger->value => true])->isEnabled($trigger));

        $off = self::settings([$trigger->value => false]);

        self::assertFalse($off->isEnabled($trigger));

        foreach (self::provideTriggers() as [$other]) {
            if ($other === $trigger) {
                continue;
            }

            self::assertTrue($off->isEnabled($other));
        }
    }

    /**
     * Rows of `[a value that is not a boolean]`, `env()`'s strings among them.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedValues(): iterable
    {
        yield 'a string' => ['false'];
        yield 'an integer' => [0];
        yield 'null' => [null];
        yield 'a list' => [[true]];
    }

    /**
     * A value that is not a boolean fails closed, named by its key, when it is
     * read and when the settings are validated.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedValues')]
    public function testAMalformedValueFailsClosed(mixed $value): void
    {
        $settings = self::settings(['link_removed' => $value]);

        try {
            $settings->isEnabled(RevocationReason::LINK_REMOVED);

            self::fail('Expected the malformed setting to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('authentication.revocation.link_removed must be true or false.', $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('authentication.revocation.link_removed must be true or false.');

        $settings->validate();
    }

    /**
     * Validating well-formed settings reads each of them and passes.
     *
     * @return void
     */
    public function testWellFormedSettingsValidate(): void
    {
        $this->expectNotToPerformAssertions();

        self::settings(['connection_disabled' => false, 'connection_deleted' => true])->validate();
    }

    /**
     * A reason no setting turns off always ends sessions, whatever is set under
     * its name.
     *
     * @return void
     */
    public function testAReasonNoSettingTurnsOffIsAlwaysOn(): void
    {
        self::assertTrue(self::settings(['factor_removed' => false])->isEnabled(RevocationReason::FACTOR_REMOVED));
    }

    /**
     * The settings over the `revocation` block given.
     *
     * @param  array<string, mixed>  $revocation
     * @return \SineMacula\Laravel\Authentication\Sessions\RevocationSettings
     */
    private static function settings(array $revocation): RevocationSettings
    {
        return new RevocationSettings(new Repository(['authentication' => ['revocation' => $revocation]]));
    }
}
