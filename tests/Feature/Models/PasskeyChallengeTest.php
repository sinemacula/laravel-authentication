<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Carbon\CarbonImmutable;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Models\PasskeyChallenge;
use Tests\Integration\Fixtures\SeparateConnectionDevice;
use Tests\TestCase;

/**
 * Feature tests for where the passkey challenge model keeps its rows, what it
 * keeps out of its serialisation, and which rows `model:prune` deletes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyChallenge::class)]
final class PasskeyChallengeTest extends TestCase
{
    /**
     * Release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * The model uses the configured table, and `passkey_challenges` when none
     * is configured.
     *
     * @return void
     */
    public function testTheTableIsTheConfiguredOne(): void
    {
        Config::set('authentication.passkeys.challenges_table', 'webauthn_challenges');

        self::assertSame('webauthn_challenges', (new PasskeyChallenge)->getTable());

        Config::set('authentication.passkeys', []);

        self::assertSame('passkey_challenges', (new PasskeyChallenge)->getTable());
    }

    /**
     * The model follows the device model onto its connection.
     *
     * @return void
     */
    public function testTheConnectionIsTheDeviceModelsOne(): void
    {
        Config::set('authentication.device.model', SeparateConnectionDevice::class);

        self::assertSame(SeparateConnectionDevice::CONNECTION, (new PasskeyChallenge)->getConnectionName());

        Config::set('authentication.device.model', Device::class);

        self::assertNull((new PasskeyChallenge)->getConnectionName());
    }

    /**
     * A challenge records when it was created but is never updated, and
     * serialising it leaves its options out.
     *
     * @return void
     */
    public function testAChallengeIsNeverUpdatedAndHidesItsOptions(): void
    {
        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);

        $challenge = (new PasskeyChallenge)->forceFill([
            'id'         => '0192f6b2-0000-7000-8000-000000000001',
            'purpose'    => 'sign_in',
            'guard'      => 'api',
            'rp_id'      => 'example.test',
            'options'    => ['challenge' => 'abc'],
            'expires_at' => $now->addMinutes(5),
        ]);

        $challenge->save();

        self::assertNull($challenge->getUpdatedAtColumn());
        self::assertSame(['challenge' => 'abc'], PasskeyChallenge::query()->sole()->options);
        self::assertArrayNotHasKey('options', $challenge->toArray());
        self::assertTrue(PasskeyChallenge::query()->sole()->created_at?->equalTo($now));
    }

    /**
     * Pruning deletes the challenges that have expired, at their expiry second,
     * and keeps those that can still be answered.
     *
     * @return void
     */
    public function testPruningDeletesExpiredChallenges(): void
    {
        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);

        foreach (['expired' => -60, 'expiring' => 0, 'live' => 1] as $name => $offset) {
            (new PasskeyChallenge)->forceFill([
                'id' => match ($name) {
                    'expired'  => '0192f6b2-0000-7000-8000-000000000001',
                    'expiring' => '0192f6b2-0000-7000-8000-000000000002',
                    default    => '0192f6b2-0000-7000-8000-000000000003',
                },
                'purpose'    => 'sign_in',
                'guard'      => 'api',
                'rp_id'      => 'example.test',
                'options'    => [],
                'expires_at' => $now->addSeconds($offset),
            ])->save();
        }

        Artisan::call('model:prune', ['--model' => [PasskeyChallenge::class], '--pretend' => true]);

        self::assertStringContainsString('2 [' . PasskeyChallenge::class . '] records will be pruned.', Artisan::output());
        self::assertSame(3, PasskeyChallenge::query()->count());

        Artisan::call('model:prune', ['--model' => [PasskeyChallenge::class]]);

        self::assertSame(['0192f6b2-0000-7000-8000-000000000003'], PasskeyChallenge::query()->pluck('id')->all());
    }
}
