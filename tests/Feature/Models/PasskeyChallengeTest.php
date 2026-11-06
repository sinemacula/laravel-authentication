<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Carbon\CarbonImmutable;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Models\PasskeyChallenge;
use Tests\Integration\Fixtures\SeparateConnectionSession;
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
     * The model lives on the storage connection, read each time it is built,
     * whatever connection the session model names.
     *
     * @return void
     */
    public function testTheConnectionIsTheStorageConnection(): void
    {
        Config::set('authentication.session.model', SeparateConnectionSession::class);

        self::assertNull((new PasskeyChallenge)->getConnectionName());

        Config::set('authentication.storage.connection', 'package_store');

        self::assertSame('package_store', (new PasskeyChallenge)->getConnectionName());

        Config::set('authentication.storage.connection', '');

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
     * Pruning deletes the challenges that expired a challenge lifetime ago (300
     * seconds by default), used or not, at that second, and keeps those that
     * can still be answered, those that expired less ago, so a response to them
     * is told it expired, and a used one until it expires and its lifetime has
     * passed too.
     *
     * @return void
     */
    public function testPruningDeletesChallengesExpiredForALifetime(): void
    {
        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);

        $rows = [
            1 => ['expires' => -300, 'used' => false],
            2 => ['expires' => -300, 'used' => true],
            3 => ['expires' => -299, 'used' => false],
            4 => ['expires' => -299, 'used' => true],
            5 => ['expires' => 1, 'used' => false],
            6 => ['expires' => 1, 'used' => true],
        ];

        foreach ($rows as $number => $row) {
            (new PasskeyChallenge)->forceFill([
                'id'          => sprintf('0192f6b2-0000-7000-8000-%012d', $number),
                'purpose'     => 'sign_in',
                'guard'       => 'api',
                'rp_id'       => 'example.test',
                'options'     => [],
                'expires_at'  => $now->addSeconds($row['expires']),
                'consumed_at' => $row['used'] ? $now->addSeconds($row['expires'] - 1) : null,
            ])->save();
        }

        Artisan::call('model:prune', ['--model' => [PasskeyChallenge::class], '--pretend' => true]);

        self::assertStringContainsString('2 [' . PasskeyChallenge::class . '] records will be pruned.', Artisan::output());
        self::assertSame(6, PasskeyChallenge::query()->count());

        Artisan::call('model:prune', ['--model' => [PasskeyChallenge::class]]);

        self::assertSame([3, 4, 5, 6], array_map(static fn (string $id): int => (int) substr($id, -12), PasskeyChallenge::query()->orderBy('id')->pluck('id')->all()));
    }
}
