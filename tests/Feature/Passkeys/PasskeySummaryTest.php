<?php

declare(strict_types = 1);

namespace Tests\Feature\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySummary;
use Tests\TestCase;

/**
 * Feature tests for what a passkey list shows of a passkey: its id, name,
 * transports, AAGUID, backup state and times, and never its key material.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeySummary::class)]
final class PasskeySummaryTest extends TestCase
{
    /**
     * A passkey is summarised by what it shows, as immutable times; the array
     * and JSON forms use snake_case keys and ISO-8601 times, and hold no
     * credential id, public key, user handle or count.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAPasskeyIsSummarisedWithoutItsKeyMaterial(): void
    {
        $passkey = (new Passkey)->forceFill([
            'id'                 => '0192f6b2-0000-7000-8000-000000000001',
            'credential_id_hash' => str_repeat('a', 64),
            'credential_id'      => 'Y3JlZGVudGlhbA',
            'user_handle'        => 'aGFuZGxl',
            'public_key'         => 'a2V5',
            'sign_count'         => 7,
            'transports'         => ['usb', 'nfc'],
            'aaguid'             => 'adce0002-35bc-c60a-648b-0b25f1f05503',
            'backup_eligible'    => true,
            'backup_state'       => false,
            'name'               => 'Key',
            'created_at'         => Carbon::create(2026, 4, 6, 12, 0, 0),
            'last_used_at'       => Carbon::create(2026, 4, 7, 9, 30, 0),
        ]);

        $summary = PasskeySummary::of($passkey);

        self::assertInstanceOf(CarbonImmutable::class, $summary->createdAt);
        self::assertInstanceOf(CarbonImmutable::class, $summary->lastUsedAt);

        $expected = [
            'id'              => '0192f6b2-0000-7000-8000-000000000001',
            'name'            => 'Key',
            'transports'      => ['usb', 'nfc'],
            'aaguid'          => 'adce0002-35bc-c60a-648b-0b25f1f05503',
            'backup_eligible' => true,
            'backed_up'       => false,
            'created_at'      => '2026-04-06T12:00:00+00:00',
            'last_used_at'    => '2026-04-07T09:30:00+00:00',
        ];

        self::assertSame($expected, $summary->toArray());
        self::assertSame($expected, $summary->jsonSerialize());
        self::assertSame($expected, json_decode(json_encode($summary, JSON_THROW_ON_ERROR), true, flags: JSON_THROW_ON_ERROR));
    }

    /**
     * A passkey never used shows no last use.
     *
     * @return void
     */
    public function testAPasskeyNeverUsedShowsNoLastUse(): void
    {
        $passkey = (new Passkey)->forceFill([
            'id'              => '0192f6b2-0000-7000-8000-000000000001',
            'transports'      => [],
            'backup_eligible' => false,
            'backup_state'    => false,
            'created_at'      => Carbon::create(2026, 4, 6, 12, 0, 0),
        ]);

        $summary = PasskeySummary::of($passkey);

        self::assertNull($summary->lastUsedAt);
        self::assertNull($summary->toArray()['last_used_at']);
        self::assertNull($summary->name);
        self::assertNull($summary->aaguid);
    }
}
