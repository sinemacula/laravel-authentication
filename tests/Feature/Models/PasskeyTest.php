<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Models\Passkey;
use Tests\Integration\Fixtures\SeparateConnectionDevice;
use Tests\TestCase;

/**
 * Feature tests for where the passkey model keeps its rows, and what it keeps
 * out of its serialisation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Passkey::class)]
final class PasskeyTest extends TestCase
{
    /**
     * The model uses the configured table, and `passkeys` when none is
     * configured.
     *
     * @return void
     */
    public function testTheTableIsTheConfiguredOne(): void
    {
        Config::set('authentication.passkeys.table', 'webauthn_credentials');

        self::assertSame('webauthn_credentials', (new Passkey)->getTable());

        Config::set('authentication.passkeys', []);

        self::assertSame('passkeys', (new Passkey)->getTable());
    }

    /**
     * The model lives on the storage connection, read each time it is built,
     * whatever connection the device model names.
     *
     * @return void
     */
    public function testTheConnectionIsTheStorageConnection(): void
    {
        Config::set('authentication.device.model', SeparateConnectionDevice::class);

        self::assertNull((new Passkey)->getConnectionName());

        Config::set('authentication.storage.connection', 'package_store');

        self::assertSame('package_store', (new Passkey)->getConnectionName());

        Config::set('authentication.storage.connection', '');

        self::assertNull((new Passkey)->getConnectionName());
    }

    /**
     * Serialising a passkey leaves out its credential id and its digest, its
     * public key, its user handle and its sign count, and casts the rest.
     *
     * @return void
     */
    public function testSerialisationLeavesTheKeyMaterialOut(): void
    {
        $passkey = (new Passkey)->forceFill([
            'id'                 => '0192f6b2-0000-7000-8000-000000000001',
            'credential_id_hash' => str_repeat('a', 64),
            'credential_id'      => 'Y3JlZGVudGlhbA',
            'user_handle'        => 'aGFuZGxl',
            'public_key'         => 'a2V5',
            'sign_count'         => '7',
            'transports'         => ['usb'],
            'backup_eligible'    => 1,
            'backup_state'       => 0,
            'uv_initialized'     => 1,
            'name'               => 'Laptop',
            'last_used_at'       => '2026-04-06 12:00:00',
        ]);

        self::assertSame(['id', 'transports', 'backup_eligible', 'backup_state', 'uv_initialized', 'name', 'last_used_at'], array_keys($passkey->toArray()));
        self::assertSame([7, ['usb']], [$passkey->sign_count, $passkey->transports]);
        self::assertSame([true, false, true], [$passkey->backup_eligible, $passkey->backup_state, $passkey->uv_initialized]);
        self::assertSame('2026-04-06 12:00:00', $passkey->last_used_at?->format('Y-m-d H:i:s'));
    }
}
