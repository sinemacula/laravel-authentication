<?php

declare(strict_types = 1);

namespace Tests\Integration\Passkeys;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyCredentials;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyService;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Passkeys\VirtualAuthenticator;
use Tests\TestCase;

/**
 * Proves a passkey whose public key is too long for a 64 KiB text column is
 * stored whole and stays usable, on whichever engine the suite runs against:
 * nothing bounds a COSE key, and a registration's insert ignores duplicates,
 * which on MySQL would cut a longer key without an error and leave a passkey
 * that reports registered but can never verify.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyCredentials::class)]
#[CoversClass(PasskeyService::class)]
final class LargePasskeyPublicKeyTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithSessions;

    /** @var int The most bytes a MySQL `TEXT` column holds. */
    private const int TEXT_BYTES = 65535;

    /** @var int Bytes of a key id that takes the encoded public key past 65,535 bytes. */
    private const int KEY_ID_BYTES = 50000;

    /**
     * Create the identity tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        $this->authenticator()->keyId = str_repeat('k', self::KEY_ID_BYTES);
    }

    /**
     * Drop the identity tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * A registered public key longer than a text column holds is stored in
     * full, its key id included to the last byte.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPublicKeyLongerThanATextColumnIsStoredWhole(): void
    {
        $this->registerPasskey($this->seedIdentity());

        $stored = DB::table('passkeys')->value('public_key');

        self::assertIsString($stored);
        self::assertGreaterThan(self::TEXT_BYTES, strlen($stored));
        self::assertStringEndsWith($this->authenticator()->keyId, VirtualAuthenticator::decode($stored));
    }

    /**
     * A passkey with a public key longer than a text column holds answers a
     * factor ceremony.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasskeyWithAPublicKeyLongerThanATextColumnVerifiesAFactor(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $options = Auth::passkeys('api')->factorOptions($identity);

        self::assertNull(Auth::passkeys('api')->verifyFactor($identity, $options->challengeId, $this->authenticator()->get($options->options)));
        self::assertNotNull(DB::table('passkeys')->value('last_used_at'));
    }

    /**
     * A passkey with a public key longer than a text column holds signs its
     * identity in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasskeyWithAPublicKeyLongerThanATextColumnSignsIn(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $result = $this->signInWithPasskey();

        self::assertTrue($result->isSignedIn());
        self::assertTrue($identity->is($result->session?->identity));
    }

    /**
     * Configure the guards and their relying party.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        self::configureSessionGuards($config);
        self::configurePasskeys($config);
    }
}
