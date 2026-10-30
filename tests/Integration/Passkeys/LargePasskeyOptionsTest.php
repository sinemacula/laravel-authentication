<?php

declare(strict_types = 1);

namespace Tests\Integration\Passkeys;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyChallenges;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyService;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySummary;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Proves ceremony options too long for a 64 KiB text column are stored whole
 * and answered, on whichever engine the suite runs against: an identity with
 * enough passkeys of the longest credential id WebAuthn allows has registration
 * and factor options over 65,535 bytes, and both are issued, stored in full and
 * used up by a registration and a factor that verify.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyChallenges::class)]
#[CoversClass(PasskeyService::class)]
final class LargePasskeyOptionsTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithSessions;

    /** @var int The longest credential id WebAuthn allows, in bytes. */
    private const int LONGEST_CREDENTIAL_ID = 1023;

    /** @var int Passkeys of the longest credential id whose descriptors take the options past 65,535 bytes. */
    private const int PASSKEYS = 46;

    /** @var int The most bytes a MySQL `TEXT` column holds. */
    private const int TEXT_BYTES = 65535;

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
     * Registration options excluding every passkey the identity has are stored
     * whole however long, and a registration answering them stores one more.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRegistrationOptionsLongerThanATextColumnAreStoredAndAnswered(): void
    {
        $identity = $this->withPasskeys(self::PASSKEYS);
        $options  = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);

        self::assertCount(self::PASSKEYS, (array) $options->options['excludeCredentials']);
        self::assertGreaterThan(self::TEXT_BYTES, $this->storedBytes($options->challengeId));

        $answer  = $this->authenticator()->create($options->options, self::LONGEST_CREDENTIAL_ID);
        $summary = Auth::passkeys('api')->register($identity, $options->challengeId, $answer, 'Laptop')->passkey;

        self::assertInstanceOf(PasskeySummary::class, $summary);
        self::assertCount(self::PASSKEYS + 1, Auth::passkeys('api')->passkeys($identity));
        self::assertSame(0, DB::table('passkey_challenges')->count());
    }

    /**
     * Factor options allowing every passkey the identity has are stored whole
     * however long, and the factor answering them verifies.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testFactorOptionsLongerThanATextColumnAreStoredAndAnswered(): void
    {
        $identity = $this->withPasskeys(self::PASSKEYS);
        $options  = Auth::passkeys('api')->factorOptions($identity);

        self::assertCount(self::PASSKEYS, (array) $options->options['allowCredentials']);
        self::assertGreaterThan(self::TEXT_BYTES, $this->storedBytes($options->challengeId));
        self::assertTrue(Auth::passkeys('api')->verifyFactor($identity, $options->challengeId, $this->authenticator()->get($options->options))->isVerified());
        self::assertSame(0, DB::table('passkey_challenges')->count());
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

    /**
     * Seed an identity and register the number of passkeys given for it through
     * the guard, each with a credential id of the longest length.
     *
     * @param  int  $count
     * @return \Tests\Integration\Fixtures\IntegrationIdentity
     *
     * @throws \Throwable
     */
    private function withPasskeys(int $count): IntegrationIdentity
    {
        $identity = $this->seedIdentity();
        $passkeys = Auth::passkeys('api');

        for ($i = 0; $i < $count; $i++) {
            $options  = $passkeys->registrationOptions($identity, self::USER_NAME);
            $response = $this->authenticator()->create($options->options, self::LONGEST_CREDENTIAL_ID);

            self::assertTrue($passkeys->register($identity, $options->challengeId, $response, 'Laptop')->isRegistered());
        }

        return $identity;
    }

    /**
     * The length, in bytes, of the options stored for the challenge.
     *
     * @param  string  $challengeId
     * @return int
     */
    private function storedBytes(string $challengeId): int
    {
        $options = DB::table('passkey_challenges')->where('id', $challengeId)->value('options');

        self::assertIsString($options);

        return strlen($options);
    }
}
