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
 * Proves ceremony options longer than a 64 KiB text column are stored whole and
 * answered.
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
     * Registration options of any length are stored whole and a registration
     * answering them succeeds.
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
        $summary = Auth::passkeys('api')->register($identity, $options->challengeId, $answer, self::requestClient(), 'Laptop')->passkey;

        self::assertInstanceOf(PasskeySummary::class, $summary);
        self::assertCount(self::PASSKEYS + 1, Auth::passkeys('api')->passkeys($identity));
        self::assertSame(0, DB::table('passkey_challenges')->whereNull('consumed_at')->count());
    }

    /**
     * Factor options of any length are stored whole and the factor answering
     * them verifies.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testFactorOptionsLongerThanATextColumnAreStoredAndAnswered(): void
    {
        $identity = $this->withPasskeys(self::PASSKEYS);
        $options  = self::factorCeremony(Auth::passkeys('api'), $identity);

        self::assertCount(self::PASSKEYS, (array) $options->options['allowCredentials']);
        self::assertGreaterThan(self::TEXT_BYTES, $this->storedBytes($options->challengeId));
        self::assertTrue(self::verifyPasskeyFactor($identity, $options->challengeId, $this->authenticator()->get($options->options))->isVerified());
        self::assertSame(0, DB::table('passkey_challenges')->whereNull('consumed_at')->count());
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
     * Seed an identity with the given number of passkeys of the longest
     * credential id.
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

            self::assertTrue($passkeys->register($identity, $options->challengeId, $response, self::requestClient(), 'Laptop')->isRegistered());
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
