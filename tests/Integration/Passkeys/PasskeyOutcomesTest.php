<?php

declare(strict_types = 1);

namespace Tests\Integration\Passkeys;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Passkeys\Enums\PasskeyRegistrationStatus;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorResult;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyRegistration;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyService;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Passkeys\VirtualAuthenticator;
use Tests\TestCase;

/**
 * Proves what a registration and a factor verification answer is what they
 * wrote, on whichever engine the suite runs against: the summary a passkey is
 * registered or verified with is the one read back from its row, and a refused
 * ceremony leaves the rows as they were.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyService::class)]
#[CoversClass(PasskeyRegistration::class)]
#[CoversClass(PasskeyFactorResult::class)]
final class PasskeyOutcomesTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithSessions;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clock and create the identity tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        self::freezeAt($this->now);

        $this->createSessionTables();
    }

    /**
     * Drop the identity tables and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A registration answers `registered` with the summary its row reads back
     * as.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationAnswersThePasskeyItStored(): void
    {
        $identity = $this->seedIdentity();
        $options  = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);
        $result   = Auth::passkeys('api')->register($identity, $options->challengeId, $this->authenticator()->create($options->options), 'Laptop');

        self::assertSame(PasskeyRegistrationStatus::REGISTERED, $result->status);
        self::assertNotNull($result->passkey);
        self::assertSame(Auth::passkeys('api')->passkeys($identity)[0]->toArray(), $result->passkey->toArray());
        self::assertSame($result->passkey->id, DB::table('passkeys')->value('id'));
    }

    /**
     * A refused registration answers its status and stores nothing: a challenge
     * that is not one, a response that does not verify, and a credential
     * registered already.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedRegistrationStoresNothing(): void
    {
        $identity = $this->seedIdentity();
        $options  = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);
        $answer   = $this->authenticator()->create($options->options);

        self::assertSame(PasskeyRegistrationStatus::CHALLENGE_INVALID, Auth::passkeys('api')->register($identity, '0192f6b2-0000-7000-8000-000000000001', $answer)->status);
        self::assertSame(PasskeyRegistrationStatus::RESPONSE_INVALID, Auth::passkeys('api')->register($identity, $options->challengeId, '{')->status);
        self::assertSame(0, DB::table('passkeys')->count());

        $this->registerPasskey($identity);

        $again     = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);
        $duplicate = $this->authenticator()->create($again->options, id: VirtualAuthenticator::decode($this->authenticator()->lastCredentialId()));
        $result    = Auth::passkeys('api')->register($identity, $again->challengeId, $duplicate);

        self::assertSame([PasskeyRegistrationStatus::ALREADY_REGISTERED, null], [$result->status, $result->passkey]);
        self::assertSame(1, DB::table('passkeys')->count());
    }

    /**
     * A verified factor answers the passkey as its use left the row: the last
     * use recorded and read back as the summary says.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerifiedFactorAnswersThePasskeyAsItsUseLeftIt(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        self::freezeAt($this->now->addSeconds(60));

        $options = Auth::passkeys('api')->factorOptions($identity);
        $result  = Auth::passkeys('api')->verifyFactor($identity, $options->challengeId, $this->authenticator()->get($options->options));
        $stored  = Auth::passkeys('api')->passkeys($identity)[0];

        self::assertTrue($result->isVerified());
        self::assertSame($stored->toArray(), $result->passkey?->toArray());
        self::assertTrue($stored->lastUsedAt?->equalTo($this->now->addSeconds(60)));
        self::assertSame(1, Passkey::query()->sole()->sign_count);
    }

    /**
     * A refused factor answers its reason and records no use: the count and the
     * last use stay as the verified use before it left them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedFactorRecordsNoUse(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $first = Auth::passkeys('api')->factorOptions($identity);

        self::assertTrue(Auth::passkeys('api')->verifyFactor($identity, $first->challengeId, $this->authenticator()->get($first->options))->isVerified());

        $before = Passkey::query()->sole()->only(['sign_count', 'last_used_at', 'updated_at']);

        self::freezeAt($this->now->addSeconds(60));

        $this->authenticator()->setCounter($this->authenticator()->lastCredentialId(), 0);

        $again  = Auth::passkeys('api')->factorOptions($identity);
        $result = Auth::passkeys('api')->verifyFactor($identity, $again->challengeId, $this->authenticator()->get($again->options));

        self::assertSame([FailureReason::PASSKEY_COUNTER_REGRESSED, null], [$result->reason, $result->passkey]);
        self::assertEquals($before, Passkey::query()->sole()->only(['sign_count', 'last_used_at', 'updated_at']));
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
     * Freeze both clocks at the moment.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @return void
     */
    private static function freezeAt(CarbonImmutable $now): void
    {
        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);
    }
}
