<?php

declare(strict_types = 1);

namespace Tests\Feature\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PasskeyUsed;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Models\PasskeyChallenge;
use SineMacula\Laravel\Authentication\Passkeys\CeremonyOptions;
use SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Authentication\Passkeys\RelyingParty;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Passkeys\VirtualAuthenticator;
use Tests\TestCase;

/**
 * Feature tests for the verification a passkey sign-in and a passkey factor
 * share: the order its checks run in, what each refusal is, the owner callback
 * that admits the passkey's owner, and the `PasskeyUsed` a verified use reports
 * once committed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyAssertions::class)]
final class PasskeyAssertionsTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithSessions;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);
        CarbonImmutable::setTestNow($this->now);

        $this->createSessionTables();
    }

    /**
     * Drop the tables and release the clocks.
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
     * A verified answer returns the owner the callback admitted, with the
     * passkey, its count moved; the callback is handed the passkey the answer
     * names.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerifiedAnswerReturnsTheAdmittedOwnerAndThePasskey(): void
    {
        $identity = $this->seedIdentity();
        $summary  = $this->registerPasskey($identity);
        $options  = $this->signInOptions();
        $handed   = null;

        $verified = $this->signIn($options, $this->authenticator()->get($options->options), static function (Passkey $passkey) use ($identity, &$handed): Identity {
            $handed = $passkey->id;

            return $identity;
        });

        self::assertIsArray($verified);
        self::assertSame($identity, $verified[0]);
        self::assertSame([$summary->id, $summary->id, 1], [$handed, $verified[1]->id, $verified[1]->sign_count]);
    }

    /**
     * The owner callback's refusal is the answer's, and the assertion is not
     * checked: the passkey keeps its count.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOwnerCallbacksRefusalIsTheAnswers(): void
    {
        $this->registerPasskey($this->seedIdentity());

        $options = $this->signInOptions();
        $refused = $this->assertions()->verify(
            self::rp(),
            ChallengePurpose::SIGN_IN,
            null,
            $options->challengeId,
            $this->authenticator()->get($options->options),
            static fn (): FailureReason => FailureReason::IDENTIFIER_UNVERIFIED,
            $this->now,
        );

        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $refused);
        self::assertSame(0, Passkey::query()->sole()->sign_count);
    }

    /**
     * A challenge that is not a string is refused as invalid before the answer
     * is looked at.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChallengeThatIsNotAStringIsInvalid(): void
    {
        $owner = static fn (): never => self::fail('The owner must not be asked.');

        self::assertSame(FailureReason::PASSKEY_CHALLENGE_INVALID, $this->assertions()->verify(self::rp(), ChallengePurpose::SIGN_IN, null, 42, '{}', $owner, $this->now));
    }

    /**
     * An answer that is neither an array nor a string, or that names no passkey
     * of the relying party, uses the challenge up and is refused as
     * `invalid_credentials`, without asking the owner callback.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAnswerThatNamesNoPasskeyIsRefused(): void
    {
        $this->registerPasskey($this->seedIdentity());

        $owner = static fn (): never => self::fail('The owner must not be asked.');

        $first = $this->signInOptions();

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->signIn($first, 42, $owner));
        self::assertNull(PasskeyChallenge::query()->find($first->challengeId));

        $stranger = new VirtualAuthenticator(self::ORIGIN);

        $stranger->create(['rp' => ['id' => self::RP_ID], 'user' => ['id' => VirtualAuthenticator::encode('handle')], 'challenge' => 'challenge']);

        $second = $this->signInOptions();

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->signIn($second, $stranger->get($second->options), $owner));
    }

    /**
     * For a ceremony bound to an identity, the passkey's own user handle is the
     * one checked, so an answer that carries none verifies; usernameless, the
     * answer must carry it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundCeremonyChecksThePasskeysOwnHandle(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $factor = Auth::passkeys('api')->factorOptions($identity);
        $signIn = $this->signInOptions();

        $withoutHandle = static function (array $credential): array {
            $response = (array) $credential['response'];

            unset($response['userHandle']);

            return ['response' => $response] + $credential;
        };

        $owner  = static fn (): Identity => $identity;
        $answer = $withoutHandle($this->authenticator()->get($factor->options));
        $bound  = $this->assertions()->verify(self::rp(), ChallengePurpose::FACTOR, $identity, $factor->challengeId, $answer, $owner, $this->now);
        $loose  = $this->signIn($signIn, $withoutHandle($this->authenticator()->get($signIn->options)), $owner);

        self::assertIsArray($bound);
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $loose);
    }

    /**
     * A count that the rule refuses is a regression, and so is one whose
     * compare-and-set another use won.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACountTheRuleRefusesOrAnotherUseWonIsARegression(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $owner = static fn (): Identity => $identity;

        DB::table('passkeys')->update(['sign_count' => 5]);

        $behind = $this->signInOptions();

        self::assertSame(FailureReason::PASSKEY_COUNTER_REGRESSED, $this->signIn($behind, $this->authenticator()->get($behind->options), $owner));

        $this->authenticator()->setCounter($this->authenticator()->lastCredentialId(), 6);

        $raced = $this->signInOptions();
        $moved = static function () use ($identity): Identity {
            DB::table('passkeys')->update(['sign_count' => 9]);

            return $identity;
        };

        self::assertSame(FailureReason::PASSKEY_COUNTER_REGRESSED, $this->signIn($raced, $this->authenticator()->get($raced->options), $moved));
        self::assertSame(9, Passkey::query()->sole()->sign_count);
    }

    /**
     * A use is reported with the guard, the client, the owner, the method
     * `passkey` and the passkey's id, once its connection commits, and not when
     * it rolls back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAUseIsReportedOnceCommitted(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);
        $this->recordEvents([PasskeyUsed::class]);

        $passkey = Passkey::query()->sole();
        $client  = new ClientContext('198.51.100.7', 'Used/1');

        DB::beginTransaction();

        $this->assertions()->used(self::rp(), $client, $identity, $passkey, app(Dispatcher::class));

        self::assertSame([], $this->recorded);

        DB::rollBack();

        self::assertSame([], $this->recorded);

        DB::transaction(function () use ($client, $identity, $passkey): void {
            $this->assertions()->used(self::rp(), $client, $identity, $passkey, app(Dispatcher::class));
        });

        $used = $this->recordedEvent(PasskeyUsed::class);

        self::assertSame(['api', 'passkey'], [$used->context->guard, $used->context->method]);
        self::assertSame([$passkey->id, '198.51.100.7'], [$used->context->credentialId, $used->context->client->ip]);
        self::assertSame($identity, $used->context->identity);
    }

    /**
     * Without a transactions manager in the container, a use is reported at
     * once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAUseIsReportedAtOnceWithoutATransactionsManager(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);
        $this->recordEvents([PasskeyUsed::class]);

        $passkey = Passkey::query()->sole();

        DB::beginTransaction();

        app()->offsetUnset('db.transactions');

        $this->assertions()->used(self::rp(), new ClientContext(null, null), $identity, $passkey, app(Dispatcher::class));

        self::assertSame([PasskeyUsed::class], $this->recordedClasses());

        DB::rollBack();
    }

    /**
     * Configure the guards and their relying party.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);
        self::configurePasskeys($config);
    }

    /**
     * Verify the answer to the sign-in options, usernameless, with the owner
     * callback.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\CeremonyOptions  $options
     * @param  mixed  $answer
     * @param  \Closure(\SineMacula\Laravel\Authentication\Models\Passkey): (\SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason)  $owner
     * @return array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Models\Passkey}|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function signIn(CeremonyOptions $options, mixed $answer, \Closure $owner): array|FailureReason
    {
        return $this->assertions()->verify(self::rp(), ChallengePurpose::SIGN_IN, null, $options->challengeId, $answer, $owner, $this->now);
    }

    /**
     * The verifier under test.
     *
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeyAssertions
     */
    private function assertions(): PasskeyAssertions
    {
        return new PasskeyAssertions(app());
    }

    /**
     * The `api` guard's relying party.
     *
     * @return \SineMacula\Laravel\Authentication\Passkeys\RelyingParty
     */
    private static function rp(): RelyingParty
    {
        return RelyingParty::forGuard('api', app(ConfigRepository::class));
    }
}
