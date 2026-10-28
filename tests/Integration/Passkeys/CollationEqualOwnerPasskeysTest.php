<?php

declare(strict_types = 1);

namespace Tests\Integration\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PasskeyAdded;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;
use SineMacula\Laravel\Authentication\Events\PasskeyUsed;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passkeys\Enums\PasskeyRegistrationFailure;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyChallenges;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyCredentials;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySummary;
use Tests\Concerns\InteractsWithFoldingCollations;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Integration tests for passkeys and their challenges whose owner columns are
 * under a collation that counts distinct keys as equal: an identity whose key
 * differs from the owner's only in case or accent sees none of the owner's
 * passkeys, removes none, and answers none of the owner's challenges, while the
 * owner still can.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyChallenges::class)]
#[CoversClass(PasskeyCredentials::class)]
final class CollationEqualOwnerPasskeysTest extends TestCase
{
    use InteractsWithFoldingCollations, InteractsWithPasskeys, InteractsWithSessions;

    /** @var string The key of the identity that holds the passkey. */
    private const string OWNER = 'alice';

    /**
     * Fold the owner columns, freeze the clock and record the passkey events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::foldColumns('passkeys', ['authenticatable_type', 'authenticatable_id']);
        self::foldColumns('passkey_challenges', ['authenticatable_type', 'authenticatable_id'], nullable: true);

        Carbon::setTestNow(Carbon::parse('2026-04-06 12:00:00'));
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-04-06 12:00:00'));
    }

    /**
     * Release the clock.
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
     * The other identity is offered none of the owner's passkeys to exclude
     * from a registration or to answer a factor ceremony with, lists none, and
     * removes none, which is left with nothing reported; the owner still lists
     * and removes it.
     *
     * @param  string  $folded
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFoldedKeys')]
    public function testAnotherKeyTheCollationCountsAsEqualHoldsNoPasskeys(string $folded): void
    {
        $owner   = self::namedIdentity(self::OWNER);
        $passkey = $this->registerPasskey($owner);
        $other   = self::namedIdentity($folded);

        self::assertColumnFolds('passkeys', 'authenticatable_id', $folded);

        Event::fake([PasskeyRemoved::class]);

        $passkeys = Auth::passkeys('api');

        self::assertSame([], $passkeys->passkeys($other));
        self::assertSame([], $passkeys->registrationOptions($other, self::USER_NAME)->options['excludeCredentials']);
        self::assertSame([], $passkeys->factorOptions($other)->options['allowCredentials']);
        self::assertFalse($passkeys->remove($other, $passkey->id));
        self::assertSame(1, DB::table('passkeys')->where('id', $passkey->id)->count());

        Event::assertNotDispatched(PasskeyRemoved::class);

        self::assertSame([$passkey->id], array_map(static fn (PasskeySummary $summary): string => $summary->id, $passkeys->passkeys($owner)));
        self::assertTrue($passkeys->remove($owner, $passkey->id));
        self::assertSame(0, DB::table('passkeys')->count());
    }

    /**
     * The other identity cannot answer the owner's registration challenge,
     * which it leaves unused, so the owner still registers with it.
     *
     * @param  string  $folded
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFoldedKeys')]
    public function testAnotherKeyTheCollationCountsAsEqualCannotAnswerARegistrationChallenge(string $folded): void
    {
        $owner    = self::namedIdentity(self::OWNER);
        $passkeys = Auth::passkeys('api');
        $options  = $passkeys->registrationOptions($owner, self::USER_NAME);
        $answer   = $this->authenticator()->create($options->options);

        self::assertColumnFolds('passkey_challenges', 'authenticatable_id', $folded);

        Event::fake([PasskeyAdded::class]);

        self::assertSame(PasskeyRegistrationFailure::CHALLENGE_INVALID, $passkeys->register(self::namedIdentity($folded), $options->challengeId, $answer));
        self::assertSame(1, DB::table('passkey_challenges')->count());
        self::assertSame(0, DB::table('passkeys')->count());

        Event::assertNotDispatched(PasskeyAdded::class);

        self::assertInstanceOf(PasskeySummary::class, $passkeys->register($owner, $options->challengeId, $answer));
        self::assertSame(self::OWNER, DB::table('passkeys')->value('authenticatable_id'));
    }

    /**
     * The other identity cannot answer the owner's factor challenge with the
     * owner's passkey, which it leaves unused, so the owner still verifies the
     * factor with it.
     *
     * @param  string  $folded
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFoldedKeys')]
    public function testAnotherKeyTheCollationCountsAsEqualCannotAnswerAFactorChallenge(string $folded): void
    {
        $owner = self::namedIdentity(self::OWNER);

        $this->registerPasskey($owner);

        $passkeys = Auth::passkeys('api');
        $options  = $passkeys->factorOptions($owner);
        $answer   = $this->authenticator()->get($options->options);

        self::assertColumnFolds('passkey_challenges', 'authenticatable_id', $folded);

        Event::fake([PasskeyUsed::class]);

        self::assertSame(FailureReason::PASSKEY_CHALLENGE_INVALID, $passkeys->verifyFactor(self::namedIdentity($folded), $options->challengeId, $answer));
        self::assertSame(1, DB::table('passkey_challenges')->count());

        Event::assertNotDispatched(PasskeyUsed::class);

        self::assertNull($passkeys->verifyFactor($owner, $options->challengeId, $answer));
    }

    /**
     * Configure the guards and the relying party.
     *
     * @param  mixed  $app
     * @return void
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
}
