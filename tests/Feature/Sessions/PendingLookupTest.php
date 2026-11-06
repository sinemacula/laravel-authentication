<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\PendingLookup;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\TestCase;

/**
 * Feature tests for the lookup of the live pending session of a guard a pending
 * credential names, against a real database. The pending-session actions are
 * tested in `PendingSessionsTest` and the passkey registration on a pending
 * sign-in in `PasskeyServiceTest`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingLookup::class)]
final class PendingLookupTest extends TestCase
{
    use InteractsWithProofs, InteractsWithRateLimits, InteractsWithSessions;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clock, create the tables and ask a further factor of every
     * sign-in.
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

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);
    }

    /**
     * Drop the tables and release the clock.
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
     * A live credential finds its session, its owner and no principal (the
     * sign-in has not chosen one for the identity that is its own), as a string
     * or as a `Secret`, locked or not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALiveCredentialFindsItsSessionAndOwner(): void
    {
        $identity = $this->seedIdentity();
        $pending  = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($pending->credential);

        $lookup = new PendingLookup($this->freshGuard()->context());

        DB::beginTransaction();

        foreach ([$pending->credential, $pending->credential->reveal()] as $credential) {
            $found = $lookup->find($credential, $this->now, true);

            self::assertNotNull($found);
            self::assertSame($pending->pending?->id, $found[0]->getSessionIdentifier());
            self::assertTrue($identity->is($found[1]));
        }

        DB::rollBack();

        self::assertNotNull($lookup->find($pending->credential, $this->now, false));
    }

    /**
     * Rows of one name each: a credential that names no live pending session of
     * the guard.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnnamingCredentials(): iterable
    {
        foreach (['no_dot', 'empty_key', 'empty_secret', 'long_key', 'unknown_session', 'wrong_secret', 'expired', 'revoked', 'active'] as $case) {
            yield $case => [$case];
        }
    }

    /**
     * A credential with no key or secret, a key longer than any the session can
     * have, a session that is unknown, a wrong secret, or a session that is
     * expired, revoked or no longer pending names no session, whether the read
     * is locked or not.
     *
     * @param  string  $case
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnnamingCredentials')]
    public function testACredentialThatNamesNoLivePendingSessionFindsNothing(string $case): void
    {
        $this->seedIdentity();

        $pending = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($pending->credential);

        match ($case) {
            'expired' => $this->moveClockTo($this->now->addMinutes(5)),
            'revoked' => DB::table('authentication_sessions')->update(['revoked_at' => $this->now]),
            'active'  => DB::table('authentication_sessions')->update(['status' => 'active']),
            default   => null,
        };

        $credential = self::unnamingCredential($case, $pending->credential->reveal());

        $lookup = new PendingLookup($this->freshGuard()->context());

        DB::beginTransaction();

        self::assertNull($lookup->find($credential, CarbonImmutable::now()->startOfSecond(), true));
        self::assertNull($lookup->find(new Secret($credential), CarbonImmutable::now()->startOfSecond(), false));

        DB::rollBack();
    }

    /**
     * A credential of another guard's pending session finds nothing on this
     * one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherGuardsCredentialFindsNothing(): void
    {
        $this->seedIdentity();

        $pending = $this->sessions('admin')->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($pending->credential);
        self::assertNull((new PendingLookup($this->freshGuard('api')->context()))->find($pending->credential, $this->now, false));
        self::assertNotNull((new PendingLookup($this->freshGuard('admin')->context()))->find($pending->credential, $this->now, false));
    }

    /**
     * Configure the guards.
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

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * The credential as the case hands it in: made malformed, unknown or wrong
     * in its secret, or as it is.
     *
     * @param  string  $case
     * @param  string  $credential
     * @return string
     */
    private static function unnamingCredential(string $case, string $credential): string
    {
        [$key, $secret] = explode('.', $credential, 2);

        return match ($case) {
            'no_dot'          => 'nodothere',
            'empty_key'       => '.' . $secret,
            'empty_secret'    => $key . '.',
            'long_key'        => str_repeat('k', 256) . '.' . $secret,
            'unknown_session' => 'missing.' . $secret,
            'wrong_secret'    => $key . '.' . strrev($secret),
            default           => $credential,
        };
    }

    /**
     * Move the frozen clock.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @return void
     */
    private function moveClockTo(CarbonImmutable $at): void
    {
        Carbon::setTestNow($at);
        CarbonImmutable::setTestNow($at);
    }
}
