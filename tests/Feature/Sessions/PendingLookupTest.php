<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Runtime\CredentialTimebox;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\PendingLookup;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Database\LockMarkingSQLiteGrammar;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\WideKeySession;
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
    use InteractsWithProofs, InteractsWithRateLimits, InteractsWithSessionRecords, InteractsWithSessions;

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
            self::assertTrue($identity->is($found[2]));
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
     * A credential without a key or a secret, or a key longer than 255
     * characters, is rejected without a query; a key of 255 characters, however
     * many bytes they take, is looked up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyACredentialThatCouldNameASessionIsLookedUp(): void
    {
        $this->seedIdentity();

        $pending = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($pending->credential);

        [$key, $secret] = explode('.', $pending->credential->reveal(), 2);

        $lookup = new PendingLookup($this->freshGuard()->context());

        foreach (['no dot' => 'nodothere', 'empty key' => '.' . $secret, 'empty secret' => $key . '.', 'no secret or key' => '.'] as $name => $credential) {
            self::assertSame(0, $this->queriesDuring(static fn (): mixed => $lookup->find($credential, CarbonImmutable::now(), false)), $name);
        }

        self::createSessionRecordTable('wide_key_sessions', stringKey: true);

        config()->set('authentication.session.model', WideKeySession::class);
        config()->set('authentication.session.table', 'wide_key_sessions');

        try {
            $wide = new PendingLookup($this->freshGuard()->context());

            foreach (['a', 'é'] as $character) {
                $inside  = str_repeat($character, 255) . '.secret';
                $outside = str_repeat($character, 256) . '.secret';

                self::assertSame(1, $this->queriesDuring(static fn (): mixed => $wide->find($inside, CarbonImmutable::now(), false)), $character . ' x 255');
                self::assertSame(0, $this->queriesDuring(static fn (): mixed => $wide->find($outside, CarbonImmutable::now(), false)), $character . ' x 256');
            }
        } finally {
            config()->set('authentication.session.table', 'authentication_sessions');

            Schema::dropIfExists('wide_key_sessions');
        }
    }

    /**
     * Finding with the lock reads the session's row locked for update, and
     * without it reads the row plain. On SQLite, which takes no row lock, the
     * lock is written into the SQL as a comment.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSessionIsLockedOnlyWhenAsked(): void
    {
        $this->seedIdentity();

        $pending = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($pending->credential);

        $connection = DB::connection();

        if ($connection->getDriverName() === 'sqlite') {
            $connection->setQueryGrammar(new LockMarkingSQLiteGrammar($connection));
        }

        $lookup = new PendingLookup($this->freshGuard()->context());

        /** @var \ArrayObject<int, bool> $locks */
        $locks = new \ArrayObject;

        $connection->listen(static function (QueryExecuted $query) use ($locks): void {
            if (!str_starts_with($query->sql, 'select') || !str_contains($query->sql, 'authentication_sessions')) {
                return;
            }

            $locks[] = str_contains(strtolower($query->sql), 'for update');
        });

        DB::beginTransaction();

        $lookup->find($pending->credential, $this->now, false);

        self::assertSame([false], $locks->getArrayCopy());

        $locks->exchangeArray([]);

        $lookup->find($pending->credential, $this->now, true);

        self::assertSame([true], $locks->getArrayCopy());

        DB::rollBack();
    }

    /**
     * A session whose owner is gone names nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionWhoseOwnerIsGoneIsNotFound(): void
    {
        $identity = $this->seedIdentity();
        $pending  = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($pending->credential);

        $identity->delete();

        self::assertNull((new PendingLookup($this->freshGuard()->context()))->find($pending->credential, $this->now, false));
    }

    /**
     * Rows of `[recorded principal, principal the resolver answers]`: the
     * identity's own principal resolved from its recorded id, and the ways the
     * recorded principal stops being the session's: it no longer resolves, the
     * resolver answers another than the one recorded, or one that is not the
     * owner's.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: bool}>
     */
    public static function providePrincipals(): iterable
    {
        yield from [
            'the recorded principal'        => ['1', 'ada', true],
            'one that no longer resolves'   => ['1', null, false],
            'another than the one recorded' => ['2', 'ada', false],
            'one that is not the owner\'s'  => ['2', 'grace', false],
        ];
    }

    /**
     * The principal a session records is resolved from the recorded id for the
     * owner, and the session is found only while that very principal, the
     * owner's, is the one resolved.
     *
     * @param  string  $recorded
     * @param  ?string  $answers
     * @param  bool  $found
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('providePrincipals')]
    public function testTheRecordedPrincipalMustResolveAsTheOwnersOwn(string $recorded, ?string $answers, bool $found): void
    {
        $ada   = $this->seedIdentity();
        $grace = $this->seedIdentity('grace@example.test');

        $pending = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($pending->credential);

        DB::table('authentication_sessions')->update(['principal_id' => $recorded]);

        $answer = match ($answers) {
            'ada'   => $ada,
            'grace' => $grace,
            default => null,
        };

        /** @var \ArrayObject<int, mixed> $hints */
        $hints = new \ArrayObject;

        $resolver = new readonly class ($answer, $hints) implements PrincipalResolver {
            /**
             * Constructor.
             *
             * @param  ?\Tests\Integration\Fixtures\IntegrationIdentity  $answer
             * @param  \ArrayObject<int, mixed>  $hints
             */
            public function __construct(

                /** The principal answered. */
                private ?IntegrationIdentity $answer,

                /** Every hint asked with. */
                private \ArrayObject $hints,
            ) {}

            /**
             * Answer the principal, keeping the hint.
             *
             * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
             * @param  mixed  $hint
             * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
             */
            #[\Override]
            public function resolve(Identity $identity, mixed $hint = null): ?Principal
            {
                $this->hints[] = $hint;

                return $this->answer;
            }
        };

        $real    = $this->freshGuard()->context();
        $context = new GuardContext($real->name(), $real->provider(), $resolver, app(Dispatcher::class), new Request, new CredentialTimebox(new Timebox));
        $result  = (new PendingLookup($context))->find($pending->credential, $this->now, false);

        self::assertSame([$recorded], $hints->getArrayCopy());
        self::assertSame($found, $result !== null);
        self::assertSame($found ? $answer : null, $result[2] ?? null);
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
     * Count the queries the callback sends the default connection.
     *
     * @param  \Closure(): mixed  $callback
     * @return int
     */
    private function queriesDuring(\Closure $callback): int
    {
        $count = 0;

        DB::listen(static function () use (&$count): void {
            $count++;
        });

        $callback();

        return $count;
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
